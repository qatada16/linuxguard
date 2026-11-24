from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from linuxguard.evaluation.labels import Case, load_cases, save_cases
from linuxguard.evaluation.synthetic.background import HOUR, scheduled_jobs_hour, start_services, work_session
from linuxguard.evaluation.synthetic.environment import ACCOUNTS, SimulationEnvironment
from linuxguard.evaluation.synthetic.scenarios import BENIGN_SCENARIOS, MALICIOUS_SCENARIOS, ScenarioSpec

DEFAULT_START = datetime(2026, 11, 2, tzinfo=UTC).timestamp()
WORKDAY_START_HOUR = 8.5
WORKDAY_END_HOUR = 17.5
OFF_HOURS_START = 1.0
OFF_HOURS_END = 4.0
AUDIT_FILE = "audit.log"
AUTH_FILE = "auth.log"
LABELS_FILE = "labels.json"
PASSWD_FILE = "passwd"


@dataclass(slots=True)
class LabeledDataset:
    audit_lines: list[str]
    auth_lines: list[str]
    cases: list[Case]
    passwd_lines: list[str]
    host: str
    start: float
    end: float
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def malicious_cases(self) -> list[Case]:
        return [case for case in self.cases if case.malicious]

    def save(self, directory: str | Path) -> Path:
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        (target / AUDIT_FILE).write_text("\n".join(self.audit_lines) + "\n", encoding="utf-8")
        (target / AUTH_FILE).write_text("\n".join(self.auth_lines) + "\n", encoding="utf-8")
        (target / PASSWD_FILE).write_text("\n".join(self.passwd_lines) + "\n", encoding="utf-8")
        save_cases(self.cases, target / LABELS_FILE)
        return target

    @classmethod
    def load(cls, directory: str | Path, host: str = "lab-ubuntu") -> "LabeledDataset":
        source = Path(directory)
        cases = load_cases(source / LABELS_FILE)
        return cls(
            audit_lines=(source / AUDIT_FILE).read_text(encoding="utf-8").splitlines(),
            auth_lines=(source / AUTH_FILE).read_text(encoding="utf-8").splitlines(),
            cases=cases,
            passwd_lines=(source / PASSWD_FILE).read_text(encoding="utf-8").splitlines(),
            host=host,
            start=min((case.start for case in cases), default=0.0),
            end=max((case.end for case in cases), default=0.0),
        )


def _random_time(environment: SimulationEnvironment, day_start: float, spec: ScenarioSpec) -> float:
    if spec.off_hours:
        low, high = OFF_HOURS_START, OFF_HOURS_END
    else:
        low, high = WORKDAY_START_HOUR, WORKDAY_END_HOUR
    return day_start + environment.rng.uniform(low, high) * HOUR


def _work_sessions(environment: SimulationEnvironment, day_start: float) -> None:
    rng = environment.rng
    for account in ACCOUNTS:
        cursor = day_start + rng.uniform(8.0, 9.5) * HOUR
        for _ in range(rng.randint(2, 3)):
            duration = rng.uniform(0.5, 2.0) * HOUR
            if cursor + duration > day_start + 18.5 * HOUR:
                break
            work_session(environment, account, cursor, duration)
            cursor += duration + rng.uniform(0.3, 1.5) * HOUR


def build_dataset(
    seed: int,
    days: int = 1,
    start: float = DEFAULT_START,
    malicious_per_scenario: int = 2,
    benign_per_scenario: int = 2,
    host: str = "lab-ubuntu",
) -> LabeledDataset:
    environment = SimulationEnvironment(seed=seed, host=host)
    start_services(environment, start)
    for day in range(days):
        day_start = start + day * 24 * HOUR
        for hour in range(24):
            scheduled_jobs_hour(environment, day_start + hour * HOUR)
        _work_sessions(environment, day_start)
        scheduled: list[tuple[ScenarioSpec, float]] = []
        for spec in BENIGN_SCENARIOS:
            scheduled.extend((spec, _random_time(environment, day_start, spec)) for _ in range(benign_per_scenario))
        for spec in MALICIOUS_SCENARIOS:
            scheduled.extend((spec, _random_time(environment, day_start, spec)) for _ in range(malicious_per_scenario))
        for spec, timestamp in sorted(scheduled, key=lambda item: item[1]):
            spec.generate(environment, timestamp)
    end = start + days * 24 * HOUR
    return LabeledDataset(
        audit_lines=environment.sink.sorted_audit_lines(),
        auth_lines=environment.sink.sorted_auth_lines(),
        cases=list(environment.cases),
        passwd_lines=environment.passwd_lines(),
        host=host,
        start=start,
        end=end,
        metadata={"seed": seed, "days": days, "malicious_per_scenario": malicious_per_scenario},
    )
