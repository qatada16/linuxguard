import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from linuxguard.domain.events import SecurityEvent

BOUNDARY_TOLERANCE_SECONDS = 1.0


@dataclass(slots=True)
class Case:
    case_id: str
    scenario: str
    malicious: bool
    start: float
    end: float
    selectors: dict[str, list[str]] = field(default_factory=dict)
    covered_by_rules: bool | None = None
    description: str = ""

    def contains(self, event: SecurityEvent) -> bool:
        if not self.start - BOUNDARY_TOLERANCE_SECONDS <= event.timestamp <= self.end + BOUNDARY_TOLERANCE_SECONDS:
            return False
        if not self.selectors:
            return True
        for field_name, values in self.selectors.items():
            value = event.field_value(field_name)
            if value is not None and str(value) in values:
                return True
        return False


class CaseLabeler:
    def __init__(self, cases: Iterable[Case]) -> None:
        self._cases = sorted(cases, key=lambda case: (not case.malicious, case.start))

    @property
    def cases(self) -> list[Case]:
        return list(self._cases)

    def label(self, event: SecurityEvent) -> str | None:
        for case in self._cases:
            if case.contains(event):
                return case.case_id
        return None

    def label_all(self, events: Iterable[SecurityEvent]) -> dict[str, str]:
        labels: dict[str, str] = {}
        for event in events:
            case_id = self.label(event)
            if case_id is not None:
                labels[event.event_id] = case_id
        return labels


def save_cases(cases: Iterable[Case], path: str | Path) -> None:
    Path(path).write_text(json.dumps([asdict(case) for case in cases], indent=2), encoding="utf-8")


def load_cases(path: str | Path) -> list[Case]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("A labels file must contain a JSON list of cases")
    return [Case(**item) for item in document]
