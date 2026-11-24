import statistics
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from linuxguard.domain.alerts import Alert
from linuxguard.evaluation.labels import Case


def safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


@dataclass(frozen=True, slots=True)
class ResourceUsage:
    wall_seconds: float
    cpu_seconds: float
    peak_memory_mb: float
    events: int
    storage_bytes: int = 0

    @property
    def events_per_second(self) -> float:
        return safe_ratio(self.events, self.wall_seconds)

    @property
    def milliseconds_per_event(self) -> float:
        return safe_ratio(self.wall_seconds * 1000, self.events)


@dataclass(slots=True)
class DetectionMetrics:
    alerts: int
    correct_alerts: int
    malicious_cases: int
    detected_malicious: int
    benign_cases: int
    flagged_benign: int
    detection_delays: list[float] = field(default_factory=list)
    detected_by_scenario: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def alert_precision(self) -> float:
        return safe_ratio(self.correct_alerts, self.alerts)

    @property
    def case_precision(self) -> float:
        return safe_ratio(self.detected_malicious, self.detected_malicious + self.flagged_benign)

    @property
    def recall(self) -> float:
        return safe_ratio(self.detected_malicious, self.malicious_cases)

    @property
    def false_positive_rate(self) -> float:
        return safe_ratio(self.flagged_benign, self.benign_cases)

    @property
    def f1(self) -> float:
        precision, recall = self.case_precision, self.recall
        return safe_ratio(2 * precision * recall, precision + recall)

    @property
    def mean_delay_seconds(self) -> float:
        return statistics.fmean(self.detection_delays) if self.detection_delays else 0.0

    @property
    def median_delay_seconds(self) -> float:
        return statistics.median(self.detection_delays) if self.detection_delays else 0.0

    def summary(self) -> dict[str, float]:
        return {
            "alerts": self.alerts,
            "correct_alerts": self.correct_alerts,
            "alert_precision": self.alert_precision,
            "case_precision": self.case_precision,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "f1": self.f1,
            "malicious_cases": self.malicious_cases,
            "detected_malicious": self.detected_malicious,
            "benign_cases": self.benign_cases,
            "flagged_benign": self.flagged_benign,
            "mean_delay_seconds": self.mean_delay_seconds,
            "median_delay_seconds": self.median_delay_seconds,
        }


def score_alerts(alerts: Iterable[Alert], cases: list[Case], event_labels: dict[str, str]) -> DetectionMetrics:
    cases_by_id = {case.case_id: case for case in cases}
    flagged: dict[str, float] = {}
    alert_list = list(alerts)
    correct = 0
    for alert in alert_list:
        touched = {event_labels[event.event_id] for event in alert.evidence if event.event_id in event_labels}
        is_correct = any(cases_by_id[case_id].malicious for case_id in touched)
        correct += int(is_correct)
        for case_id in touched:
            if is_correct and not cases_by_id[case_id].malicious:
                continue
            flagged[case_id] = min(flagged.get(case_id, alert.last_seen), alert.last_seen)
    malicious = [case for case in cases if case.malicious]
    benign = [case for case in cases if not case.malicious]
    per_scenario: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    delays = []
    for case in malicious:
        per_scenario[case.scenario][1] += 1
        if case.case_id in flagged:
            per_scenario[case.scenario][0] += 1
            delays.append(max(0.0, flagged[case.case_id] - case.start))
    for case in benign:
        per_scenario[case.scenario][1] += 1
        if case.case_id in flagged:
            per_scenario[case.scenario][0] += 1
    return DetectionMetrics(
        alerts=len(alert_list),
        correct_alerts=correct,
        malicious_cases=len(malicious),
        detected_malicious=sum(1 for case in malicious if case.case_id in flagged),
        benign_cases=len(benign),
        flagged_benign=sum(1 for case in benign if case.case_id in flagged),
        detection_delays=delays,
        detected_by_scenario={name: (counts[0], counts[1]) for name, counts in per_scenario.items()},
    )
