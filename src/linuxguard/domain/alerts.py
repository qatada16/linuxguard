import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum

from linuxguard.domain.events import SecurityEvent


def format_number(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class DetectorType(StrEnum):
    RULE = "rule"
    ANOMALY = "anomaly"


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass(frozen=True, slots=True)
class FeatureContribution:
    name: str
    value: float
    baseline_mean: float
    deviation: float
    description: str = ""


@dataclass(slots=True)
class Alert:
    detector: DetectorType
    title: str
    severity: Severity
    description: str
    entity: str
    first_seen: float
    last_seen: float
    evidence: list[SecurityEvent] = field(default_factory=list)
    rule_id: str | None = None
    tactic: str | None = None
    technique: str | None = None
    anomaly_score: float | None = None
    threshold: float | None = None
    contributions: list[FeatureContribution] = field(default_factory=list)
    status: AlertStatus = AlertStatus.OPEN
    explanation: str | None = None
    explanation_provider: str | None = None
    created_at: float = field(default_factory=time.time)
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @property
    def evidence_ids(self) -> list[str]:
        return [event.event_id for event in self.evidence]
