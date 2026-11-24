from dataclasses import dataclass, field

from linuxguard.detection.rules.conditions import EventMatcher
from linuxguard.domain.alerts import Severity
from linuxguard.domain.events import SecurityEvent

DEFAULT_SUPPRESSION_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class Threshold:
    count: int
    window_seconds: float
    group_by: tuple[str, ...] = ()
    distinct: str | None = None


@dataclass(frozen=True, slots=True)
class SequenceStep:
    matcher: EventMatcher
    min_count: int = 1


@dataclass(frozen=True, slots=True)
class RuleSequence:
    steps: tuple[SequenceStep, ...]
    within_seconds: float
    group_by: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    name: str
    description: str
    severity: Severity
    matcher: EventMatcher | None = None
    exclusions: tuple[EventMatcher, ...] = ()
    threshold: Threshold | None = None
    sequence: RuleSequence | None = None
    tactic: str | None = None
    technique: str | None = None
    explanation: str | None = None
    response: tuple[str, ...] = ()
    enabled: bool = True
    suppress_seconds: float = DEFAULT_SUPPRESSION_SECONDS
    tags: tuple[str, ...] = field(default_factory=tuple)

    def is_excluded(self, event: SecurityEvent) -> bool:
        return any(exclusion.matches(event) for exclusion in self.exclusions)

    def matches(self, event: SecurityEvent) -> bool:
        return self.matcher is not None and self.matcher.matches(event) and not self.is_excluded(event)


@dataclass(slots=True)
class RuleMatch:
    rule: Rule
    events: list[SecurityEvent]
    group_key: tuple[str, ...]
    reason: str
