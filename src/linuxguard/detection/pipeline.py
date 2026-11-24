from enum import StrEnum

from linuxguard.detection.anomaly.detector import AnomalyFinding, IsolationForestDetector
from linuxguard.detection.anomaly.windows import ActivityWindow, WindowAggregator
from linuxguard.detection.rules.engine import MISSING_GROUP_VALUE, RuleEngine
from linuxguard.detection.rules.model import RuleMatch
from linuxguard.domain.alerts import Alert, DetectorType, Severity, format_number
from linuxguard.domain.events import SecurityEvent

ANOMALY_TACTIC = "Anomalous Behaviour"
MEDIUM_MARGIN = 0.03
HIGH_MARGIN = 0.08


class DetectionMode(StrEnum):
    RULES = "rules"
    HYBRID = "hybrid"


def limit_evidence(events: list[SecurityEvent], limit: int) -> list[SecurityEvent]:
    if len(events) <= limit:
        return list(events)
    head = limit // 2
    return events[:head] + events[len(events) - (limit - head) :]


def describe_entity(fields: tuple[str, ...], key: tuple[str, ...], trigger: SecurityEvent) -> str:
    parts = []
    for field, value in zip(fields, key, strict=True):
        if value == MISSING_GROUP_VALUE:
            continue
        parts.append(f"{trigger.user or 'unknown'}@session:{value}" if field == "session_id" else value)
    return ", ".join(parts)


def anomaly_severity(score: float, threshold: float) -> Severity:
    margin = score - threshold
    if margin >= HIGH_MARGIN:
        return Severity.HIGH
    if margin >= MEDIUM_MARGIN:
        return Severity.MEDIUM
    return Severity.LOW


def alert_from_rule_match(match: RuleMatch, evidence_limit: int) -> Alert:
    rule = match.rule
    events = match.events
    trigger = events[-1]
    entity = trigger.entity
    if rule.threshold is not None or rule.sequence is not None:
        fields = rule.threshold.group_by if rule.threshold is not None else rule.sequence.group_by
        entity = describe_entity(fields, match.group_key, trigger) or entity
    return Alert(
        detector=DetectorType.RULE,
        title=rule.name,
        severity=rule.severity,
        description=f"{rule.description} {match.reason}.".strip(),
        entity=entity,
        first_seen=events[0].timestamp,
        last_seen=trigger.timestamp,
        evidence=limit_evidence(events, evidence_limit),
        rule_id=rule.rule_id,
        tactic=rule.tactic,
        technique=rule.technique,
    )


def alert_from_finding(finding: AnomalyFinding, evidence_limit: int) -> Alert:
    window = finding.window
    unusual = ", ".join(
        f"{item.description} = {format_number(item.value)} (baseline mean {item.baseline_mean:.2f})"
        for item in finding.contributions
    )
    if finding.score > finding.threshold:
        basis = (
            f"Isolation Forest anomaly score {finding.score:.3f} exceeded the baseline threshold "
            f"{finding.threshold:.3f}"
        )
    else:
        basis = f"Isolation Forest score {finding.score:.3f} was below the threshold {finding.threshold:.3f}, but"
    if finding.exceeded_features:
        basis += f" {', '.join(finding.exceeded_features)} far exceeded the largest value seen in the baseline"
    description = (
        f"{basis} for {len(window.events)} events in a {window.end - window.start:g}s window. "
        f"Most unusual features: {unusual or 'n/a'}. "
        "An anomaly indicates unusual behaviour, not a confirmed intrusion."
    )
    severity = anomaly_severity(finding.score, finding.threshold)
    if finding.exceeded_features and severity.rank < Severity.MEDIUM.rank:
        severity = Severity.MEDIUM
    return Alert(
        detector=DetectorType.ANOMALY,
        title=f"Anomalous activity for {window.entity}",
        severity=severity,
        description=description,
        entity=window.entity,
        first_seen=window.events[0].timestamp,
        last_seen=window.end,
        evidence=limit_evidence(sorted(window.events, key=lambda event: event.timestamp), evidence_limit),
        tactic=ANOMALY_TACTIC,
        anomaly_score=finding.score,
        threshold=finding.threshold,
        contributions=list(finding.contributions),
    )


class DetectionPipeline:
    def __init__(
        self,
        rule_engine: RuleEngine,
        detector: IsolationForestDetector | None = None,
        mode: DetectionMode = DetectionMode.RULES,
        lateness_seconds: float = 5.0,
        evidence_limit: int = 50,
    ) -> None:
        if mode == DetectionMode.HYBRID and (detector is None or not detector.is_fitted):
            raise ValueError("Hybrid detection requires a trained anomaly detector")
        self._rules = rule_engine
        self._detector = detector if mode == DetectionMode.HYBRID else None
        self._mode = mode
        self._evidence_limit = evidence_limit
        self._aggregator = WindowAggregator(self._detector.window_seconds, lateness_seconds) if self._detector else None

    @property
    def mode(self) -> DetectionMode:
        return self._mode

    def process(self, event: SecurityEvent) -> list[Alert]:
        alerts = [alert_from_rule_match(match, self._evidence_limit) for match in self._rules.process(event)]
        if self._aggregator is not None:
            alerts.extend(self._score_windows(self._aggregator.add(event)))
        return alerts

    def process_all(self, events: list[SecurityEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            alerts.extend(self.process(event))
        alerts.extend(self.flush())
        return alerts

    def advance(self, now: float) -> list[Alert]:
        if self._aggregator is None:
            return []
        return self._score_windows(self._aggregator.advance(now))

    def flush(self) -> list[Alert]:
        if self._aggregator is None:
            return []
        return self._score_windows(self._aggregator.flush())

    def _score_windows(self, windows: list[ActivityWindow]) -> list[Alert]:
        if not windows or self._detector is None:
            return []
        findings = self._detector.detect(windows)
        return [alert_from_finding(finding, self._evidence_limit) for finding in findings]
