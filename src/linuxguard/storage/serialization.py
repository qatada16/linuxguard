import json
import sqlite3
from typing import Any

from linuxguard.domain.alerts import Alert, AlertStatus, DetectorType, FeatureContribution, Severity
from linuxguard.domain.events import SecurityEvent

EVENT_COLUMNS: tuple[str, ...] = (
    "event_id",
    "timestamp",
    "source",
    "record_id",
    "category",
    "action",
    "outcome",
    "host",
    "user",
    "effective_user",
    "target_user",
    "uid",
    "auid",
    "euid",
    "pid",
    "ppid",
    "session_id",
    "process_name",
    "executable",
    "parent_executable",
    "command_line",
    "working_directory",
    "target_path",
    "file_mode",
    "src_ip",
    "dest_ip",
    "dest_port",
    "audit_key",
    "correlation_id",
    "details",
    "raw",
)

ALERT_COLUMNS: tuple[str, ...] = (
    "alert_id",
    "detector",
    "rule_id",
    "title",
    "description",
    "severity",
    "status",
    "entity",
    "first_seen",
    "last_seen",
    "created_at",
    "tactic",
    "technique",
    "anomaly_score",
    "threshold",
    "contributions",
    "explanation",
    "explanation_provider",
)


def event_to_row(event: SecurityEvent) -> tuple[Any, ...]:
    values = event.to_dict()
    values["details"] = json.dumps(values["details"], sort_keys=True, default=str)
    return tuple(values[column] for column in EVENT_COLUMNS)


def event_from_row(row: sqlite3.Row) -> SecurityEvent:
    values = {column: row[column] for column in EVENT_COLUMNS}
    values["details"] = json.loads(values["details"] or "{}")
    return SecurityEvent.from_dict(values)


def alert_to_row(alert: Alert) -> tuple[Any, ...]:
    contributions = [
        {
            "name": item.name,
            "value": item.value,
            "baseline_mean": item.baseline_mean,
            "deviation": item.deviation,
            "description": item.description,
        }
        for item in alert.contributions
    ]
    values = {
        "alert_id": alert.alert_id,
        "detector": alert.detector.value,
        "rule_id": alert.rule_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.value,
        "status": alert.status.value,
        "entity": alert.entity,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "created_at": alert.created_at,
        "tactic": alert.tactic,
        "technique": alert.technique,
        "anomaly_score": alert.anomaly_score,
        "threshold": alert.threshold,
        "contributions": json.dumps(contributions),
        "explanation": alert.explanation,
        "explanation_provider": alert.explanation_provider,
    }
    return tuple(values[column] for column in ALERT_COLUMNS)


def alert_from_row(row: sqlite3.Row, evidence: list[SecurityEvent] | None = None) -> Alert:
    contributions = [FeatureContribution(**item) for item in json.loads(row["contributions"] or "[]")]
    return Alert(
        alert_id=row["alert_id"],
        detector=DetectorType(row["detector"]),
        rule_id=row["rule_id"],
        title=row["title"],
        description=row["description"],
        severity=Severity(row["severity"]),
        status=AlertStatus(row["status"]),
        entity=row["entity"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        created_at=row["created_at"],
        tactic=row["tactic"],
        technique=row["technique"],
        anomaly_score=row["anomaly_score"],
        threshold=row["threshold"],
        contributions=contributions,
        explanation=row["explanation"],
        explanation_provider=row["explanation_provider"],
        evidence=evidence or [],
    )
