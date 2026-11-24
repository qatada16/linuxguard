import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from linuxguard.domain.alerts import Alert
from linuxguard.investigation.timeline import Timeline

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _as_datetime(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, UTC)


def alerts_frame(alerts: list[Alert]) -> pd.DataFrame:
    rows = [
        {
            "id": alert.alert_id,
            "last_seen": _as_datetime(alert.last_seen),
            "severity": alert.severity.value,
            "detector": alert.detector.value,
            "rule": alert.rule_id or "-",
            "status": alert.status.value,
            "title": alert.title,
            "entity": alert.entity,
            "score": alert.anomaly_score,
        }
        for alert in alerts
    ]
    columns = ["id", "last_seen", "severity", "detector", "rule", "status", "title", "entity", "score"]
    return pd.DataFrame(rows, columns=columns)


def alerts_per_hour(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame()
    grouped = frame.assign(hour=frame["last_seen"].dt.floor("h")).groupby(["hour", "detector"]).size()
    return grouped.unstack(fill_value=0)


def timeline_frame(timeline: Timeline) -> pd.DataFrame:
    rows = [
        {
            "time": _as_datetime(entry.event.timestamp),
            "evidence": entry.is_evidence,
            "source": entry.event.source,
            "category": entry.event.category.value,
            "user": entry.event.user,
            "activity": entry.summary,
            "alerts": len(entry.related_alert_ids),
        }
        for entry in timeline.entries
    ]
    return pd.DataFrame(rows, columns=["time", "evidence", "source", "category", "user", "activity", "alerts"])


def load_evaluation(path: str | Path) -> dict[str, Any] | None:
    results = Path(path)
    if not results.is_file():
        return None
    return json.loads(results.read_text(encoding="utf-8"))


def evaluation_frame(summary: dict[str, Any]) -> pd.DataFrame:
    rows = []
    for result in summary["configurations"].values():
        metrics = result["metrics"]
        rows.append(
            {
                "configuration": result["label"],
                "precision": metrics["case_precision"]["mean"],
                "recall": metrics["recall"]["mean"],
                "false_positive_rate": metrics["false_positive_rate"]["mean"],
                "f1": metrics["f1"]["mean"],
                "alerts": metrics["alerts"]["mean"],
                "mean_delay_s": metrics["mean_delay_seconds"]["mean"],
                "ms_per_event": result["resources"]["milliseconds_per_event"]["mean"],
            }
        )
    return pd.DataFrame(rows)
