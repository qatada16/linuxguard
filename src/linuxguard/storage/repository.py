import sqlite3
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Self

from linuxguard.domain.alerts import Alert, AlertStatus
from linuxguard.domain.events import SecurityEvent
from linuxguard.storage.database import connect
from linuxguard.storage.serialization import (
    ALERT_COLUMNS,
    EVENT_COLUMNS,
    alert_from_row,
    alert_to_row,
    event_from_row,
    event_to_row,
)

_EVENT_INSERT = (
    f"INSERT OR IGNORE INTO events ({', '.join(EVENT_COLUMNS)}) VALUES ({', '.join('?' for _ in EVENT_COLUMNS)})"
)
_ALERT_INSERT = (
    f"INSERT OR REPLACE INTO alerts ({', '.join(ALERT_COLUMNS)}) VALUES ({', '.join('?' for _ in ALERT_COLUMNS)})"
)
_EVENT_SELECT = f"SELECT {', '.join(EVENT_COLUMNS)} FROM events"
_QUALIFIED_EVENT_COLUMNS = ", ".join(f"e.{column}" for column in EVENT_COLUMNS)
QUERY_CHUNK_SIZE = 500


class EvidenceStore:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    @classmethod
    def open(cls, database_path: str | Path) -> Self:
        return cls(connect(database_path))

    def close(self) -> None:
        self._connection.close()

    def checkpoint(self) -> None:
        self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def save_events(self, events: Iterable[SecurityEvent]) -> int:
        rows = [event_to_row(event) for event in events]
        if not rows:
            return 0
        with self._connection:
            before = self._connection.total_changes
            self._connection.executemany(_EVENT_INSERT, rows)
            return self._connection.total_changes - before

    def save_alert(self, alert: Alert) -> None:
        self.save_alerts([alert])

    def save_alerts(self, alerts: Sequence[Alert]) -> None:
        if not alerts:
            return
        with self._connection:
            for alert in alerts:
                self._connection.executemany(_EVENT_INSERT, [event_to_row(event) for event in alert.evidence])
                self._connection.execute(_ALERT_INSERT, alert_to_row(alert))
                self._connection.executemany(
                    "INSERT OR IGNORE INTO alert_evidence (alert_id, event_id, position) VALUES (?, ?, ?)",
                    [(alert.alert_id, event.event_id, index) for index, event in enumerate(alert.evidence)],
                )

    def get_alert(self, alert_id: str, include_evidence: bool = True) -> Alert | None:
        row = self._connection.execute(
            f"SELECT {', '.join(ALERT_COLUMNS)} FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if row is None:
            return None
        evidence = self.evidence_for(alert_id) if include_evidence else []
        return alert_from_row(row, evidence)

    def list_alerts(
        self,
        severity: str | None = None,
        status: str | None = None,
        detector: str | None = None,
        since: float | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[Alert]:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (("severity", severity), ("status", status), ("detector", detector)):
            if value:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        if since is not None:
            clauses.append("last_seen >= ?")
            parameters.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = (
            f"SELECT {', '.join(ALERT_COLUMNS)} FROM alerts{where} "
            "ORDER BY last_seen DESC, created_at DESC LIMIT ? OFFSET ?"
        )
        rows = self._connection.execute(query, (*parameters, limit, offset)).fetchall()
        return [alert_from_row(row) for row in rows]

    def evidence_for(self, alert_id: str) -> list[SecurityEvent]:
        rows = self._connection.execute(
            f"SELECT {_QUALIFIED_EVENT_COLUMNS} FROM alert_evidence AS a "
            "JOIN events AS e ON e.event_id = a.event_id WHERE a.alert_id = ? ORDER BY a.position",
            (alert_id,),
        ).fetchall()
        return [event_from_row(row) for row in rows]

    def alert_ids_for_events(self, event_ids: Sequence[str]) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for offset in range(0, len(event_ids), QUERY_CHUNK_SIZE):
            chunk = tuple(event_ids[offset : offset + QUERY_CHUNK_SIZE])
            placeholders = ", ".join("?" for _ in chunk)
            rows = self._connection.execute(
                f"SELECT event_id, alert_id FROM alert_evidence WHERE event_id IN ({placeholders})", chunk
            ).fetchall()
            for row in rows:
                mapping.setdefault(row["event_id"], []).append(row["alert_id"])
        return mapping

    def events_between(
        self,
        start: float,
        end: float,
        correlation_ids: Sequence[str] | None = None,
        users: Sequence[str] | None = None,
        limit: int = 2000,
    ) -> list[SecurityEvent]:
        clauses = ["timestamp BETWEEN ? AND ?"]
        parameters: list[Any] = [start, end]
        scopes: list[str] = []
        if correlation_ids:
            scopes.append(f"correlation_id IN ({', '.join('?' for _ in correlation_ids)})")
            parameters.extend(correlation_ids)
        if users:
            scopes.append(f"user IN ({', '.join('?' for _ in users)})")
            parameters.extend(users)
        if scopes:
            clauses.append(f"({' OR '.join(scopes)})")
        query = f"{_EVENT_SELECT} WHERE {' AND '.join(clauses)} ORDER BY timestamp, event_id LIMIT ?"
        rows = self._connection.execute(query, (*parameters, limit)).fetchall()
        return [event_from_row(row) for row in rows]

    def update_status(self, alert_id: str, status: AlertStatus) -> bool:
        with self._connection:
            cursor = self._connection.execute(
                "UPDATE alerts SET status = ? WHERE alert_id = ?", (status.value, alert_id)
            )
        return cursor.rowcount > 0

    def save_explanation(self, alert_id: str, explanation: str, provider: str) -> bool:
        with self._connection:
            cursor = self._connection.execute(
                "UPDATE alerts SET explanation = ?, explanation_provider = ? WHERE alert_id = ?",
                (explanation, provider, alert_id),
            )
        return cursor.rowcount > 0

    def statistics(self) -> dict[str, Any]:
        def grouped(column: str) -> dict[str, int]:
            rows = self._connection.execute(
                f"SELECT {column} AS key, COUNT(*) AS total FROM alerts GROUP BY {column}"
            ).fetchall()
            return {row["key"]: row["total"] for row in rows}

        events = self._connection.execute(
            "SELECT COUNT(*) AS total, MIN(timestamp) AS first, MAX(timestamp) AS last FROM events"
        ).fetchone()
        alerts_total = self._connection.execute("SELECT COUNT(*) AS total FROM alerts").fetchone()["total"]
        return {
            "events": events["total"],
            "first_event": events["first"],
            "last_event": events["last"],
            "alerts": alerts_total,
            "by_severity": grouped("severity"),
            "by_detector": grouped("detector"),
            "by_status": grouped("status"),
        }
