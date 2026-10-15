"""Local SQLite evidence with stable event IDs and replay-safe batch updates."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3


_SCHEMA = """
CREATE TABLE events (
    id INTEGER PRIMARY KEY, host TEXT NOT NULL, audit_id TEXT NOT NULL,
    ts TEXT NOT NULL, serial TEXT NOT NULL, event_type TEXT NOT NULL,
    key TEXT, user TEXT, uid INTEGER, pid INTEGER, ppid INTEGER,
    exe TEXT, cmdline TEXT, path TEXT, success INTEGER CHECK(success IN (0, 1)),
    src_ip TEXT, raw BLOB NOT NULL, event_json TEXT NOT NULL,
    UNIQUE(host, ts, serial)
);
CREATE INDEX events_ts ON events(ts);
CREATE INDEX events_user_ts ON events(user, ts);
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, ts TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('rule', 'ml')), rule_id TEXT,
    severity TEXT NOT NULL, title TEXT NOT NULL, reason TEXT NOT NULL,
    anomaly_score REAL, window_start TEXT, window_end TEXT,
    status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new', 'investigating', 'closed'))
);
CREATE INDEX alerts_ts ON alerts(ts);
CREATE TABLE alert_evidence (
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    event_id INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY(alert_id, event_id)
);
CREATE TABLE features (
    window_start TEXT NOT NULL, window_end TEXT NOT NULL,
    user TEXT NOT NULL, f_json TEXT NOT NULL,
    PRIMARY KEY(window_start, window_end, user)
);
PRAGMA user_version = 1;
"""
_EVENT_COLUMNS = ("host", "audit_id", "ts", "serial", "event_type", "key", "user", "uid",
                  "pid", "ppid", "exe", "cmdline", "path", "success", "src_ip", "raw", "event_json")
_ALERT_COLUMNS = ("ts", "source", "rule_id", "severity", "title", "reason", "anomaly_score",
                  "window_start", "window_end", "status")


def utc_timestamp(value):
    """Use fixed-width UTC strings so SQLite ordering matches chronological order."""
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return stamp.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class InsertResult:
    inserted: int
    updated: int
    unchanged: int


class EvidenceStore:
    def __init__(self, database: str | Path):
        path = Path(database).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        try:
            self.connection.execute("PRAGMA foreign_keys = ON")
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                if self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                    raise ValueError("database is not an empty LinuxGuard database")
                self.connection.executescript("BEGIN;\n" + _SCHEMA + "\nCOMMIT;")
            elif version != 1:
                raise ValueError(f"unsupported database version: {version}")
        except Exception:
            self.connection.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.connection.close()

    def insert_events(self, events) -> InsertResult:
        """Upsert cumulative groups, never replacing fuller evidence with a stale batch.

        Divergent evidence for the same identity is an error, not an overwrite.
        Use a separate database for independent VM snapshot runs.
        """
        inserted = updated = unchanged = 0
        columns = ", ".join(_EVENT_COLUMNS)
        placeholders = ", ".join("?" for _ in _EVENT_COLUMNS)
        with self.connection:
            for source in events:
                event = {**source, "ts": utc_timestamp(source["ts"])}
                raw = event["raw"].encode("utf-8", errors="surrogateescape")
                payload = json.dumps(event, sort_keys=True)
                old = self.connection.execute(
                    "SELECT id, raw, event_json FROM events WHERE host=? AND ts=? AND serial=?",
                    (event["host"], event["ts"], event["serial"]),
                ).fetchone()
                if old is not None:
                    if old["raw"].startswith(raw) and len(old["raw"]) > len(raw):
                        unchanged += 1
                        continue
                    if not raw.startswith(old["raw"]):
                        raise ValueError("conflicting raw evidence for " + event["host"] + ":" + event["audit_id"])
                    if old["event_json"] == payload:
                        unchanged += 1
                        continue
                values = {**event, "raw": raw, "event_json": payload}
                row = [values.get(column) for column in _EVENT_COLUMNS]
                if old is None:
                    self.connection.execute(f"INSERT INTO events ({columns}) VALUES ({placeholders})", row)
                    inserted += 1
                else:
                    assignments = ", ".join(column + "=?" for column in _EVENT_COLUMNS)
                    self.connection.execute(f"UPDATE events SET {assignments} WHERE id=?", [*row, old["id"]])
                    updated += 1
        return InsertResult(inserted, updated, unchanged)


    def events_between(self, start, end, *, user=None) -> list[dict]:
        """Return normalized events plus database IDs in the half-open interval [start, end)."""
        start, end = utc_timestamp(start), utc_timestamp(end)
        if end <= start:
            raise ValueError("end must be after start")
        query = "SELECT id, event_json FROM events WHERE ts>=? AND ts<?"
        args = [start, end]
        if user is not None:
            query += " AND user=?"
            args.append(user)
        rows = self.connection.execute(query + " ORDER BY ts, CAST(serial AS INTEGER), host", args)
        return [dict(json.loads(row["event_json"]), id=row["id"]) for row in rows]

