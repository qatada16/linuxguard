import os
import sqlite3
import stat
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    source TEXT NOT NULL,
    record_id TEXT NOT NULL,
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    host TEXT,
    user TEXT,
    effective_user TEXT,
    target_user TEXT,
    uid INTEGER,
    auid INTEGER,
    euid INTEGER,
    pid INTEGER,
    ppid INTEGER,
    session_id TEXT,
    process_name TEXT,
    executable TEXT,
    parent_executable TEXT,
    command_line TEXT,
    working_directory TEXT,
    target_path TEXT,
    file_mode INTEGER,
    src_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    audit_key TEXT,
    correlation_id TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    raw TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_correlation ON events (correlation_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_user ON events (user, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_category ON events (category, timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    detector TEXT NOT NULL,
    rule_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    entity TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    created_at REAL NOT NULL,
    tactic TEXT,
    technique TEXT,
    anomaly_score REAL,
    threshold REAL,
    contributions TEXT NOT NULL DEFAULT '[]',
    explanation TEXT,
    explanation_provider TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts (last_seen);

CREATE TABLE IF NOT EXISTS alert_evidence (
    alert_id TEXT NOT NULL REFERENCES alerts (alert_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events (event_id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_evidence_event ON alert_evidence (event_id);
"""


def _restrict_permissions(path: Path) -> None:
    if os.name == "posix" and path.exists():
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def connect(database_path: str | Path) -> sqlite3.Connection:
    path = Path(database_path)
    in_memory = str(database_path) == ":memory:"
    if not in_memory:
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(database_path), check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    if not in_memory:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
    initialize_schema(connection)
    if not in_memory:
        _restrict_permissions(path)
    return connection


def initialize_schema(connection: sqlite3.Connection) -> None:
    with connection:
        connection.executescript(SCHEMA)
        current = connection.execute("SELECT version FROM schema_info").fetchone()
        if current is None:
            connection.execute("INSERT INTO schema_info (version) VALUES (?)", (SCHEMA_VERSION,))
        elif current["version"] != SCHEMA_VERSION:
            raise RuntimeError(
                f"Database schema version {current['version']} is not supported (expected {SCHEMA_VERSION})"
            )
