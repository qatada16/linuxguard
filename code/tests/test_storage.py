import io
import sqlite3

import pytest

from linuxguard.parser import parse_lines
from linuxguard.storage import EvidenceStore, InsertResult


def event(serial="1", epoch="1700000000.125", host="target"):
    return parse_lines(io.StringIO(
        f'type=SYSCALL msg=audit({epoch}:{serial}): uid=1000 auid=1000 pid=12 '
        'success=yes exe="/usr/bin/echo" key="lg_exec"\n'
    ), host=host).events[0]


def alert():
    return {"ts": "2023-11-14T22:13:20Z", "source": "rule", "rule_id": "R001",
            "severity": "high", "title": "Test alert", "reason": "Synthetic evidence"}


def test_replay_preserves_full_normalization_and_private_database(tmp_path):
    path = tmp_path / "evidence.db"
    original = event()
    with EvidenceStore(path) as store:
        assert store.insert_events([original]) == InsertResult(1, 0, 0)
        assert store.insert_events([original]) == InsertResult(0, 0, 1)
        rows = store.events_between("2023-11-14T22:13:20Z", "2023-11-14T22:13:21Z")
        assert rows == [dict(original, id=1)]
        assert store.connection.execute("SELECT raw FROM events").fetchone()[0] == original["raw"].encode()
        assert store.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert path.stat().st_mode & 0o777 == 0o600
    with EvidenceStore(path) as store:
        assert store.insert_events([original]).unchanged == 1


def test_late_records_update_same_id_and_keep_alert_evidence(tmp_path):
    partial = event()
    extra = 'type=EXECVE msg=audit(1700000000.125:1): argc=2 a0="echo" a1="hello"\n'
    complete = parse_lines(io.StringIO(partial["raw"] + extra), host="target").events[0]
    with EvidenceStore(tmp_path / "evidence.db") as store:
        store.insert_events([partial])
        alert_id = store.insert_alert(alert(), [1])
        assert store.insert_events([complete]) == InsertResult(0, 1, 0)
        assert store.timeline(alert_id)[0]["id"] == 1
        assert store.timeline(alert_id)[0]["argv"] == ["echo", "hello"]
        assert store.insert_events([partial]) == InsertResult(0, 0, 1)
        assert store.timeline(alert_id)[0]["raw"] == complete["raw"]


def test_conflicting_evidence_rolls_back_entire_batch(tmp_path):
    original = event()
    conflict = dict(original, raw=original["raw"].replace("success=yes", "success=no"))
    with EvidenceStore(tmp_path / "evidence.db") as store:
        store.insert_events([original])
        with pytest.raises(ValueError, match="conflicting raw"):
            store.insert_events([event(serial="2"), conflict])
        assert store.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert store.connection.execute("SELECT raw FROM events").fetchone()[0] == original["raw"].encode()


def test_event_identity_includes_host_timestamp_and_serial(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        result = store.insert_events([event(), event(host="other"), event(epoch="1700000001.125"), event(serial="2")])
        assert result.inserted == 4


def test_timestamp_queries_use_real_order_and_half_open_bounds(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        store.insert_events([event(epoch="1700000000"), event(epoch="1700000000.125"), event(epoch="1700000001")])
        rows = store.events_between("2023-11-15T03:13:20+05:00", "2023-11-14T22:13:21Z", user="1000")
        assert [row["ts"] for row in rows] == ["2023-11-14T22:13:20.000000Z", "2023-11-14T22:13:20.125000Z"]
        assert store.events_between("2023-11-14T22:13:20Z", "2023-11-14T22:13:21Z", user="someone-else") == []
        with pytest.raises(ValueError, match="timezone"):
            store.events_between("2023-11-14T22:13:20", "2023-11-14T22:13:21Z")
        with pytest.raises(ValueError, match="after"):
            store.events_between("2023-11-14T22:13:21Z", "2023-11-14T22:13:20Z")


def test_alert_replay_keeps_status_and_returns_ordered_evidence(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        store.insert_events([event(epoch="1700000001"), event(epoch="1700000000")])
        alert_id = store.insert_alert(alert(), [1, 2, 2])
        store.connection.execute("UPDATE alerts SET status='closed' WHERE id=?", (alert_id,))
        store.connection.commit()
        assert store.insert_alert(alert(), [2, 1]) == alert_id
        assert store.connection.execute("SELECT status FROM alerts").fetchone()[0] == "closed"
        assert [row["id"] for row in store.timeline(alert_id)] == [2, 1]
        assert store.connection.execute("SELECT COUNT(*) FROM alert_evidence").fetchone()[0] == 2
        assert store.timeline(999) == []


def test_failed_alert_evidence_link_leaves_no_orphan_alert(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        store.insert_events([event()])
        with pytest.raises(sqlite3.IntegrityError):
            store.insert_alert(alert(), [1, 999])
        assert store.connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
        assert store.connection.execute("SELECT COUNT(*) FROM alert_evidence").fetchone()[0] == 0
        with pytest.raises(ValueError, match="evidence"):
            store.insert_alert(alert(), [])
        with pytest.raises(sqlite3.IntegrityError):
            store.insert_alert(dict(alert(), source="unknown"), [1])


def test_non_utf8_raw_bytes_round_trip(tmp_path):
    original = event()
    original["raw"] += "\udcff\n"
    with EvidenceStore(tmp_path / "evidence.db") as store:
        store.insert_events([original])
        raw = store.connection.execute("SELECT raw FROM events").fetchone()[0]
        assert raw.endswith(b"\xff\n")
        rows = store.events_between("2023-11-14T22:13:20Z", "2023-11-14T22:13:21Z")
        assert rows[0]["raw"] == original["raw"]


def test_unrelated_or_future_database_is_rejected(tmp_path):
    path = tmp_path / "other.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE user_data (value TEXT)")
    with pytest.raises(ValueError, match="not an empty"):
        EvidenceStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="unsupported"):
        EvidenceStore(path)
