import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from linuxguard.pipeline import run_pipeline


CODE_DIR = Path(__file__).resolve().parents[1]
RAW = 'type=SYSCALL msg=audit(1700000000.125:1): uid=1000 success=yes key="lg_exec"\n'


def paths(tmp_path):
    source = tmp_path / "source.audit"
    source.write_text(RAW)
    return {"file": source, "output": tmp_path / "capture.audit", "state": tmp_path / "cursor.json",
            "database": tmp_path / "evidence.db", "host": "target"}


def test_local_pipeline_replay_then_late_records(tmp_path):
    args = paths(tmp_path)
    first = run_pipeline(**args)
    assert first.collection.bytes_written == len(RAW) and first.stored.inserted == 1
    second = run_pipeline(**args)
    assert second.collection.bytes_written == 0
    assert second.stored.inserted == second.stored.updated == 0
    with args["file"].open("a") as stream:
        stream.write('type=EXECVE msg=audit(1700000000.125:1): argc=1 a0="echo"\n')
    third = run_pipeline(**args)
    assert third.stored.inserted == 0 and third.stored.updated == 1
    assert third.parsed.events[0]["argv_complete"] is True
    with sqlite3.connect(args["database"]) as connection:
        row, = connection.execute("SELECT id, event_json FROM events").fetchall()
        assert row[0] == 1 and json.loads(row[1])["argv"] == ["echo"]
    assert args["output"].read_bytes() == args["file"].read_bytes()


def test_pipeline_rejects_malformed_data_without_database_writes(tmp_path):
    args = paths(tmp_path)
    run_pipeline(**args)
    with args["file"].open("a") as stream:
        stream.write("not an audit record\n")
    with pytest.raises(ValueError, match="malformed.*preserved"):
        run_pipeline(**args)
    assert args["output"].read_bytes() == args["file"].read_bytes()
    with sqlite3.connect(args["database"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_database_failure_recovers_from_committed_capture(tmp_path, monkeypatch):
    from linuxguard.storage import EvidenceStore

    args = paths(tmp_path)
    original = EvidenceStore.insert_events

    def fail(store, events):
        raise sqlite3.OperationalError("simulated database write failure")

    monkeypatch.setattr(EvidenceStore, "insert_events", fail)
    with pytest.raises(sqlite3.OperationalError):
        run_pipeline(**args)
    assert args["output"].read_text() == RAW and args["state"].exists()
    monkeypatch.setattr(EvidenceStore, "insert_events", original)
    result = run_pipeline(**args)
    assert result.collection.bytes_written == 0 and result.stored.inserted == 1


def test_passwd_mapping_and_local_host_are_explicit(tmp_path):
    args = paths(tmp_path)
    passwd = tmp_path / "passwd"
    passwd.write_text("alice:x:1000:1000::/home/alice:/bin/sh\n")
    args.pop("host")
    result = run_pipeline(**args, passwd_file=passwd)
    assert result.parsed.events[0]["user"] == "alice"
    assert result.parsed.events[0]["host"] == "unknown"


def test_ssh_pipeline_infers_target_hostname(tmp_path, monkeypatch):
    args = paths(tmp_path)
    args.pop("host")
    args.pop("file")
    args["ssh_host"] = "lg"

    def fake_collect(**kwargs):
        from linuxguard.collector import collect
        result = collect(output=kwargs["output"], state=kwargs["state"], file=tmp_path / "source.audit")
        cursor = json.loads(result.state.read_text())
        cursor["reader_host"] = "target-from-reader"
        result.state.write_text(json.dumps(cursor))
        return result

    monkeypatch.setattr("linuxguard.pipeline.collect", fake_collect)
    result = run_pipeline(**args)
    assert result.parsed.events[0]["host"] == "target-from-reader"


@pytest.mark.parametrize("other", ["output", "state", "file", "passwd_file"])
def test_path_collisions_are_rejected_before_writing(tmp_path, other):
    args = paths(tmp_path)
    args[other] = args["database"]
    with pytest.raises(ValueError, match="different files"):
        run_pipeline(**args)
    assert not args["database"].exists()
    assert (tmp_path / "source.audit").read_text() == RAW


def test_cli_pipeline_replay_and_database_error(tmp_path):
    args = paths(tmp_path)
    command = [sys.executable, "-m", "linuxguard", "pipeline", "--config", str(CODE_DIR / "config/linuxguard.yaml")]
    for name, value in args.items():
        command.extend(["--" + name, str(value)])
    for expected in ("1 inserted, 0 updated", "0 inserted, 0 updated"):
        result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert expected in result.stdout and "no detection" in result.stdout
    args["database"].write_bytes(b"not a database")
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 2 and "Pipeline error" in result.stderr
    assert "Traceback" not in result.stderr
