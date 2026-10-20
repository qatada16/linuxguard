import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benign-workload.py"
spec = importlib.util.spec_from_file_location("benign_workload", SCRIPT)
workload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workload)


def test_short_workload_is_contained_and_records_success(tmp_path):
    result = workload.run_workload(tmp_path, duration=0)
    work = Path(result["directory"])
    assert work.parent == tmp_path
    assert result["status"] == "completed" and result["end_ts"] >= result["start_ts"]
    assert result["steps"] and all(step["returncode"] == 0 for step in result["steps"])
    assert json.loads((work / "manifest.json").read_text()) == result
    assert (work / "notes.txt").read_text().startswith("LinuxGuard development notes")


def test_command_failure_keeps_failed_manifest(tmp_path, monkeypatch):
    def fail(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, "", "test failure")

    monkeypatch.setattr(workload.subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        workload.run_workload(tmp_path, duration=0)
    manifest, = tmp_path.glob("*/manifest.json")
    result = json.loads(manifest.read_text())
    assert result["status"] == "failed" and result["end_ts"]
    assert result["steps"][0]["stderr"] == "test failure"


def test_duration_is_bounded_before_creating_files(tmp_path):
    for duration in (-1, 7201):
        with pytest.raises(ValueError, match="duration"):
            workload.run_workload(tmp_path, duration)
    assert not list(tmp_path.iterdir())
