"""Host-side checks for the Phase 9 scenario runner; no privileged action is invoked.

Only pure parts are exercised: the catalogue and ``--list``. The scenarios themselves
run only as root on the VM.
"""

import importlib.util
import inspect
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scenarios" / "run.py"
spec = importlib.util.spec_from_file_location("scenario_run", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_catalogue_ids_unique_and_both_labels_present():
    catalogue = runner.build_catalogue()
    ids = [s.id for s in catalogue]
    assert len(ids) == len(set(ids))
    labels = {s.label for s in catalogue}
    assert labels == {"benign", "malicious"}
    assert sum(s.label == "malicious" for s in catalogue) >= 8
    assert sum(s.label == "benign" for s in catalogue) >= 8


def test_every_malicious_scenario_is_reversible():
    for s in runner.build_catalogue():
        if s.label == "malicious" and s.expect.startswith("R"):
            # a rule-targeted malicious action must declare how it is undone and verified
            assert callable(s.cleanup) and callable(s.verify_clean)


def test_labels_are_authored_not_derived_from_a_detector():
    # The runner must not import the detector, so a label can never come from an alert.
    source = SCRIPT.read_text()
    assert "import" in source
    assert "linuxguard.rules" not in source and "linuxguard.storage" not in source
    assert "label" in {name for name, _ in inspect.getmembers(runner.Scenario)} or \
        "label" in runner.Scenario.__dataclass_fields__


def test_list_runs_without_root_and_changes_nothing(tmp_path):
    result = subprocess.run([sys.executable, str(SCRIPT), "--list"],
                            capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 0
    assert "MAL-SUDOERS" in result.stdout and "BEN-TAR" in result.stdout
    assert not list(tmp_path.iterdir())  # no files created by listing


def test_repeats_bounds_are_enforced_before_any_privileged_work(monkeypatch):
    called = False
    def fail(*a, **k):
        nonlocal called
        called = True
    monkeypatch.setattr(runner, "execute", fail)
    with pytest.raises(SystemExit):
        runner.main(["--repeats", "0"])
    assert called is False


def test_sh_helper_allows_a_redirected_stdout(tmp_path):
    # Regression: sh() forced capture_output, which conflicts with stdout=sink.
    out = tmp_path / "out.txt"
    with out.open("w") as sink:
        runner.sh("printf", "hello", stdout=sink)
    assert out.read_text() == "hello"
    assert runner.sh("printf", "hi").stdout == "hi"  # capture still works when not redirected
