import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "extract-benign-sample.py"
spec = importlib.util.spec_from_file_location("extract_benign_sample", SCRIPT)
extraction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extraction)


def inputs(tmp_path):
    capture, manifest, output = (tmp_path / name for name in ("full.audit", "manifest.json", "sample.audit"))
    capture.write_text(
        'type=SYSCALL msg=audit(1700000000.000:1): uid=1000\n'
        'type=SYSCALL msg=audit(1700000001.000:2): uid=1000\x1dUID="alice"\n'
        'type=SYSCALL msg=audit(1700000003.000:3): uid=1000\n'
        'type=EXECVE msg=audit(1700000001.000:2): argc=1 a0="echo"\n'
    )
    manifest.write_text(json.dumps({"kind": "scripted-benign-development", "status": "completed", "host": "target",
                                    "start_ts": "2023-11-14T22:13:21Z", "end_ts": "2023-11-14T22:13:23Z"}))
    return capture, manifest, output


def test_extracts_whole_interleaved_groups_and_retains_source(tmp_path):
    capture, manifest, output = inputs(tmp_path)
    original = capture.read_bytes()
    metadata = extraction.extract_sample(capture, manifest, output)
    assert metadata["events"] == 1 and metadata["records"] == 2
    assert b"SYSCALL" in output.read_bytes() and b"EXECVE" in output.read_bytes()
    assert b"1700000003" not in output.read_bytes()
    assert metadata["sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert metadata["review_status"] == "pending"
    assert capture.read_bytes() == original
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="already exists"):
        extraction.extract_sample(capture, manifest, output)


@pytest.mark.parametrize("problem", ["incomplete", "malformed", "empty-interval", "same-file"])
def test_invalid_inputs_do_not_write_sample(tmp_path, problem):
    capture, manifest, output = inputs(tmp_path)
    if problem == "incomplete":
        value = json.loads(manifest.read_text())
        manifest.write_text(json.dumps(dict(value, status="running")))
    elif problem == "malformed":
        with capture.open("a") as stream:
            stream.write("broken\n")
    elif problem == "empty-interval":
        capture.write_text('type=USER_START msg=audit(1700000099.000:9): uid=1000\n')
    else:
        output = capture
    with pytest.raises(ValueError):
        extraction.extract_sample(capture, manifest, output)
    if output != capture:
        assert not output.exists()
