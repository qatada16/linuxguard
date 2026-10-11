import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from linuxguard.collector import CollectionError, collect


@pytest.fixture
def capture(tmp_path):
    source = tmp_path / "audit.log"
    source.write_bytes(b"first\nsecond\n")
    output, state = tmp_path / "capture.audit", tmp_path / "state.json"
    return source, output, state


def run(capture):
    source, output, state = capture
    return collect(file=source, output=output, state=state)


def test_incremental_read_does_not_duplicate_and_preserves_partial_line(capture):
    source, output, state = capture
    assert run(capture).bytes_written == len(b"first\nsecond\n")
    assert run(capture).bytes_written == 0
    with source.open("ab") as stream:
        stream.write(b"third")
    assert run(capture).bytes_written == 0
    with source.open("ab") as stream:
        stream.write(b"\n")
    assert run(capture).bytes_written == len(b"third\n")
    assert output.read_bytes() == b"first\nsecond\nthird\n"
    assert json.loads(state.read_text())["cursor"]["offset"] == source.stat().st_size
    assert output.stat().st_mode & 0o777 == 0o600
    assert state.stat().st_mode & 0o777 == 0o600


def test_rename_rotation_collects_old_tail_before_new_log(capture):
    source, output, _ = capture
    run(capture)
    with source.open("ab") as stream:
        stream.write(b"old-tail\n")
    source.rename(source.with_name("audit.log.1"))
    source.write_bytes(b"new-log\n")
    result = run(capture)
    assert result.rotated_files == [str(source.with_name("audit.log.1"))]
    assert output.read_bytes() == b"first\nsecond\nold-tail\nnew-log\n"
    assert run(capture).bytes_written == 0


def test_multiple_rotations_are_read_in_order(capture):
    source, output, _ = capture
    run(capture)
    with source.open("ab") as stream:
        stream.write(b"tail\n")
    source.rename(source.with_name("audit.log.2"))
    source.with_name("audit.log.1").write_bytes(b"middle\n")
    source.write_bytes(b"current\n")
    run(capture)
    assert output.read_bytes() == b"first\nsecond\ntail\nmiddle\ncurrent\n"


def test_copytruncate_uses_retained_copy(capture):
    source, output, _ = capture
    run(capture)
    source.with_name("audit.log.1").write_bytes(source.read_bytes() + b"tail\n")
    source.write_bytes(b"new\n")
    run(capture)
    assert output.read_bytes() == b"first\nsecond\ntail\nnew\n"


@pytest.mark.parametrize("kind", ["truncated", "renamed", "missing_middle", "partial_archive"])
def test_gap_does_not_advance_state_or_modify_capture(capture, kind):
    source, output, state = capture
    run(capture)
    original_state, original_capture = state.read_bytes(), output.read_bytes()
    if kind == "truncated":
        source.write_bytes(b"new\n")
    elif kind == "renamed":
        source.rename(source.with_name("unavailable"))
        source.write_bytes(b"new\n")
    elif kind == "missing_middle":
        source.rename(source.with_name("audit.log.2"))
        source.write_bytes(b"new\n")
    else:
        with source.open("ab") as stream:
            stream.write(b"partial")
        source.rename(source.with_name("audit.log.1"))
        source.write_bytes(b"new\n")
    with pytest.raises(CollectionError):
        run(capture)
    assert state.read_bytes() == original_state
    assert output.read_bytes() == original_capture


@pytest.mark.parametrize("change", ["capture_deleted", "capture_edited", "state_corrupted", "different_source"])
def test_invalid_saved_state_is_not_silently_reset(capture, change):
    source, output, state = capture
    run(capture)
    if change == "capture_deleted":
        output.unlink()
    elif change == "capture_edited":
        output.write_bytes(b"changed\n")
    elif change == "state_corrupted":
        state.write_text("broken json")
    else:
        another = source.with_name("another.log")
        another.write_bytes(b"other\n")
        capture = another, output, state
    with pytest.raises(CollectionError):
        run(capture)


def test_existing_output_without_state_is_not_appended(capture):
    _, output, _ = capture
    output.write_bytes(b"evidence to preserve\n")
    with pytest.raises(CollectionError, match="already contains"):
        run(capture)
    assert output.read_bytes() == b"evidence to preserve\n"


def test_source_cannot_be_overwritten(capture):
    source, _, state = capture
    with pytest.raises(ValueError, match="different files"):
        collect(file=source, output=source, state=state)


def test_ssh_failure_does_not_create_capture_or_state(tmp_path):
    output, state = tmp_path / "out.audit", tmp_path / "state.json"
    with patch("linuxguard.collector.subprocess.run", return_value=subprocess.CompletedProcess([], 255, "", "permission denied")):
        with pytest.raises(CollectionError, match="permission denied"):
            collect(ssh_host="lg", output=output, state=state)
    assert not output.exists() and not state.exists()


def test_remote_reader_executes_same_code_without_shell_interpolation(tmp_path):
    source = tmp_path / "audit ' $(false).log"
    source.write_bytes(b"record\n")

    real_runner = subprocess.run

    def transport(command, *, input, **kwargs):
        assert command[-2:] == ["lg", "python3 -"]
        assert str(source) not in command
        return real_runner([sys.executable, "-"], input=input, capture_output=True, text=True)

    output, state = tmp_path / "out.audit", tmp_path / "state.json"
    with patch("linuxguard.collector.subprocess.run", side_effect=transport):
        result = collect(ssh_host="lg", log_path=str(source), output=output, state=state)
    assert result.bytes_written == len(b"record\n")
    assert output.read_bytes() == b"record\n"


def test_cli_local_replay(capture):
    source, output, state = capture
    code = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "linuxguard", "collect", "--config", str(code / "config/linuxguard.yaml"),
         "--file", str(source), "--output", str(output), "--state", str(state)],
        cwd=source.parent, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == source.read_bytes()
