"""Incremental audit collection with durable local evidence and explicit gap errors."""

import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from linuxguard import reader


class CollectionError(RuntimeError):
    """Collection cannot proceed without risking an evidence gap."""


@dataclass(frozen=True)
class CollectionResult:
    bytes_written: int
    output: Path
    state: Path
    rotated_files: list[str]


def _atomic_json(path, value):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix="." + path.name, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def collect(*, output: str | Path, state: str | Path, file: str | Path | None = None,
            ssh_host: str | None = None, log_path: str = "/var/log/audit/audit.log") -> CollectionResult:
    """Append complete raw lines, then atomically commit the source cursor.

    Exactly one of file/ssh_host is required. SSH uses the caller's SSH agent and
    known-host configuration. A cursor is bound to one source and output file.
    """
    # shortcut: use one collector per state/output pair; add an advisory lock before running concurrent workers.
    output, state = Path(output).resolve(), Path(state).resolve()
    if (file is None) == (ssh_host is None):
        raise ValueError("choose exactly one local file or SSH host")
    source_path = str(Path(file).resolve()) if file is not None else log_path
    if output == state or (file is not None and Path(source_path) in (output, state)):
        raise ValueError("source, output, and state must be different files")
    if ssh_host is not None and (not ssh_host or ssh_host.startswith("-") or any(c.isspace() for c in ssh_host)):
        raise ValueError("SSH host must be a hostname, alias, or user@host without whitespace")
    source = {"mode": "file" if file is not None else "ssh", "host": ssh_host, "path": source_path}
    previous = None
    if state.exists():
        try:
            previous = json.loads(state.read_text(encoding="utf-8"))
            if previous["version"] != 1 or previous["source"] != source or previous["output"] != str(output):
                raise ValueError("state belongs to another source or output")
            cursor = previous["cursor"]
            if not all(type(cursor[key]) is int and cursor[key] >= 0 for key in ("device", "inode", "offset")):
                raise ValueError("invalid cursor numbers")
            if not isinstance(cursor["anchor"], str) or not re.fullmatch(r"[0-9a-f]{64}", cursor["anchor"]):
                raise ValueError("invalid cursor fingerprint")
            if type(previous["output_size"]) is not int or previous["output_size"] < 0:
                raise ValueError("invalid capture size")
            if not output.exists() or output.stat().st_size != previous["output_size"]:
                raise ValueError("capture size differs from committed state; preserve it and recover using a new output/state pair")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise CollectionError(f"Cannot use collection state {state}: {exc}") from exc
    elif output.exists() and output.stat().st_size:
        raise CollectionError("Output already contains data without a cursor; use a new output/state pair")

    request = {"path": source_path, "cursor": previous["cursor"] if previous else None}
    try:
        if file is not None:
            response = reader.read_snapshot(request)
        else:
            # The remote shell sees only a fixed command. Request data is Python
            # string-literal JSON on stdin, never interpolated into shell syntax.
            script = Path(reader.__file__).read_text(encoding="utf-8")
            script += "\nimport json\ntry:\n    print(json.dumps(read_snapshot(json.loads(" + repr(json.dumps(request)) + "))))\n"
            script += "except (OSError, ValueError) as exc:\n    print(json.dumps({'error': str(exc)}))\n"
            process = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5",
                 ssh_host, "python3 -"], input=script, capture_output=True, text=True, timeout=30,
            )
            if process.returncode:
                raise CollectionError(f"SSH failed: {process.stderr.strip()}")
            response = json.loads(process.stdout)
        if "error" in response:
            raise CollectionError(response["error"])
        data = base64.b64decode(response["data"], validate=True)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        raise CollectionError(str(exc)) from exc

    output.parent.mkdir(parents=True, exist_ok=True)
    state.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "ab") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    updated = {"version": 1, "source": source, "output": str(output),
               "output_size": output.stat().st_size, "cursor": response["cursor"],
               "reader_host": response["reader_host"]}
    _atomic_json(state, updated)
    return CollectionResult(len(data), output, state, response["rotated_files"])
