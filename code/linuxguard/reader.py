"""Standard-library audit reader, also sent to the VM through SSH's stdin."""

import base64
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import socket


def _anchor(stream, offset):
    start = max(0, offset - 256)
    stream.seek(start)
    data = stream.read(offset - start)
    if len(data) != offset - start:
        raise ValueError("Log changed while checking its cursor; retry without advancing")
    return hashlib.sha256(data).hexdigest()


def read_snapshot(request):
    """Read complete lines since a cursor, including retained numbered rotations."""
    path = Path(request["path"])
    previous = request.get("cursor")
    with ExitStack() as stack:
        handles = {}

        def opened(file):
            if file not in handles:
                stream = stack.enter_context(file.open("rb"))
                handles[file] = (stream, os.fstat(stream.fileno()))
            return handles[file]

        def matches(file, require_identity):
            stream, info = opened(file)
            identity_ok = (info.st_dev, info.st_ino) == (previous["device"], previous["inode"])
            return (
                (identity_ok or not require_identity)
                and info.st_size >= previous["offset"]
                and _anchor(stream, previous["offset"]) == previous["anchor"]
            )

        current, info = opened(path)
        segments = [(path, 0)]
        if previous:
            if matches(path, True):
                segments = [(path, previous["offset"])]
            else:
                rotations = {}
                prefix = path.name + "."
                for candidate in path.parent.iterdir():
                    suffix = candidate.name.removeprefix(prefix)
                    if candidate.name.startswith(prefix) and suffix.isdecimal() and int(suffix) > 0:
                        rotations[int(suffix)] = candidate
                found = None
                for identity_required in (True, False):
                    if not identity_required and previous["offset"] == 0:
                        continue
                    for number in sorted(rotations):
                        if matches(rotations[number], identity_required):
                            found = number
                            break
                    if found is not None:
                        break
                if found is None or any(n not in rotations for n in range(1, found + 1)):
                    raise ValueError("Rotation/truncation gap: the previous log or intervening archives are unavailable")
                segments = [(rotations[n], previous["offset"] if n == found else 0)
                            for n in range(found, 0, -1)] + [(path, 0)]

        chunks = []
        current_offset = 0
        for file, offset in segments:
            stream, snapshot = opened(file)
            stream.seek(offset)
            size = snapshot.st_size - offset
            data = stream.read(size)
            if len(data) != size:
                raise ValueError("Log changed while reading; retry without advancing the cursor")
            end = data.rfind(b"\n") + 1
            if file != path and end != len(data):
                raise ValueError("Rotated log ends with a partial record; review it before advancing")
            chunks.append(data[:end])
            if file == path:
                current_offset = offset + end
        return {
            "data": base64.b64encode(b"".join(chunks)).decode("ascii"),
            "cursor": {"device": info.st_dev, "inode": info.st_ino,
                       "offset": current_offset, "anchor": _anchor(current, current_offset)},
            "reader_host": socket.gethostname(),
            "rotated_files": [str(file) for file, _ in segments if file != path],
        }
