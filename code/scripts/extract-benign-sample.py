#!/usr/bin/env python3
"""Extract whole audit groups from a completed workload's interval; retain the source."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path

from linuxguard.parser import parse_lines
from linuxguard.storage import utc_timestamp


def extract_sample(capture, manifest_file, output):
    capture, manifest_file, output = (Path(path).resolve() for path in (capture, manifest_file, output))
    metadata_file = output.with_suffix(".metadata.json")
    if len({capture, manifest_file, output, metadata_file}) != 4:
        raise ValueError("capture, manifest, sample, and metadata must be different files")
    if output.exists() or metadata_file.exists():
        raise ValueError("sample or metadata already exists; preserve it and choose a new output")
    manifest_bytes = manifest_file.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get("kind") != "scripted-benign-development" or manifest.get("status") != "completed":
        raise ValueError("a completed scripted benign workload manifest is required")
    start, end = (utc_timestamp(manifest[name]) for name in ("start_ts", "end_ts"))
    if end <= start:
        raise ValueError("workload end must be after start")
    source = capture.read_bytes()
    result = parse_lines(io.StringIO(source.decode("utf-8", errors="surrogateescape")), host=manifest["host"])
    if result.malformed_lines:
        raise ValueError("malformed source records; sample was not written")
    events = [event for event in result.events if start <= utc_timestamp(event["ts"]) < end]
    if not events:
        raise ValueError("no audit events in the workload interval")
    raw = "".join(event["raw"] for event in events).encode("utf-8", errors="surrogateescape")
    metadata = {"kind": manifest["kind"], "review_status": "pending",
                "audit_loss_verification": "pending interactive auditctl status check",
                "host": manifest["host"], "start_ts": start, "end_ts": end,
                "capture": str(capture), "capture_sha256": hashlib.sha256(source).hexdigest(),
                "manifest": str(manifest_file), "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "output": str(output), "sha256": hashlib.sha256(raw).hexdigest(),
                "events": len(events), "records": sum(event["raw"].count("\n") for event in events),
                "note": "Whole groups selected by event timestamp in [start, end); source retained. "
                        "Sample is regrouped by event. Settled groups and background activity need review. "
                        "This is not an ML training baseline."}
    output.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as stream:
        stream.write(raw)
    with os.fdopen(os.open(metadata_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as stream:
        json.dump(metadata, stream, indent=2)
        stream.write("\n")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(extract_sample(args.capture, args.manifest, args.output), indent=2))
