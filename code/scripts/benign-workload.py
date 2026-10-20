#!/usr/bin/env python3
"""Run a bounded, unprivileged development workload inside a new home directory."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import socket
import subprocess
import tempfile
import time


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_workload(parent, duration=900):
    if not 0 <= duration <= 7200:
        raise ValueError("duration must be between 0 and 7200 seconds")
    parent = Path(parent).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="benign-", dir=parent))
    (work / "notes.txt").write_text("LinuxGuard development notes\nReview project files\n", encoding="utf-8")
    (work / "example.py").write_text("def total(values):\n    return sum(values)\n\nassert total([1, 2, 3]) == 6\n", encoding="utf-8")
    tasks = [
        ("list-and-search", [["ls", "-la"], ["find", ".", "-maxdepth", "2", "-type", "f"],
                             ["grep", "-n", "development", "notes.txt"]]),
        ("copy-and-compare", [["cp", "notes.txt", "notes-copy.txt"], ["cmp", "notes.txt", "notes-copy.txt"]]),
        ("archive-and-list", [["tar", "-czf", "notes.tar.gz", "notes.txt", "example.py"],
                              ["tar", "-tzf", "notes.tar.gz"]]),
        ("text-tools", [["sort", "notes.txt"], ["wc", "-l", "notes.txt"], ["sha256sum", "notes.txt"]]),
        ("python-check", [["python3", "-m", "py_compile", "example.py"], ["python3", "example.py"]]),
        ("read-documents", [["cat", "notes.txt"], ["head", "-n", "2", "example.py"]]),
    ]
    manifest = {"kind": "scripted-benign-development", "host": socket.gethostname(),
                "directory": str(work), "start_ts": utc_now(), "end_ts": None,
                "requested_seconds": duration, "seed": 42, "status": "running", "steps": [],
                "limitations": ["Unprivileged scripted workload, not representative human use or an ML baseline",
                                "Background VM activity and audit-loss counters require separate review"]}

    def save():
        temporary = work / ".manifest.json"
        temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        temporary.replace(work / "manifest.json")

    save()
    print(json.dumps({"manifest": str(work / "manifest.json"), "start_ts": manifest["start_ts"]}), flush=True)
    deadline = time.monotonic() + duration
    rng = random.Random(42)
    try:
        while True:
            rng.shuffle(tasks)
            for name, commands in tasks:
                started = utc_now()
                with (work / "notes.txt").open("a", encoding="utf-8") as stream:
                    stream.write("Reviewed " + name + " at " + started + "\n")
                for command in commands:
                    result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=30)
                    manifest["steps"].append({"task": name, "argv": command, "start_ts": started,
                                              "end_ts": utc_now(), "returncode": result.returncode,
                                              "stdout": result.stdout, "stderr": result.stderr})
                    save()
                    result.check_returncode()
                print(json.dumps({"task": name, "at": utc_now()}), flush=True)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    manifest["status"] = "completed"
                    return manifest
                time.sleep(min(rng.uniform(15, 35), remaining))
    finally:
        manifest["end_ts"] = utc_now()
        if manifest["status"] == "running":
            manifest["status"] = "failed"
        save()
        print(json.dumps({"status": manifest["status"], "end_ts": manifest["end_ts"],
                          "manifest": str(work / "manifest.json")}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=900, help="Seconds, default 900 (15 minutes)")
    args = parser.parse_args()
    run_workload(Path.home() / "linuxguard-workloads", args.duration)
