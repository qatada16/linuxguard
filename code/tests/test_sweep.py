"""Integration test for the ML threshold sweep (synthetic baseline/test/labels)."""

import csv
import importlib.util
import io
from pathlib import Path

from linuxguard import ml
from linuxguard.parser import parse_lines
from linuxguard.storage import EvidenceStore

SPEC = importlib.util.spec_from_file_location("sweep", Path(__file__).resolve().parents[1] / "eval" / "sweep.py")
sweep_mod = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(sweep_mod)

TOOLS = ["/usr/bin/ls", "/usr/bin/cat", "/usr/bin/grep", "/usr/bin/git", "/usr/bin/vim", "/usr/bin/tar"]


def calm(n, base=1700000000):
    import random
    lines, serial = [], 0
    for w in range(n):
        rng = random.Random(w); t = base + w * 60
        for i in range(rng.randint(2, 7)):
            serial += 1
            lines.append(f'type=SYSCALL msg=audit({t + i}.000:{serial}): uid=1000 auid=1000 '
                         f'success=yes exe="{rng.choice(TOOLS)}" syscall=59 key="lg_exec"\n')
    return lines, serial, base + n * 60


def _store(path, lines):
    s = EvidenceStore(path)
    s.insert_events(parse_lines(io.StringIO("".join(lines)), host="t").events)
    return s


def test_sweep_shape_and_monotonic_alerts(tmp_path):
    lines, serial, at = calm(40)
    base = _store(tmp_path / "b.db", lines)
    bundle = ml.train(base, window_seconds=60, n_estimators=120, random_state=42, threshold_percentile=1.0)
    ml.save(bundle, tmp_path / "m.joblib")
    burst = list(lines)
    for i in range(18):
        serial += 1
        burst.append(f'type=SYSCALL msg=audit({at + i}.000:{serial}): uid=1000 auid=1000 '
                     f'success=yes exe="/opt/x{i}" syscall=59 key="lg_exec"\n')
    test = _store(tmp_path / "t.db", burst)
    ml.score(test, bundle, settled=True)  # populate some alerts so the db has rows
    test.connection.close()
    from datetime import datetime, timezone
    win = datetime.fromtimestamp(at, timezone.utc).isoformat().replace("+00:00", "Z")
    labels = tmp_path / "labels.csv"
    with labels.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scenario_id", "repetition", "label", "start_ts", "end_ts"])
        w.writeheader()
        w.writerow({"scenario_id": "M1", "repetition": "1", "label": "malicious",
                    "start_ts": win, "end_ts": win})
    rows = sweep_mod.sweep(tmp_path / "b.db", tmp_path / "t.db", labels, tmp_path / "m.joblib")
    assert len(rows) == len(sweep_mod.PERCENTILES)
    alerts = [r["ml_alerts"] for r in rows]
    assert alerts == sorted(alerts)  # looser percentile -> at least as many ML alerts
    assert all(r["precision"] is None or 0 <= r["precision"] <= 1 for r in rows)
