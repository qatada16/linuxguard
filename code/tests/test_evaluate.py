"""Checks for the A-vs-B evaluation matching and metrics (synthetic labels and alerts)."""

import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("evaluate", Path(__file__).resolve().parents[1] / "eval" / "evaluate.py")
ev = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(ev)


def label(sid, lab, start, end):
    return {"scenario_id": sid, "label": lab, "start_ts": start, "end_ts": end}


LABELS = [
    label("MAL-A", "malicious", "2026-11-27T22:00:10.000000Z", "2026-11-27T22:00:10.200000Z"),
    label("BEN-B", "benign",    "2026-11-27T22:00:20.000000Z", "2026-11-27T22:00:20.200000Z"),
    label("MAL-C", "malicious", "2026-11-27T22:00:30.000000Z", "2026-11-27T22:00:30.200000Z"),  # only ML catches
]


def alert(source, ts, rule_id=None):
    return {"source": source, "rule_id": rule_id, "ts": ts}


def test_nearest_start_matching_tolerates_ms_skew():
    # Alert fires 3 ms BEFORE the recorded start_ts; must still attribute to MAL-A, not earlier.
    hits = ev.attribute(LABELS, [alert("rule", "2026-11-27T22:00:09.997000Z", "R03")])
    assert [a for a in hits["MAL-A"]] and not hits["BEN-B"] and not hits["MAL-C"]


def test_metrics_true_and_false_positives():
    alerts = [alert("rule", "2026-11-27T22:00:10.050000Z", "R03"),   # TP on MAL-A
              alert("rule", "2026-11-27T22:00:20.050000Z", "R01")]   # FP on BEN-B
    m = ev.metrics(LABELS, alerts)
    assert m["tp"] == 1 and m["fp"] == 1 and m["fn"] == 1
    assert m["precision"] == 0.5 and m["recall"] == 0.5
    assert abs(m["false_positive_rate"] - 1.0) < 1e-9  # one benign scenario, flagged
    assert m["latency_median"] is not None and m["latency_median"] >= 0




