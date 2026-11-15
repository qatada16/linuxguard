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


def test_compare_shows_ml_improving_recall():
    alerts = [alert("rule", "2026-11-27T22:00:10.050000Z", "R03"),      # both A and B
              alert("ml", "2026-11-27T22:00:30.100000Z")]               # only B (MAL-C)
    a, b, per = ev.compare(LABELS, alerts)
    assert a["recall"] == 0.5 and b["recall"] == 1.0
    mal_c = next(r for r in per if r["scenario_id"] == "MAL-C")
    assert mal_c["A"] == [] and mal_c["B"] == ["ml"]


def test_repetitions_are_scored_per_run():
    # Repeated runs of the same scenario_id must be counted independently, not collapsed.
    labels = [
        label("M1", "malicious", "2026-11-27T22:00:10.000000Z", "2026-11-27T22:00:10.200000Z"),
        label("M1", "malicious", "2026-11-27T22:00:20.000000Z", "2026-11-27T22:00:20.200000Z"),
        label("B1", "benign",    "2026-11-27T22:00:30.000000Z", "2026-11-27T22:00:30.200000Z"),
        label("B1", "benign",    "2026-11-27T22:00:40.000000Z", "2026-11-27T22:00:40.200000Z"),
    ]
    for i, row in enumerate(labels):  # give each row a repetition so run keys are unique
        row["repetition"] = str(i % 2 + 1)
    alerts = [alert("rule", "2026-11-27T22:00:10.050000Z", "R03")]  # only M1 rep 1 caught
    m = ev.metrics(labels, alerts)
    assert m["tp"] == 1 and m["fn"] == 1 and m["fp"] == 0 and m["n_malicious"] == 2 and m["n_benign"] == 2
    a, b, per = ev.compare(labels, alerts)
    m1 = next(r for r in per if r["scenario_id"] == "M1")
    assert m1["runs"] == 2 and m1["A_caught"] == 1
