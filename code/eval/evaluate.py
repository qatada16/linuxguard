#!/usr/bin/env python3
"""Compare rules-only (A) against rules+ML (B) on one labelled scenario capture (Phase 10 core).

The unit of evaluation is a single scenario *run* (one row of labels.csv). With repeated
runs there are many rows per scenario_id, so rows are keyed by scenario_id + repetition.
Each alert is matched to the run that was executing when it fired (nearest scenario start,
because audit timestamps land a few ms before the runner's recorded start_ts and runs are
seconds apart). Labels come from the runner, never from detector output. A uses only
source='rule' alerts; B uses rule and ML together, measured on the same recorded log.
"""

import argparse
import csv
import json
import sqlite3
from datetime import datetime, timedelta
from statistics import mean, median


def _t(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _run_key(row):
    rep = row.get("repetition")
    return f"{row['scenario_id']}#{rep}" if rep else row["scenario_id"]


def attribute(labels, alerts, *, edge_grace=5.0):
    """Map each alert to the nearest scenario-run start; return run_key -> list of alerts."""
    starts = sorted((_t(r["start_ts"]), _run_key(r)) for r in labels)
    hits = {_run_key(r): [] for r in labels}
    lo = starts[0][0] - timedelta(seconds=edge_grace)
    hi = max(_t(r["end_ts"]) for r in labels) + timedelta(seconds=edge_grace)
    for alert in alerts:
        when = _t(alert["ts"])
        if lo <= when <= hi:
            hits[min(starts, key=lambda s: abs((s[0] - when).total_seconds()))[1]].append(alert)
    return hits


def metrics(labels, alerts):
    """Precision, recall, false-positive rate and detection latency over scenario runs."""
    hits = attribute(labels, alerts)
    tp = fn = fp = 0
    latencies = []
    for row in labels:
        fired = hits[_run_key(row)]
        if row["label"] == "malicious":
            if fired:
                tp += 1
                latencies.append(max(0.0, (min(_t(a["ts"]) for a in fired) - _t(row["start_ts"])).total_seconds()))
            else:
                fn += 1
        elif fired:
            fp += 1
    n_mal = sum(1 for r in labels if r["label"] == "malicious")
    n_ben = len(labels) - n_mal
    return {
        "tp": tp, "fp": fp, "fn": fn, "n_malicious": n_mal, "n_benign": n_ben,
        "precision": tp / (tp + fp) if (tp + fp) else None,
        "recall": tp / (tp + fn) if (tp + fn) else None,
        "false_positive_rate": fp / n_ben if n_ben else None,
        "latency_mean": mean(latencies) if latencies else None,
        "latency_median": median(latencies) if latencies else None,
        "latency_max": max(latencies) if latencies else None,
    }


def compare(labels, alerts):
    """A = rule alerts only; B = rule + ML. Returns (metrics_A, metrics_B, per_scenario)."""
    rule_alerts = [a for a in alerts if a["source"] == "rule"]
    a, b = metrics(labels, rule_alerts), metrics(labels, alerts)
    hits_a, hits_b = attribute(labels, rule_alerts), attribute(labels, alerts)
    agg = {}
    for row in sorted(labels, key=lambda r: (r["scenario_id"], r.get("repetition", ""))):
        sid = row["scenario_id"]
        e = agg.setdefault(sid, {"scenario_id": sid, "label": row["label"], "runs": 0,
                                 "A_caught": 0, "B_caught": 0, "_a": set(), "_b": set()})
        e["runs"] += 1
        fa, fb = hits_a[_run_key(row)], hits_b[_run_key(row)]
        if fa:
            e["A_caught"] += 1
            e["_a"].update(x["rule_id"] or x["source"] for x in fa)
        if fb:
            e["B_caught"] += 1
            e["_b"].update(x["rule_id"] or x["source"] for x in fb)
    per = [{"scenario_id": e["scenario_id"], "label": e["label"], "runs": e["runs"],
            "A_caught": e["A_caught"], "B_caught": e["B_caught"],
            "A": sorted(e["_a"]), "B": sorted(e["_b"])} for e in agg.values()]
    return a, b, per


def _load(test_db, labels_csv):
    labels = list(csv.DictReader(open(labels_csv)))
    con = sqlite3.connect(test_db); con.row_factory = sqlite3.Row
    alerts = [dict(r) for r in con.execute("SELECT source, rule_id, ts FROM alerts")]
    return labels, alerts


def _print(a, b, per):
    def line(tag, m):
        f = lambda v, p=".2f": "n/a" if v is None else format(v, p)
        print(f"  {tag}: P={f(m['precision'])} R={f(m['recall'])} FPR={f(m['false_positive_rate'])} "
              f"TP={m['tp']} FP={m['fp']} FN={m['fn']} "
              f"latency(med/max)={f(m['latency_median'],'.1f')}/{f(m['latency_max'],'.1f')}s "
              f"(malicious runs={m['n_malicious']}, benign runs={m['n_benign']})")
    print("Configuration metrics (per scenario run):")
    line("A rules    ", a)
    line("B rules+ML ", b)
    print("\nPer scenario (runs caught, rules/sources fired):")
    print(f"  {'SCENARIO':16} {'LABEL':9} {'A':>7} {'B':>7}  rules")
    for row in per:
        caught = f"{row['A_caught']}/{row['runs']}", f"{row['B_caught']}/{row['runs']}"
        print(f"  {row['scenario_id']:16} {row['label']:9} {caught[0]:>7} {caught[1]:>7}  "
              f"A={','.join(row['A']) or '-'} B={','.join(row['B']) or '-'}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate rules-only vs rules+ML on a labelled capture")
    parser.add_argument("--test-db", required=True, help="SQLite database with rule and ML alerts")
    parser.add_argument("--labels", required=True, help="scenario runner labels.csv")
    parser.add_argument("--json", action="store_true", help="Emit metrics as JSON")
    args = parser.parse_args(argv)
    labels, alerts = _load(args.test_db, args.labels)
    a, b, per = compare(labels, alerts)
    if args.json:
        print(json.dumps({"A": a, "B": b, "per_scenario": per}, indent=2))
    else:
        _print(a, b, per)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
