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










