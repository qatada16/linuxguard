#!/usr/bin/env python3
"""ML threshold sweep (proposal 7.6/10.6): precision/recall of B vs the alert threshold.

Calibrates the Isolation Forest alert cutoff at several percentiles of the *baseline* scores,
then for each cutoff forms the ML alert set over the test capture, combines it with the stored
rule alerts, and reports B's precision/recall/FPR against labels.csv. A (rules only) is fixed.
Reuses linuxguard.ml.window_scores and eval.evaluate for scoring and matching.
"""

import argparse
import csv
import importlib.util
import json
import sqlite3
from pathlib import Path

import numpy as np

from linuxguard import ml
from linuxguard.storage import EvidenceStore

_EVAL = importlib.util.spec_from_file_location("evaluate", Path(__file__).resolve().parent / "evaluate.py")
evaluate = importlib.util.module_from_spec(_EVAL); _EVAL.loader.exec_module(evaluate)

PERCENTILES = (0.5, 1.0, 2.0, 5.0, 10.0)


def sweep(baseline_db, test_db, labels_csv, model_path, percentiles=PERCENTILES):
    bundle = ml.load(model_path)
    with EvidenceStore(baseline_db) as store:
        _, _, baseline_scores = ml.window_scores(store.events(), bundle)
    with EvidenceStore(test_db) as store:
        rows, _, test_scores = ml.window_scores(store.events(), bundle)
    labels = list(csv.DictReader(open(labels_csv)))
    con = sqlite3.connect(test_db)
    rule_alerts = [{"source": "rule", "rule_id": r[0], "ts": r[1]}
                   for r in con.execute("SELECT rule_id, ts FROM alerts WHERE source='rule'")]
    out = []
    for pct in percentiles:
        threshold = float(np.percentile(baseline_scores, pct))
        ml_alerts = [{"source": "ml", "rule_id": None, "ts": row["window_end"]}
                     for row, s in zip(rows, test_scores) if s < threshold and row["event_ids"]]
        m = evaluate.metrics(labels, rule_alerts + ml_alerts)
        out.append({"percentile": pct, "threshold": round(threshold, 4), "ml_alerts": len(ml_alerts),
                    "precision": m["precision"], "recall": m["recall"],
                    "false_positive_rate": m["false_positive_rate"],
                    "tp": m["tp"], "fp": m["fp"], "fn": m["fn"]})
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline-db", required=True)
    p.add_argument("--test-db", required=True)
    p.add_argument("--labels", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    rows = sweep(a.baseline_db, a.test_db, a.labels, a.model)
    if a.json:
        print(json.dumps(rows, indent=2)); return 0
    f = lambda v: "n/a" if v is None else format(v, ".2f")
    print(f"{'pct':>5} {'threshold':>10} {'ml_alerts':>10} {'P':>6} {'R':>6} {'FPR':>6}  TP/FP/FN")
    for r in rows:
        print(f"{r['percentile']:>5} {r['threshold']:>10} {r['ml_alerts']:>10} "
              f"{f(r['precision']):>6} {f(r['recall']):>6} {f(r['false_positive_rate']):>6}  "
              f"{r['tp']}/{r['fp']}/{r['fn']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
