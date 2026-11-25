#!/usr/bin/env python3
"""Render the report's result figures from the evaluation and sweep JSON (matplotlib).

Reads the Git-ignored experiment outputs and writes tracked PNG+SVG to docs/figures/, so the
figures are reproducible from committed data (the numbers, not the raw captures). Usage:

    python eval/make_figures.py --eval-json <evaluation.json> --sweep-json <sweep.json> --out docs/figures
"""

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BLUE, ORANGE = "#1d4ed8", "#b45309"


def _save(fig, out, name):
    out.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "svg"):
        fig.savefig(out / f"{name}.{ext}", bbox_inches="tight", dpi=140)
    plt.close(fig)


def metrics_bar(a, b, out):
    labels = ["Precision", "Recall", "False-positive rate"]
    av = [a["precision"], a["recall"], a["false_positive_rate"]]
    bv = [b["precision"], b["recall"], b["false_positive_rate"]]
    x = range(len(labels)); w = 0.38
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar([i - w / 2 for i in x], av, w, label="A — rules only", color=BLUE)
    ax.bar([i + w / 2 for i in x], bv, w, label="B — rules + ML", color=ORANGE)
    for i, (va, vb) in enumerate(zip(av, bv)):
        ax.text(i - w / 2, va + 0.01, f"{va:.2f}", ha="center", fontsize=9)
        ax.text(i + w / 2, vb + 0.01, f"{vb:.2f}", ha="center", fontsize=9)
    ax.set_xticks(list(x)); ax.set_xticklabels(labels); ax.set_ylim(0, 1.08)
    ax.set_title("A (rules) vs B (rules + ML) — 210 scenario runs"); ax.legend()
    _save(fig, out, "metrics_ab")


def per_scenario(per, out):
    per = sorted(per, key=lambda r: (r["label"] != "malicious", r["scenario_id"]))
    names = [r["scenario_id"] for r in per]
    a = [r["A_caught"] / r["runs"] for r in per]
    b = [r["B_caught"] / r["runs"] for r in per]
    y = range(len(per)); h = 0.38
    fig, ax = plt.subplots(figsize=(8, 9))
    ax.barh([i + h / 2 for i in y], a, h, label="A — rules", color=BLUE)
    ax.barh([i - h / 2 for i in y], b, h, label="B — rules + ML", color=ORANGE)
    ax.set_yticks(list(y)); ax.set_yticklabels(names, fontsize=9); ax.invert_yaxis()
    ax.set_xlim(0, 1.05); ax.set_xlabel("fraction of 10 runs detected")
    ax.set_title("Per-scenario detection rate"); ax.legend(loc="lower right")
    _save(fig, out, "per_scenario")


def sweep_curve(rows, out):
    pct = [r["percentile"] for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(pct, [r["precision"] for r in rows], "o-", color=BLUE, label="Precision")
    ax.plot(pct, [r["recall"] for r in rows], "s-", color=ORANGE, label="Recall")
    ax.plot(pct, [r["false_positive_rate"] for r in rows], "^--", color="#64748b", label="FPR")
    ax.set_xlabel("ML alert threshold (baseline score percentile)"); ax.set_ylim(0, 1.05)
    ax.set_title("ML threshold sweep (configuration B)"); ax.legend(); ax.grid(alpha=0.3)
    _save(fig, out, "threshold_sweep")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--eval-json", required=True)
    p.add_argument("--sweep-json", required=True)
    p.add_argument("--out", default="../docs/figures")
    a = p.parse_args(argv)
    ev = json.load(open(a.eval_json)); sweep = json.load(open(a.sweep_json))
    out = Path(a.out)
    metrics_bar(ev["A"], ev["B"], out)
    per_scenario(ev["per_scenario"], out)
    sweep_curve(sweep, out)
    print(f"wrote figures to {out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
