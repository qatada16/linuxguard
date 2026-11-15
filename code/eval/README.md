# Evaluation (Phase 10)

`evaluate.py` compares **A = rules only** against **B = rules + ML** on one labelled
scenario capture (the test set produced by `scenarios/run.py`). It matches each alert to
the nearest scenario start (audit timestamps land a few milliseconds before the runner's
recorded `start_ts`, and scenarios are seconds apart, so exact-window matching misassigns),
then reports precision, recall, false-positive rate and detection latency per configuration,
plus a per-scenario table of which rules/sources fired.

```bash
# the test database holds rule and ML alerts (pipeline --detect --model); A filters source='rule', B is all
python3 eval/evaluate.py --test-db data/experiments/test.db --labels data/scenarios/<run_id>/labels.csv
python3 eval/evaluate.py --test-db ... --labels ... --json   # machine-readable metrics
```

Labels come from the scenario runner, never from detector output. Keep the baseline
(training) and the scenario (test) captures in separate databases. Still pending for a full
Phase 10: resource-use sampling (CPU/memory/db size on the VM), an ML threshold sweep, and
the written results chapter with charts. Store generated results under `results/`
(Git-ignored).

## Results (2026-11-28, run 20261128T072137-d905c5, provisional model)

Per scenario run (210 runs: 110 malicious, 100 benign):

| Config | Precision | Recall | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| A rules | 1.00 | 0.80 | 0.00 | 88 | 0 | 22 |
| B rules+ML | 0.89 | 0.82 | 0.11 | 90 | 11 | 20 |

Rules caught every rule-targeted scenario with zero false positives and missed the two
ML-only scenarios. ML recovered only 2 of those runs while adding 11 benign false positives.
On this provisional, scripted baseline **ML did not clearly help**; collect a richer
normal-only baseline (Phase 7.2) before final conclusions. See the handoff section 12.
