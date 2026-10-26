# Scenarios (Phase 9)

`run.py` generates labelled benign and malicious audit telemetry for evaluating the
detector. It runs **only** as root on the `linuxguard-target` VM. Every action is
inert, reversible and confined to the VM on loopback; each scenario has a cleanup and
a clean-verify step, and is undone before the next. Labels come from the catalogue in
`run.py`, never from detector output.

```bash
python3 scenarios/run.py --list            # catalogue only; no root, no changes
sudo python3 scenarios/run.py --repeats 1  # one development pass (on the VM)
```

Outputs land under `/home/bonzo/linuxguard-scenarios/<run_id>/` on the VM:
`labels.csv` (`scenario_id, run_id, repetition, label, category, start_ts, end_ts`,
UTC) and `run.json` (seed, scenario ids, before/after `auditctl -s`). Copy them to
`code/data/scenarios/<run_id>/` on the host (Git-ignored) to join alerts to labels.

Repeated-failed-authentication scenarios (rules R04/R05) are deferred: this VM has no
user-creation tool (`useradd`/`adduser`) and no `sshpass`, so password failures cannot
be driven headlessly. Those rules are covered by synthetic unit tests and by the real
mistyped logins already present in the setup capture.

Keep the baseline training data and the test data separate, and run only inside the
designated VM on the libvirt `default` network. Restore a clean snapshot or rely on
each scenario's cleanup between runs.
