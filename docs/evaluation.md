# Evaluation: Rule-only vs Rule + Machine Learning Detection

This document describes how LinuxGuard compares **Baseline A** (rule-based detection only) with **Baseline B**
(rule-based detection combined with anomaly detection) and discusses the results. The full generated tables are
in [`reports/evaluation/evaluation_report.md`](../reports/evaluation/evaluation_report.md) and the raw numbers in
[`reports/evaluation/evaluation_results.json`](../reports/evaluation/evaluation_results.json).

## Method

### Data

Each run uses two independently generated datasets in the exact raw formats written by `auditd` (`audit.log`) and
`rsyslog` (`auth.log`):

* **Baseline (training):** three days of benign activity on a simulated Ubuntu server with four interactive users
  (two developers, an analyst and an administrator), scheduled jobs, a web service and periodic benign but unusual
  operations (package upgrades, backups, large builds, account creation, password typos, troubleshooting).
  About 2,800 activity windows per seed.
* **Test:** one further day of the same benign activity with two instances of each of 24 attack scenarios and two
  instances of each of six benign-unusual scenarios inserted at random times. About 4,400 parsed events and
  94 labelled cases per seed.

The generator is deterministic per seed; five seeds (1 to 5) were evaluated and results are reported as mean ±
standard deviation. Attack scenarios use attacker addresses from documentation ranges, and 20 % of benign logins
come from roaming addresses so that "new address" is not a trivial signal. Benign users also download packages from
changing CDN addresses.

### Scenarios

| Covered by a rule (17) | Not covered by any rule (7) | Benign but unusual (6) |
| --- | --- | --- |
| SSH brute force, password spraying, brute force followed by login, `/etc/shadow` access, sudoers modification, backdoor account, execution from `/tmp`, reverse shell, `curl \| bash`, web shell, cron persistence, SSH key persistence, kernel module load, audit tampering, log tampering, setuid backdoor, discovery burst | data exfiltration in chunks, cryptominer, internal network scan, mass file renaming (ransomware-like), privileged activity at night, decoded implant beaconing, credential hunting | system update, nightly backup, parallel build, approved account creation, password typos, administrator troubleshooting |

Routine work sessions (about 10 per seed) and hourly scheduled-job periods (24 per seed) are additional benign
cases.

### Ground truth and metrics

Every scenario instance is a **case** labelled when it is generated, independently of any detector: a time interval
plus selectors (session ID, source address or user). An event belongs to a case when it falls inside the interval and
matches a selector. An alert *detects* a case when one of its evidence events belongs to the case.

| Metric | Definition |
| --- | --- |
| Recall | detected malicious cases / malicious cases |
| False-positive rate | benign cases touched by a false alert / benign cases. A false alert is one whose evidence contains no malicious event; benign context included in a correct alert does not count. |
| Case precision | detected malicious cases / (detected malicious cases + falsely flagged benign cases) |
| Alert precision | alerts whose evidence contains malicious activity / all alerts |
| Detection delay | time from the first action of a case to the event (rules) or window end (anomalies) that raised the first alert |
| Resources | wall-clock and CPU time, time per event, throughput, peak traced Python memory and SQLite database size |

All configurations process exactly the same parsed events.

## Results (5 seeds)

| Configuration | Recall | False-positive rate | Case precision | F1 | Alert precision | Mean delay (s) | Time per event (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **A: rules only** | 0.708 ± 0.000 | 0.105 ± 0.010 | 0.876 ± 0.010 | 0.783 ± 0.004 | 0.892 ± 0.009 | 10.5 ± 0.6 | 0.084 |
| **B: rules + anomaly detector** | 0.858 ± 0.023 | 0.193 ± 0.019 | 0.824 ± 0.017 | 0.841 ± 0.019 | 0.841 ± 0.030 | 17.7 ± 2.2 | 2.965 |
| B without range guard | 0.775 ± 0.034 | 0.193 ± 0.019 | 0.808 ± 0.021 | 0.791 ± 0.028 | 0.817 ± 0.039 | 15.1 ± 3.3 | 3.271 |
| B with threshold quantile 0.990 | 0.875 ± 0.000 | 0.250 ± 0.018 | 0.787 ± 0.013 | 0.828 ± 0.007 | 0.809 ± 0.027 | 17.5 ± 0.6 | 3.258 |
| B with threshold quantile 0.999 | 0.808 ± 0.017 | 0.149 ± 0.011 | 0.851 ± 0.007 | 0.829 ± 0.009 | 0.877 ± 0.007 | 14.4 ± 0.9 | 3.195 |
| Anomaly detector only | 0.212 ± 0.031 | 0.092 ± 0.018 | 0.707 ± 0.060 | 0.326 ± 0.042 | 0.715 ± 0.091 | 49.2 ± 6.8 | 3.191 |
| Isolation Forest only, no guard | 0.075 ± 0.048 | 0.092 ± 0.018 | 0.429 ± 0.198 | 0.127 ± 0.078 | 0.462 ± 0.238 | 57.6 ± 17.5 | 3.139 |

Parsing ran at about 3,300 events per second and baseline training took about 2 seconds per seed on a laptop CPU.

### Detection of scenarios not covered by rules (detected / 10 cases)

| Scenario | A: rules only | B: rules + anomaly detector |
| --- | ---: | ---: |
| Data exfiltration | 0 | 10 |
| Internal network scan | 0 | 10 |
| Mass file encryption | 0 | 10 |
| Cryptominer | 0 | 6 |
| Off-hours privileged activity | 0 | 0 |
| Dropped implant beacon | 0 | 0 |
| Credential hunting | 0 | 0 |

All 17 rule-covered scenarios were detected in every run by both configurations.

### Falsely flagged benign cases (flagged / total)

| Benign scenario | A: rules only | B: rules + anomaly detector |
| --- | ---: | ---: |
| Administrator account creation | 10/10 | 10/10 |
| Administrator troubleshooting | 10/10 | 10/10 |
| Password typos | 2/10 | 2/10 |
| System update | 0/10 | 9/10 |
| Routine work sessions | 2/48 | 13/48 |
| Backup, builds, scheduled jobs | 0/140 | 0/140 |

## Discussion

* **Rules are precise but blind outside their definitions.** Baseline A detected every rule-covered attack with an
  alert precision of 0.89 and a ten-second mean delay, but recall stops at 0.71 because seven attack types have no
  matching rule. Its false positives are activities that are legitimately suspicious out of context (an approved new
  account, an administrator running many discovery commands, three mistyped passwords).
* **Anomaly detection adds coverage at a cost.** Baseline B raised recall from 0.71 to 0.86 and F1 from 0.78 to
  0.84 by detecting exfiltration, scanning, mass renaming and most cryptominer runs. The false-positive rate rose
  from 0.11 to 0.19, mainly through package upgrades and a minority of routine work sessions, and alert precision fell
  from 0.89 to 0.84. ML did not outperform rules in every respect, as the proposal anticipated.
* **Isolation Forest alone is weak on this problem.** Without the range guard the forest found only 7.5 % of
  attacks on its own. Benign maintenance in the baseline produces the highest training scores, and values far beyond
  the training range in a single feature are not isolated faster than those maintenance windows. The range guard
  raised standalone anomaly recall to 21 % and hybrid recall from 0.78 to 0.86 without additional false positives.
* **Threshold choice is a precision/recall trade-off.** Raising the quantile from 0.990 to 0.999 lowered the false
  positive rate from 0.25 to 0.15 and recall from 0.88 to 0.81.
* **Slow and low-volume attacks remain undetected.** Credential hunting, implant beacons every 20 to 40 seconds and
  privileged commands at night produce windows that resemble normal activity at a 60-second granularity.
* **Latency and cost.** Rule alerts are raised on the triggering event. Anomaly alerts are only possible when a
  60-second window closes, so the mean delay increases by about seven seconds. Scoring windows with the forest
  makes processing roughly 35 times more expensive per event, but at about 340 events per second it remains well
  above the event rate of a single server under normal use. Memory usage stayed below 5 MB of traced allocations, and
  storing alerts adds only about 3 % to the database size.

## Threats to validity

* The data is simulated. The generator writes realistic raw records that go through the same parser as live data,
  but the behaviour of simulated users is simpler than real behaviour and the attack scenarios are known to the
  authors. Results on real hosts are expected to show more false positives for the anomaly detector.
* Rules were written before the evaluation scenarios, but by the same team; rule recall on rule-covered scenarios
  is therefore optimistic.
* Each benign user session is a single case, so a false positive rate expressed per case depends on how activity is
  divided into cases.
* The WSL environment used during development cannot run the kernel audit subsystem (it requires the initial PID
  namespace). Live `auth.log` collection was validated on WSL, and full auditd collection requires the VM described
  in [deployment.md](deployment.md) together with the lab scripts.

## Reproduce

```bash
linuxguard evaluate --seeds 1 2 3 4 5 --output reports/evaluation
```

The run takes about eight minutes on a laptop.
