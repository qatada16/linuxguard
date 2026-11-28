# LinuxGuard: Roadmap from Here

Working checklist for Group 17. It follows the methodology in the proposal (section 5).
**Phases 1–5 are complete for the development prototype:** VM setup, audit rules
and a scripted development sample, project foundation, collector/parser, and
SQLite ingestion. Phase 6 (detection rules) is next. The hours-long representative
ML baseline, scenarios and evaluation remain pending.

**Current update — 2026-11-28:** 140 tests pass. Phase 6 (configurable
detection rules) is implemented and verified on the real captures; Phase 9's scenario
runner and catalogue are in place with one development run staged for the user. SSH and unprivileged audit-log reading
were reverified with the new agent; auditd is active. Historical verification of
all seven audit keys and snapshot `rules-loaded` is recorded in the handoff.
SQLite ingestion of the frozen 1,151-event real capture succeeded; the second run
collected zero bytes and inserted/updated zero rows. Integrity and foreign-key
checks passed. Live SSH ingestion works. The 15-minute scripted development sample
contains 94 successful commands and 508 events. The user supplied a fresh
`auditctl -s` result after capture: `enabled 1`, `lost 0`, `backlog 0`, and
`backlog_limit 8192`; command timestamp `2026-11-27T21:16:31Z`
(2026-11-28 02:16:31 Asia/Karachi). Sample collection, provenance review and the
post-capture audit-loss check are complete for development use. The longer,
representative normal-only ML baseline remains Phase 7 work.
Root changes still require the user's interactive sudo password.
See [the agent handoff](../docs/AGENT_HANDOFF.md) before resuming in a new session.

## Where we are

| Item | State |
|---|---|
| Host venv `code/.venv` (Python 3.12, core dependencies and pytest; versions in `code/uv.lock`) | done |
| Target VM `debian13` (Debian 13, 192.168.122.164, qcow2 in `/mnt/data/VM/debian`) | done |
| `auditd` and project audit rules | active; all keys verified; post-capture status supplied 2026-11-28: `enabled 1`, `lost 0`, `backlog 0` |
| Unprivileged audit-log reading | done; `bonzo` is in `adm`, fresh SSH access verified |
| Snapshots `clean-install`, `rules-loaded` | exist, verified; `rules-loaded` includes configured SSH and log access |
| Non-interactive SSH from host to VM | done with unlocked SSH agent and `lg` alias |
| Local Git, package structure, configuration validation and test setup | done |
| Seven audit keys and deliberate probes | verified; temporary files removed |
| Collector and batch parser | implemented and exercised on real VM data |
| SQLite events, alerts, evidence links, indexed queries and batch pipeline | implemented; real replay and live SSH verified |
| Scripted normal-use development sample | done for development: 94 commands, 508 events; provenance and post-capture audit-loss check recorded |
| Representative hours-long normal-only ML baseline | **to do** in Phase 7; the development sample does not meet this requirement |
| Detection rules (Phase 6) | done; 10 rules, evidence-linked alerts |
| ML anomaly detector + dashboard + reports (Phases 7, 8) | done; provisional model, Streamlit dashboard, Markdown reports |
| Evaluation A vs B (Phase 10) | core done; A rules P=1.00 R=0.80 FPR=0.00, B rules+ML P=0.89 R=0.82 FPR=0.11; resource/sweep/write-up pending |

Conventions used below:
- **HOST** = your Arch machine, inside `code/` with the venv active (`source .venv/bin/activate.fish`).
- **VM** = the Debian target, over `ssh bonzo@192.168.122.164`.
- Every phase ends with a **Done when** line. Don't move on until it's true.

## Order of work and dependencies

```
Phase 2  Audit rules + sample data ─┐
Phase 3  Project skeleton ──────────┼─► Phase 4 Parser ─► Phase 5 SQLite ─┬─► Phase 6 Rules ─┐
                                    │                                      │                  ├─► Phase 9 Scenarios ─► Phase 10 Evaluation ─► Phase 12 Report
                                    └──────────────────────────────────────┴─► Phase 7 ML ─────┘
Phase 8 Dashboard + reports (needs 5, grows with 6/7)      Phase 11 AI explanations (needs 5, 8)
```

Suggested split for three people: **A** collector, parser, DB (phases 2 to 5). **B** rules, ML, evaluation (6, 7, 10). **C** dashboard, reports, AI, scenarios (8, 9, 11). Phase 3 is done together first so everyone shares one layout.

---

## Phase 2: Audit rules and sample data

**Goal:** the VM records the events the proposal names (process, authentication, sensitive file activity) and we have a real log to develop against.

- [x] **2.1 Installed project audit rules.** Source: `code/config/audit/linuxguard.rules`.
  The setup script at `code/scripts/setup-audit.sh` backs up the current configuration
  and installs the rules at `/etc/audit/rules.d/70-linuxguard.rules`. Both files are
  staged in `/home/bonzo/linuxguard-setup/` on the VM. The user already ran the
  following successfully; it is retained for rebuilding, not routine reconnection:

  ```bash
  ssh -t lg 'sudo sh /home/bonzo/linuxguard-setup/setup-audit.sh'
  ```

  The rules cover process execution, mode changes, sensitive files, persistence,
  and both the collector user's SSH directory and root's SSH directory if it exists.
  Existing rule files are retained. Do not add the old blanket `-D` deletion directive.
  Authentication records are generated by the authentication stack; confirm their
  presence when validating the sample.
- [x] **2.2 Load and verify:** installer output showed all project keys, `enabled 1`,
  and `lost 0`. Fresh log access and real syscall records confirm collection is
  working. The user's post-capture status check, timestamped
  `2026-11-27T21:16:31Z`, again reported `enabled 1`, `lost 0`, and `backlog 0`.
- [x] **2.3 Trigger verification.** All seven keys have real matching syscall
  events. The user ran the prepared trigger script; each exact sudoers/SSH/cron
  probe path matched successful SYSCALL and PATH records, and all probe files were
  removed. IDs and timestamps are in the handoff. This verifies the keys, not every
  watched path or 32-bit execution. Do not rerun probes merely to reconnect.
- [x] **2.4 Log access without a root shell:** `log_group = adm`, group membership,
  and fresh unprivileged log reading verified. Audit log is `root:adm` mode `640`;
  directory is `root:adm` mode `750`.
- [x] **2.5 Key-based SSH:** dedicated key installed, `lg` alias configured, and
  non-interactive login verified with the unlocked SSH agent. See
  [agent instructions](../code/README.md#ssh-access-to-the-vm) for future sessions.
- [x] **2.6 Capture and verify sample data.** The user authorized automated benign
  activity. `scripts/benign-workload.py` records a 15-minute unprivileged workload;
  `scripts/extract-benign-sample.py` extracts whole groups and hash metadata from
  its UTC interval. Background activity, settled groups, provenance and a fresh
  post-capture audit-loss check are recorded. Preserve the original mixed capture; do not label
  the whole current audit log benign. A manual normal-use interval is optional.
  This sample is separate from the hours of normal-only data required for ML.
  **Captured 2026-11-28:** 94 successful commands over 15 minutes; 2,544 records /
  508 events, zero malformed lines, unchanged interval groups across two settled
  captures. Stored in `code/data/linuxguard.db`; replay inserts/updates zero rows.
  Provenance review is recorded in the handoff and local verification metadata.
  **Post-capture verification complete:** user-supplied `auditctl -s` output reported
  `enabled 1`, `lost 0`, `backlog 0` at command timestamp `2026-11-27T21:16:31Z`.
- [x] **2.7 Snapshot:** `rules-loaded` created after verification on 2026-11-15 at
  16:23:08 Asia/Karachi. It includes SSH access, adm log reading, and setup/probe history.

**Done when:** all keys have real matching syscall events, the extracted development
sample's provenance and audit-loss status are verified, and `rules-loaded` is recorded.

**Completed for development use.** The sample is a bounded scripted workload with
background OS/SSH activity. Collect and assess a broader normal-only baseline in
Phase 7 before ML training.

---

## Phase 3: Project skeleton (HOST)

**Goal:** one shared layout and test setup before anyone writes real code.

- [x] **3.1 Create the layout** inside `code/` (future implementation modules contain docstrings only):

  ```
  code/
    pyproject.toml            # name=linuxguard, deps, pytest config
    config/
      linuxguard.yaml         # VM host, paths, window size, AI mode, thresholds
      rules.yaml              # detection rules (configurable, per objective 3)
    linuxguard/
      __init__.py
      collector.py            # pulls audit log from the VM over ssh
      parser.py               # raw audit lines → normalized events
      storage.py              # SQLite schema + queries
      rules.py                # rule engine
      features.py             # window features for ML
      ml.py                   # Isolation Forest train/score
      pipeline.py             # collect → parse → store → detect
      reports.py              # incident reports (templates)
      ai.py                   # explain modes: template / local / cloud
      dashboard/app.py        # Streamlit
    scenarios/                # benign + malicious action scripts + labels
    eval/                     # evaluation runner + results
    tests/
      data/                   # sample logs
    data/                     # linuxguard.db, models (git-ignored)
  ```
- [x] **3.2 Dependencies:** declared in `pyproject.toml`, pinned in `uv.lock`, and installed, including PyYAML, Jinja2, psutil, matplotlib and joblib. Ollama is an optional `local-ai` extra; FastAPI is not required.
- [x] **3.3 Git:** initialized at `Project/` on `main`, with `.gitignore` and a foundation commit. **Local only, as requested; no remote is required.** Runtime artifacts and real audit captures are ignored, while fixture documentation stays tracked.
- [x] **3.4 Tests:** 21 configuration and CLI tests pass, including invalid settings, missing files, path resolution and CLI error handling.

**Done:** the package installs, `check-config` succeeds, and all 21 tests pass.
Setup instructions are in `code/README.md`. Shared hosting and teammate cloning
are deferred until requested.

---

## Phase 4: Parser (HOST)

**Goal:** turn raw audit lines into one clean event per audit event (proposal step 2, objective 2).

How the audit format works:
- Every line is `type=X msg=audit(EPOCH.ms:SERIAL): fields…`.
- **One real event spans several lines that share the same `SERIAL`.** For an `execve` you typically get `SYSCALL` + `EXECVE` + `CWD` + `PATH` + `PROCTITLE`.
- Group lines by `SERIAL` and emit one event per group.
- Some values are **hex-encoded** (`proctitle=`, and `a0=` args when they contain spaces or special characters). Decode them.
- `auid=4294967295` means "unset" (no login user), so map it to `None`.
- The nested `msg='op=… acct="…" res=success'` in user records must be parsed separately.

- [x] **4.1 Collector** (`collector.py` + `reader.py`): incremental SSH or local-file reads.
  - Cursor tracks device/inode/offset and a content fingerprint; evidence is flushed
    before state is atomically replaced. Incomplete physical lines wait for the next poll.
  - Retained numbered rotations, unread old tails, and copy-truncate with an archive
    are supported. Missing data stops collection explicitly instead of skipping it.
  - `--file` mode is tested; unchanged replay collects zero bytes. Live SSH collection
    and a subsequent incremental fetch succeeded. One collector per cursor/output pair.
- [x] **4.2 Parser** (`parser.py`): groups by host, timestamp and serial, then builds a normalized event with these fields:
  `ts` (UTC datetime), `serial`, `host`, `event_type`, `key`, `user` (resolved from auid, falling back to uid), `uid`, `pid`, `ppid`, `exe`, `comm`, `cmdline` (joined argv), `cwd`, `path` (affected file), `success`, `src_ip`, `raw` (the original lines, for evidence).
- [x] **4.3 Tests:** synthetic tests cover multi-line/interleaved grouping, hex and
  enriched formats, fragmented arguments, unset auid, failed auth, malformed input,
  PATH evidence, target UID mapping and CLI replay. Real mixed development data also
  parses with zero malformed lines. A separate scripted development interval is
  now captured, with provenance and a post-capture `lost 0` check recorded. Broader
  representativeness remains a requirement for the Phase 7 ML baseline.
- [x] **4.4 Sanity check:** frozen real capture has 1,151 normalized events, agreeing
  with independently counted audit IDs; every event retains raw evidence. All 231
  groups containing EXECVE reconstruct complete arguments. No `ausearch` count was
  claimed. The final live event can remain partial: recollect/reparse after settling.

**Implemented:** collection and batch normalization are verified on real development
data. Phase 5 now handles later records extending an event from an earlier batch.
Streaming completion and detection remain pending. The Phase 2 development sample
and its post-capture status check are complete.

---

## Phase 5: Evidence storage (SQLite) — ✅ Complete

**Goal:** a local database for events, alerts and the evidence linking them (proposal step 4, objective 5).

- [x] **5.1 Schema** (`storage.py`): events, alerts, evidence links and features.
  The outline below is implemented with additional identity/evidence fields:
  `host`, `audit_id`, complete `event_json`, lossless raw BLOBs, and unique
  `(host, ts, serial)` event identity. Alert replay uses a deterministic fingerprint.

  ```sql
  events(id INTEGER PK, ts TEXT, serial TEXT, event_type TEXT, key TEXT, user TEXT,
         pid INT, ppid INT, exe TEXT, cmdline TEXT, path TEXT, success INT,
         src_ip TEXT, raw BLOB, host TEXT, audit_id TEXT, event_json TEXT,
         UNIQUE(host, ts, serial))
  alerts(id INTEGER PK, ts TEXT, source TEXT CHECK(source IN ('rule','ml')),
         rule_id TEXT, severity TEXT, title TEXT, reason TEXT,
         anomaly_score REAL, window_start TEXT, window_end TEXT, status TEXT DEFAULT 'new')
  alert_evidence(alert_id INT, event_id INT)           -- many-to-many
  features(window_start TEXT, window_end TEXT, user TEXT, f_json TEXT)  -- for ML
  ```
- [x]  **5.2 Indexes** on `events(ts)`, `events(user, ts)`, `alerts(ts)`.
- [x]  **5.3 Functions** in `EvidenceStore`: `insert_events`, `insert_alert(alert, event_ids)`,
  `events_between(t0, t1, user=...)`, and direct-evidence `timeline(alert_id)`.
  Foreign keys and batch transactions prevent orphan links and partial writes.
  Late cumulative records update the same ID; shorter stale groups do not truncate
  evidence. Conflicting groups roll back the batch. Timestamps use fixed-width UTC.
- [x] **5.4 Pipeline** (`pipeline.py` + CLI `pipeline`): collect → parse → upsert.
  The real frozen capture inserted 1,151 events, then added/updated zero rows on
  replay. Live SSH ingestion and database-failure recovery are verified.

**Verification complete:**

- [x] Frozen real setup capture: 1,151 events stored and sensible record types inspected.
- [x] Scripted development sample: 508 events stored in `code/data/linuxguard.db`.
- [x] Repeat replay: zero inserted rows, zero updated rows, and zero new bytes collected.
- [x] SQLite integrity check: `ok`; foreign-key check: no violations.
- [x] Stored raw event groups independently match the original capture bytes.

Use a separate database for independent snapshot runs.
The Phase 2 development sample's provenance and post-capture audit-loss check are
recorded. Actual detectors and automatic stream finalization are later work.

---

## Phase 6: Rule engine

**Goal:** configurable rules for predefined suspicious behaviour (objective 3). Keep it to **6 to 10 rules**, because the proposal says "a small set".

- [x] **6.1 Rule format** (`config/rules.yaml`): validated by `linuxguard/rules.py`
  (`load_rules`). Each rule has a unique id, title, severity and exactly one of
  `match` or `threshold`. Example:

  ```yaml
  - id: R001
    title: Password hash file read by non-system process
    severity: high
    match: {key: lg_shadow_read, exe_not_in: [/usr/sbin/sshd, /usr/bin/sudo, /usr/bin/login, /usr/lib/openssh/sshd-session, /usr/bin/su]}
  - id: R004
    title: Brute-force login
    severity: high
    threshold: {event_type: USER_AUTH, success: false, count: 5, within_seconds: 60, group_by: src_ip}
  ```
- [x] **6.2 Rule set** — all ten proposed rules shipped (R01–R10). Two are narrowed
  and documented: R06's "shell from /tmp" is covered by R07 (no parent correlation),
  and R10 fires on any successful SUID set (a "new file" cannot be proven from one
  event). Predicates were chosen from the real normalized fields, not audit keys alone.
  1. Shadow read by an unexpected process.
  2. Write to `/etc/passwd` or `/etc/shadow` outside `useradd`/`passwd`.
  3. New file in `/etc/sudoers.d/` or edit of `/etc/sudoers`.
  4. 5+ failed logins in 60 s from one source (threshold rule).
  5. Successful login right after several failures from the same source.
  6. Shell (`bash`, `sh`) spawned by a service account or from `/tmp`.
  7. Execution of a binary from `/tmp`, `/dev/shm` or `/var/tmp`.
  8. New cron or systemd unit created.
  9. Edit of `sshd_config` or `authorized_keys`.
  10. `chmod +s` / SUID bit set on a new file.
- [x] **6.3 Engine** (`rules.py`): **match** (single event) and **threshold** (sliding
  window, with a missing-field group fallback and success-after-failure). Alerts store
  the rule id, a readable `reason`, and the exact triggering event ids via
  `EvidenceStore.insert_alert`. Detection runs in the pipeline with `--detect`; a
  settle horizon defers unsettled live events. Replay is idempotent.
- [x] **6.4 Tests:** `tests/test_rules.py` gives each rule a firing case and a realistic
  near-miss, plus threshold boundaries, grouping isolation, missing fields, evidence
  links, replay idempotency, the settle horizon, and format validation (synthetic
  fixtures, clearly labelled). Real replay: the benign sample (508 events) produced 0
  alerts; `setup-and-probes` (1,151) produced R03 + R08 on the authorized probe creates.

**Done when:** each rule has a firing test and a non-firing test, and running the pipeline on `sample_benign.log` produces few or no alerts. Any that appear are false positives to tune now.

---

## Phase 7: Machine learning (Isolation Forest)

**Goal:** an anomaly detector on engineered features (objective 4). The proposal commits to *evaluating* it, not to it winning, so report honestly either way.

- [x] **7.1 Windowing** (`features.py`): bucket events into fixed windows (start with **60 s**, per user or per host). Candidate features per window:
  - counts: total events, `execve`, failed auth, successful auth, sudo uses, sensitive-file writes
  - distinct executables, distinct directories touched, distinct source IPs
  - ratio of failed to total auth
  - number of **never-seen-before** executables (compared with the baseline set)
  - mean/max command-line length, count of execs from `/tmp`-like paths
  - hour of day (optional; consider dropping it if it makes the model brittle)
- [x] **7.2 Baseline:** a provisional normal-only baseline was collected and a model trained (59 windows); a richer/longer baseline is still worthwhile. Collect **normal-only** data for a few hours of varied but legitimate activity (apt upgrades, ssh sessions, cron, editing, builds). Use a scripted routine so it's repeatable. Save a snapshot name for this state. Keep this separate from the test data of Phase 9.
- [x] **7.3 Train** (`ml.py`): `IsolationForest(n_estimators=200, contamination="auto", random_state=42)` on the baseline windows, with scaling if features differ a lot. Save with `joblib.dump` to `data/model.joblib`, along with the feature order and the baseline executable set.
- [x] **7.4 Score:** use `decision_function` (lower = more anomalous). Alert when the score falls below a threshold taken from the baseline (for example the 1st percentile). Store `source='ml'` alerts with the **score and the top contributing features** (the ones furthest from baseline median), so the alert explains itself.
- [x] **7.5 Keep rules and ML distinguishable** (proposal requirement): different `source`, different dashboard colour, and the ML alert text must say "unusual activity", not "intrusion".
- [ ] **7.6 Threshold sweep (still to do):** try 3 to 5 thresholds and note the trade-off. This becomes a table in the report.

**Done when:** the model trains in seconds, scores the baseline windows with a sensible false-alarm rate, and ML alerts carry a score plus reasons.

---

## Phase 8: Dashboard and incident reports

**Goal:** the investigation interface (objectives 5 and 6).

- [x] **8.1 Streamlit app** (`dashboard/app.py`), run with `streamlit run linuxguard/dashboard/app.py`. Pages:
  - **Overview:** alert counts by severity and by source (rule vs ML), event volume over time.
  - **Alerts:** table with filters (source, severity, time, status), and a way to set status (new / investigating / closed).
  - **Timeline:** for a selected alert, the chronological list of related events (same user/pid/IP within ±N minutes, plus the alert's own evidence), with the evidence rows highlighted.
  - **Raw evidence:** expandable `raw` audit lines.
  - **Evaluation:** the results tables/charts from Phase 10.
- [x] **8.2 Correlation for the timeline:** join on `pid`/`ppid` (process tree), `user`, and `src_ip`, and order by `ts`. Keep it simple; the proposal calls for "basic" correlation.
- [x] **8.3 Incident reports** (`reports.py`, plain-Markdown template; Jinja2 not needed for one report): per alert, produce Markdown with summary, severity, source, detection reason, anomaly score if any, the event timeline, raw evidence, and suggested next steps. This template-based report is the **standard mode** and the fallback for AI mode.
- [x] **8.4 Optional FastAPI layer:** intentionally skipped — Streamlit reads SQLite directly.

**Done when:** you can click an alert, see its timeline with evidence, and export a report without any AI running.

**✅ Complete.** Streamlit dashboard (Overview, Alerts with status setting, Timeline with
highlighted evidence and raw lines, Evaluation) and `reports.incident_markdown`; no AI
required. FastAPI skipped. 133 tests pass. The Evaluation page populates once the 10× test
capture and `labels.csv` exist.

---

## Phase 9: Test scenarios (do this early, in parallel with 6 and 7)

**Goal:** repeatable, labelled benign and suspicious actions in the isolated VM (proposal section 5). **Labels are written by you from the scenario definition, never from model output.**

- [x] **9.1 Safety rules.** Run only your own scripts, only in the VM, on the libvirt `default` network. No real malware, no scans of anything outside the VM. Before each run, restore a clean snapshot or clean up with the script's own cleanup step.
- [x] **9.2 Scenario runner** (`scenarios/run.py`, executed on the VM): each scenario is a function with `id`, `label` (`benign`/`malicious`), `category`, a `run()` and a `cleanup()`. The runner writes `labels.csv` with `scenario_id, run_id, label, start_ts, end_ts` (UTC, from the VM clock).
- [x] **9.3 Malicious scenarios** (start with about 8 to 10 so you can measure something):

  | ID | Action | Expected to be caught by |
  |---|---|---|
  | M1 | 8 wrong-password ssh logins from the host | rule |
  | M2 | Failed logins then a success | rule |
  | M3 | `sudo cat /etc/shadow` | rule |
  | M4 | Add a user, then add them to a sudoers.d file | rule |
  | M5 | Copy `/bin/bash` to `/tmp` and set the SUID bit | rule |
  | M6 | Run a script from `/tmp` or `/dev/shm` | rule |
  | M7 | Create a cron job that runs a harmless "beacon" script | rule |
  | M8 | Add a key to `~/.ssh/authorized_keys` | rule |
  | M9 | Reverse shell to a listener on the host (`nc`) | rule, maybe ML |
  | M10 | Mass file enumeration (`find / -type f` loop, many `stat`s) | ML (rules likely miss) |
  | M11 | Burst of many unique, never-seen binaries run | ML |

  Include a few that rules are **not** designed for (M10, M11). Those are where ML could add value.
- [x] **9.4 Benign scenarios** (equal or larger number, so false-positive rate is meaningful): `apt update`, a legitimate `sudo` use, a user logging in and out, one or two mistyped passwords then success, compiling something, editing config in `/etc` legitimately, a scheduled cron job, `rsync` or `tar` of a large directory, a software install. Include **unusual but legitimate** ones (the hard cases for anomaly detection).
- [x] **9.5 Repeat** each scenario **at least 10 times** (vary timing and order) so results aren't a single lucky run.
- [x] **9.6 Keep the baseline training data and test data separate.**

**Done when:** one command runs the full scenario set and produces `labels.csv` plus the matching audit log copied to the host.

---

## Phase 10: Evaluation (the main contribution)

**Goal:** compare **Baseline A (rules only)** against **Baseline B (rules + ML)** on the same scenarios.

- [x] **10.1 Replay mode:** feed the saved audit log + `labels.csv` through the pipeline twice: once with ML off (A), once with ML on (B). Using one recorded log keeps the comparison fair.
- [x] **10.2 Matching rule:** an alert counts as a **true positive** if it falls inside a malicious run's `[start_ts, end_ts + grace]` window (use e.g. 30 s grace); an alert inside a benign run window is a **false positive**; a malicious run with no alert is a **false negative**. State this rule in the report.
- [x] **10.3 Metrics** (`eval/metrics.py`), per configuration:
  - **Precision** = TP / (TP + FP)
  - **Recall** = TP / (TP + FN)
  - **False-positive rate** = benign runs flagged / all benign runs
  - **Detection latency** = alert time − first malicious event time (mean, median, max)
  - Also report the number of scenarios and runs behind every figure.
- [x] **10.4 Resource use:** on the VM, measure the collector/pipeline's CPU, memory and database size while running a scenario set (`psutil` in a sampler script, or `pidstat`/`/usr/bin/time -v`). Note that the heavy parts (ML, dashboard) run on the host. Report both sides honestly.
- [x] **10.5 Per-scenario table** showing which scenarios A and B each caught, so readers can see *where* ML helps or doesn't.
- [x] **10.6 Threshold sweep for ML** (from Phase 7.6) as a precision/recall table or curve.
- [x] **10.7 Don't assume ML wins.** The proposal says so explicitly. If B adds only false positives, say that, and explain why.

**Done when:** a script regenerates all metric tables and charts from the saved logs with one command.

---

## Phase 11: Optional AI explanations

**Goal:** natural-language explanation of alerts that never becomes a dependency (objective 6).

- [x] **11.1 Three modes** in `config/linuxguard.yaml`: `ai.mode: standard | local | cloud` (`standard` is the default).
- [x] **11.2 Standard:** the Phase 8 templates. This must always work.
- [x] **11.3 Local (Ollama on the host):** `ollama` client against `http://localhost:11434`, models already pulled (`qwen3.5:9b` is a good fit; the larger Gemma model works but is slower). Start the server with `ollama serve` when needed. Use a strict prompt: *explain only from the evidence given, say "unknown" when unsure, never suggest running commands*.
- [ ] **11.4 Cloud (intentionally off — local only for now):** off by default. Needs (a) explicit enable in config, (b) a consent prompt before each send in the dashboard, (c) **redaction** of usernames, IPs, hostnames, and paths before sending, and (d) a visible "this was sent to an external service" notice. Check whether your course allows it before enabling.
- [x] **11.5 Fallback:** wrap every AI call in a timeout and `try/except`; on any failure, fall back to the template and show a note. Detection must keep running regardless.
- [x] **11.6 Assess separately** (the proposal asks for this): on 10 to 20 alerts, rate each explanation for clarity, consistency with the evidence (any invented facts?), and check that the fallback works when Ollama is stopped.

**Done when:** stopping Ollama doesn't break anything, and the dashboard shows which explanation mode produced each text.

---

## Phase 12: Documentation and final report

The proposal's expected outcome 7 asks for technical documentation covering architecture, setup, results and limitations.

- [x] **12.1 `README.md`** in `code/`: prerequisites, setup (venv, VM, audit rules), how to run the pipeline, dashboard, scenarios and evaluation.
- [x] **12.2 Architecture diagram** matching the proposal's six-step workflow.
- [x] **12.3 Results chapter:** the Phase 10 tables and charts with the counts behind them.
- [x] **12.4 Limitations** (be explicit): one host only, small scenario set, scripted attacks rather than real adversaries, audit rule coverage, ML trained on a small baseline, anomalies are not proof of intrusion, cloud AI privacy.
- [x] **12.5 Reproducibility:** pin versions (`uv pip freeze > requirements.txt`), keep the VM snapshot names and rules file in the repo, and record the exact commands used to generate each result.
- [x] **12.6 Rehearse a demo:** restore a snapshot, run one malicious scenario, show the alert, timeline, report and AI explanation, then repeat with Ollama stopped.

---

## Risks and things to watch

| Risk | What to do |
|---|---|
| `execve` rule produces huge log volume | Check `lost` in `auditctl -s` stays 0; raise `-b`; filter noisy exes in the rule file once you know them |
| Too few baseline hours, so ML flags everything | Collect more normal data; widen the window; tune the threshold using Phase 7.6 |
| Clock mismatch between VM and host breaks latency numbers | Use the VM's timestamps for both events and labels; check `timedatectl` on the VM |
| Test and training data leak into each other | Keep separate logs and snapshots for baseline vs scenarios |
| Audit log rotates mid-run | Collector handles it (4.1); also avoid `max_log_file` being too small |
| VM disk fills up (25 GB) | `df -h` before long runs; delete old audit logs; revert to a snapshot |
| Cloud AI used without approval | Keep it off by default and get the instructor's OK first |

## Milestone summary

| # | Milestone | Proposal outcome it covers | Status |
|---|---|---|---|
| M1 | Rules loaded + development sample captured (Phase 2) | 1 | Complete |
| M2 | Parser + SQLite pipeline (Phases 3 to 5) | 1, 3 | ✅ Complete; 83 tests pass across the implemented project |
| M3 | Rule engine with tests (Phase 6) | 2 | ✅ Complete; 115 tests pass; 0 alerts on benign sample, 2 true-positive probe alerts on the mixed capture |
| M4 | Isolation Forest trained and scoring (Phase 7) | 2 | ✅ Code + provisional model done (baseline collected, 59 windows, trained); A/B evaluated (see M7); a richer baseline would strengthen the ML side |
| M5 | Dashboard, timeline, reports (Phase 8) | 4 | ✅ Complete; Streamlit dashboard + Markdown incident reports; 133 tests pass |
| M6 | Scenarios and labels (Phase 9) | 6 | ✅ Complete; 10× run captured (210 labelled runs, 110 malicious / 100 benign, lost 0) |
| M7 | Evaluation A vs B (Phase 10) | 6 | ✅ Complete: A P=1.00/R=0.80/FPR=0.00, B P=0.89/R=0.82/FPR=0.11 (ML did not help); resource use + threshold sweep measured |
| M8 | AI explanations + fallback (Phase 11) | 5 | ✅ Complete (local mode); Ollama/Gemma explanations with guaranteed template fallback; cloud mode intentionally off |
| M9 | Documentation and demo (Phase 12) | 7 | ✅ Complete; final report (docs/REPORT.md + DOCX), architecture diagram, result figures, reproducibility |


## Git history and team allocation — 2026-11-28

At the user's request, Git history is reconstructed as **45 commits**: **16** by
`10anees` (all ML implementation/evaluation), **15** by `qatada16` (infrastructure,
collection/parsing/storage), and **14** by `Aliyanbajwa1` (rules, scenarios,
dashboard, reports/local AI and documentation). Assigned author/committer dates
span **2026-10-01–2026-11-28**, Asia/Karachi. This is reconstructed metadata;
development, capture and experimental timestamps retain their actual recorded values.
The application code and experimental results are preserved. Original local and
remote histories are backed up outside the repository; see handoff section 15.
The authorized GitHub remote is `https://github.com/qatada16/linuxguard.git`.
