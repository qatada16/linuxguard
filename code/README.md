# LinuxGuard development

The project foundation, incremental collector, batch audit parser, and SQLite
ingestion pipeline are ready. Detection, ML, dashboard, scenario evaluation, and
reports are still pending; their implementation modules remain placeholders.

## Setup and checks

Run these commands on the **host**, from this `code/` directory. Python 3.12,
`uv`, Git, and the host's OpenSSH client are required. SQLite comes with Python.

```bash
uv sync --locked --inexact
uv run --locked --inexact python -m linuxguard check-config
uv run --locked --inexact pytest
```

Last verified 2026-11-28: **83 tests pass**.

`uv.lock` pins direct and transitive dependencies. `--inexact` keeps any unrelated
packages already installed in the existing virtual environment. A fresh checkout
installs only declared dependencies. To deliberately update dependencies later,
edit `pyproject.toml`, run `uv lock`, and rerun the checks.

Shell activation is optional. For Bash use `source .venv/bin/activate`; for Fish use
`source .venv/bin/activate.fish`. The `uv run` commands work without activation.

The configuration check reads YAML and prints the selected settings. It does not
connect to the VM, create a database, start AI, or collect audit records. Relative
paths in `config/linuxguard.yaml` resolve from the configuration file's directory.
The detection-rule list is deliberately empty until the rule engine is implemented.
AI defaults to `standard`; no AI integration is implemented yet.

The Ollama client is optional for the later local explanation phase:

```bash
uv sync --locked --inexact --extra local-ai
```

FastAPI and Uvicorn are not required for the planned Streamlit/SQLite prototype.
Existing installations are left in place.

## Layout

```text
config/                 Settings, audit collection rules and future detection rules
linuxguard/config.py    Configuration loading and validation
linuxguard/__main__.py  check-config, collect, parse, and pipeline commands
linuxguard/collector.py Incremental SSH/local-file collection and cursor management
linuxguard/reader.py    Shared standard-library reader also executed on the VM
linuxguard/parser.py    Batch grouping, decoding, normalization and JSONL export
linuxguard/storage.py   SQLite events, alerts, evidence links and indexed queries
linuxguard/pipeline.py  Collect → batch parse → duplicate-safe database ingestion
linuxguard/             Remaining implementation modules are placeholders
linuxguard/dashboard/  Future Streamlit dashboard
scripts/                VM setup, trigger checks, benign workload and sample extraction
scenarios/              Future repeatable, labelled VM scenarios
eval/                   Future evaluation runner
tests/                  Configuration, collection, parsing, storage and workload tests
tests/data/             Local audit captures (ignored by Git)
data/                   Local state, databases and models (ignored by Git)
```

## Collect and normalize audit evidence

From `code/`, with the SSH agent available, collect new physical log lines:

```bash
uv run --locked --inexact python -m linuxguard collect --output data/captures/live-development.audit --state data/live-development-state.json
```

The first run reads the current audit log; later runs append only new complete
lines. The saved cursor tracks device, inode, byte offset, and a content fingerprint.
Retained numbered rotations are read in order, including unread old-file tails.
Copy-truncate is supported if a matching archive remains. Missing archives, partial
archived records, SSH errors, corrupt cursors, or a changed capture produce a clear
error rather than silently advancing past evidence.

Use one collector process per output/state pair. Keep that pair together and do
not edit the capture. Raw data is flushed before the cursor is replaced. If a
process stops between those operations, the next run detects the size mismatch;
preserve both files and recover by replaying into a fresh pair. This is not a
concurrent or transactional database ingestion service.

Capture the target's public UID mapping and build a normalized JSONL view:

```bash
scp lg:/etc/passwd data/captures/target-passwd
uv run --locked --inexact python -m linuxguard parse --file data/captures/live-development.audit --output data/captures/live-development.events.jsonl --host linuxguard-target --passwd-file data/captures/target-passwd
```

The parser groups records by node, timestamp, and serial, including interleaved
events. It handles enriched records, nested user messages, hex strings, NUL-separated
proctitles, and arguments split across EXECVE records. It preserves raw evidence,
all PATH entries, argument-completeness information, identities, timestamps and
detection keys. UID names come from the target passwd file or enriched fields;
otherwise numeric identities are retained. It never resolves target UIDs using
the host's account database.

Parsing rebuilds its JSONL output atomically, so rerunning it does not append
duplicate normalized events. Malformed lines are counted and skipped. This is a
batch view: the final live event can still be incomplete even when its physical
lines are complete. Collect and reparse after the event settles before using it
for evaluation. Streaming completion and detection are future work.

For offline replay, use a separate cursor/output pair:

```bash
uv run --locked --inexact python -m linuxguard collect --file data/captures/setup-and-probes.audit --output data/captures/replay-check.audit --state data/replay-check-state.json
```

Repeating this with unchanged input collects zero bytes. Do not reuse an SSH cursor
for a local source or switch output files under an existing cursor.

The local `setup-and-probes.audit` capture is mixed development data, not benign
training data. It parsed as 3,285 records / 1,151 events with zero malformed lines;
the count matched independently extracted audit IDs. Local replay was byte-identical
and a second replay collected zero bytes. Live SSH collection and incremental
collection were also exercised. Real captures and their metadata stay Git-ignored.

The parser's grouping follows the upstream [audit event definition](https://github.com/linux-audit/audit-documentation/wiki/SPEC-Writing-Good-Events).

## Collect into SQLite

From `code/`, use a dedicated capture/cursor pair and database for the same VM run:

```bash
uv run --locked --inexact python -m linuxguard pipeline --output data/captures/pipeline.audit --state data/pipeline-state.json --passwd-file data/captures/target-passwd
```

The default database is `data/linuxguard.db`. `--database` selects a different one.
SSH collection obtains the source hostname from the reader. For local replay,
provide the source hostname explicitly:

```bash
uv run --locked --inexact python -m linuxguard pipeline --file data/captures/setup-and-probes.audit --output data/captures/storage-replay.audit --state data/storage-replay-state.json --database data/storage-replay.db --host linuxguard-target --passwd-file data/captures/target-passwd
```

Repeat the same command: unchanged input must report `0 inserted, 0 updated`.
The frozen real development capture produced 1,151 rows; repeating it collected
zero bytes and left all 1,151 rows unchanged. Inspect with the host SQLite binary:

```bash
/usr/bin/sqlite3 data/storage-replay.db 'SELECT count(*) FROM events; PRAGMA integrity_check;'
```

Events are unique by source host, UTC timestamp, and serial. Full normalized JSON
and exact raw bytes are stored, including all PATH records. UTC timestamps have
fixed microsecond precision for correct ordering. A later cumulative batch can
extend a partial event without changing its ID or breaking evidence links. A stale
shorter batch cannot truncate it; divergent evidence aborts the database batch.
Use a separate database and capture/cursor pair after an independent snapshot
restore. No cross-run identity or automatic stream finalization is claimed.

`EvidenceStore.events_between(start, end, user=...)` uses a half-open UTC interval
`[start, end)`. `insert_alert(alert, event_ids)` creates transactional evidence links
and reuses the ID on an identical alert replay; `timeline(alert_id)` returns that
alert's direct evidence. Wider correlation and actual alert generation come later.
The features table is ready for Phase 7; feature computation is not implemented.
New databases use mode `600`. Malformed input preserves the raw capture and stops
ingestion before database writes. Database failure preserves the capture/cursor;
rerun after resolving it to replay the cumulative evidence.

## SSH access to the VM

SSH key login and the `lg` alias now work. The VM is `linuxguard-target`, user
`bonzo`, at `192.168.122.164`. A key protected by a passphrase needs an SSH agent
for automated collection.

In Fish, start an agent if needed and load the existing key:

```fish
eval (ssh-agent -c)
ssh-add ~/.ssh/id_ed25519_linuxguard
ssh -o BatchMode=yes lg 'hostname; id -un'
echo $SSH_AUTH_SOCK
```

In Bash, the agent-start command is `eval "$(ssh-agent -s)"`; the remaining
commands are the same. Load the key once per agent session. Share only the socket
path if the coding session needs access; keep passphrases and private keys private.
The remote user's shell is Fish, so multi-line POSIX scripts must be invoked with
`sh`, rather than sent directly as Fish commands.

## VM audit setup (completed)

The user ran the prepared installer successfully. A fresh SSH connection verified:

- `bonzo` belongs to `adm` and can read `/var/log/audit/audit.log` without sudo.
- Auditd is active. The successful installation reported `enabled 1` and `lost 0`.
- All seven project audit keys have real matching successful syscall events.
- The three deliberate probe paths matched their expected keys, and all probe
  files were removed. Authentication records are present.
- Snapshot `rules-loaded` was created after verification, with SSH and log access
  configured. It contains setup/probe history, not a clean training dataset.
- The audit configuration backup is `/root/linuxguard-audit-backup.GZiTLr`.

**Do not reinstall audit rules just to reconnect in a new session.** Use the
[complete agent handoff](../docs/AGENT_HANDOFF.md) for the current connection
procedure, authorization boundaries, setup history, rebuild commands, and next steps.
The repository's root `AGENTS.md` directs future coding sessions to that handoff.

The installed rules came from [config/audit/linuxguard.rules](config/audit/linuxguard.rules).
The [setup script](scripts/setup-audit.sh) remains staged with its rules at
`/home/bonzo/linuxguard-setup/` on the VM. It backs up configuration, checks the
intended target, installs and loads rules, configures group log access, and reloads
configuration. Sudo still requires the user's VM password in their own terminal;
no unattended root access was created.

The configuration follows the upstream [rule-loading guidance](https://github.com/linux-audit/audit-userspace/blob/master/rules/README-rules),
[auditd log-group configuration](https://github.com/linux-audit/audit-userspace/blob/master/docs/auditd.conf.5),
and [auditctl reload interface](https://github.com/linux-audit/audit-userspace/blob/master/docs/auditctl.8).

## Scripted benign development sample

The first run completed on 2026-11-28 (Asia/Karachi): 94 successful commands over
15 minutes, captured as 2,544 records / 508 events. Its data and provenance are
local at `data/captures/scripted-benign-20261128/`; the extracted interval is in
`data/linuxguard.db`. Replay adds/updates zero rows, database integrity checks pass,
and raw groups match the original bytes. It includes background OS/SSH activity.
The user supplied the post-capture status check at command timestamp
`2026-11-27T21:16:31Z`: `enabled 1`, `lost 0`, `backlog 0`. Development sample
verification is complete; a broader representative ML baseline remains pending.
Details and exact replay commands are in [the handoff](../docs/AGENT_HANDOFF.md#8-scripted-development-capture--2026-11-28).

The user authorized automation of normal VM tasks. A bounded unprivileged workload
is available at `scripts/benign-workload.py`. It creates a new directory under
`~/linuxguard-workloads/`, edits notes, lists/searches files, copies/compares files,
creates/lists archives, and compiles/runs a small Python assertion. It records each
command, UTC interval, exit code, stdout and stderr in `manifest.json`. Default
duration is 900 seconds; files are retained for review. It makes no privileged
configuration changes and does not install packages or run attack probes.

For a new run, first start a dedicated raw capture/cursor pair with `collect`, then
upload and run the workload using the unlocked SSH agent:

```bash
scp scripts/benign-workload.py lg:linuxguard-setup/benign-workload.py
ssh -o BatchMode=yes lg 'python3 /home/bonzo/linuxguard-setup/benign-workload.py --duration 900'
```

Continue collecting periodically during the run. The workload prints its manifest
path and timestamps. After completion, fetch that manifest, collect again after
events settle, and extract the interval into a new output:

```bash
uv run --locked --inexact python scripts/extract-benign-sample.py data/captures/RUN/full.audit data/captures/RUN/manifest.json data/captures/RUN/sample.audit
```

Replace `RUN` with the actual run directory. The extractor retains whole event
groups in `[start, end)`, preserves the cumulative original, and records hashes
and counts in `sample.metadata.json`. It refuses overwrites or malformed inputs.
Review the extracted commands/background activity and compare interval groups
across two settled captures. For future captures, a fresh audit-loss check needs
the user's interactive sudo access:

```bash
ssh -t lg 'sudo auditctl -s'
```

Record the output with each dataset; expect `enabled 1` and `lost 0`. The first
run's check is complete; do not repeat it merely to reconnect. Keep future run
verification pending until actual output is available. A scripted benign workload
is real VM evidence, but it is not representative human use or the hours of varied
normal-only data required for ML training. Keep it separate from scenario tests.

## Optional human-use sample

Record the VM's UTC time before and after 15–20 minutes of ordinary activity:

```bash
ssh lg 'date -u +%Y-%m-%dT%H:%M:%SZ'
```

Between those timestamps, use `ssh lg` normally: list files, edit files in your
home directory, copy/archive files, log out/in, and perform legitimate sudo tasks
you would ordinarily do. Do not run audit probes or suspicious scenarios during
that interval. Share both timestamps and a short activity description.

The agent can then collect the log and extract the agreed interval while preserving
the raw original. Label it benign only after reviewing its contents and activity
description. This short development sample is separate from the hours of normal
data needed for ML training. Human operation is optional for the scripted workload;
reviewing how well the activity represents the intended use remains useful.

The remaining project phases are in the [roadmap](../timeline/LinuxGuard_Roadmap.md).

## Local version control

Git lives at the parent `Project/` directory, on branch `main`, with no remote.
Run these from that directory:

```bash
git status
git log --oneline
git diff
```

Only source, documentation, synthetic fixtures explicitly allowed by `.gitignore`,
and the dependency lock should be committed. The virtual environment, real audit
captures, runtime state, generated results, databases, and models stay local.
