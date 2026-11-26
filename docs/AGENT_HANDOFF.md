# LinuxGuard: session handoff and complete access procedure

Last verified: **2026-11-28**, Asia/Karachi (SSH, log access, local tests and SQLite).
The user supplied fresh privileged audit status after capture, with command timestamp
`2026-11-27T21:16:31Z` (2026-11-28 02:16:31 Asia/Karachi): `enabled 1`, `lost 0`, `backlog 0`.
This describes the existing local
machine and its lab VM. Recheck live state when resuming; the SSH-agent socket and
VM address can change.

## 1. Scope, authorization, and remaining user involvement

The user requested that the agent implement what it can, guide them step by step,
and keep version control local. They explicitly completed SSH-key installation,
unlocked the key in an agent, shared its socket path for agent use, and ran the
prepared VM audit setup using their VM sudo password.

Authorized project work includes local implementation, verification, local Git,
and setup/collection against this designated lab VM. Continue within that scope
without repeating permission questions for already authorized steps. This record
does not supply credentials, bypass machine permissions, or authorize unrelated
systems, publication, external data sharing, or destructive snapshot restores.

| Capability | Current state | User involvement |
|---|---|---|
| Local source editing, dependencies, tests, Git | Working | None for ordinary development |
| SSH as `bonzo` | Working with unlocked key | Unlock key again if the agent expires |
| Read `/var/log/audit/audit.log` | Working without sudo | None while SSH works |
| Change VM root configuration or query `auditctl` | Sudo requires a password | Run a prepared command interactively |
| Normal-use data and labels | Scripted development sample and post-capture audit-loss check complete; ML baseline and scenarios pending | Assess representativeness for a broader ML baseline |

**SSH and log-reading access are complete. Root access is not unattended.** No sudo
password, private-key contents, or key passphrase is stored in this repository.
Host and VM commands below must run as the indicated user, not as a different OS
account. A new agent session still needs access to this same machine and account.

## 2. Machine and repository details

| Item | Value |
|---|---|
| Host user | `phoenix` |
| Repository | `/home/phoenix/Documents/7th Sem/IS/Project` |
| Python project | `code/` inside the repository |
| Virtual environment | `code/.venv`, Python 3.12 |
| Package and lock | `code/pyproject.toml`, `code/uv.lock` |
| Git | Branch `main`, no remote |
| VM management | `virsh -c qemu:///system` |
| VM name / guest hostname | `debian13` / `linuxguard-target` |
| Guest OS / architecture | Debian 13 / x86_64 |
| VM user / address | `bonzo` / `192.168.122.164` |
| SSH alias | `lg` |
| Remote login shell | Fish |
| Audit log | `/var/log/audit/audit.log` |
| Audit configuration | `/etc/audit/auditd.conf` |
| Installed project rules | `/etc/audit/rules.d/70-linuxguard.rules` |
| VM staged setup files | `/home/bonzo/linuxguard-setup/` |
| Pre-setup backup reported by installer | `/root/linuxguard-audit-backup.GZiTLr` |
| Snapshots | `clean-install` and `rules-loaded` |
| `rules-loaded` created | 2026-11-15 16:23:08 Asia/Karachi, VM running |

Useful initial checks on the host:

```bash
cd '/home/phoenix/Documents/7th Sem/IS/Project'
git status --short
git log -5 --oneline
virsh -c qemu:///system list --all
virsh -c qemu:///system domifaddr debian13
virsh -c qemu:///system snapshot-list debian13
```

Do not restore `clean-install` merely to reconnect: it predates SSH-key installation
and project audit setup, so restoring it would undo guest-side access and setup.

## 3. Reuse SSH access in another agent session

The key files already exist on the host:

- Private key path: `/home/phoenix/.ssh/id_ed25519_linuxguard` (do not print/copy its contents).
- Public key path: `/home/phoenix/.ssh/id_ed25519_linuxguard.pub`.
- Expected public-key fingerprint: `SHA256:P2LPq5Cjub4Iuo+2ySlUedO/wzRRq+hUgO6oXDpxnqc`.

The user's `~/.ssh/config` is a file owned by `phoenix`, mode `600`, containing:

```sshconfig
Host lg
    HostName 192.168.122.164
    User bonzo
    IdentityFile ~/.ssh/id_ed25519_linuxguard
    IdentitiesOnly yes
```

The user initially made `~/.ssh/config` a directory. It was repaired and the
original directory preserved at `~/.ssh/config.directory-backup`. No repeat repair
is needed. `lg` is an SSH alias, not a package or DNS name.

### Connect with the already unlocked agent

Last verified socket (temporary runtime value, **not a permanent configuration**):

```text
/home/phoenix/.ssh/agent/s.3xdY5g3Npm.local.56875.wxrpVKn3Gg
```

In the agent's Bash execution tool, explicitly pass it to SSH:

```bash
env SSH_AUTH_SOCK=/home/phoenix/.ssh/agent/s.3xdY5g3Npm.local.56875.wxrpVKn3Gg ssh-add -l
env SSH_AUTH_SOCK=/home/phoenix/.ssh/agent/s.3xdY5g3Npm.local.56875.wxrpVKn3Gg ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=5 lg 'hostname; id -un'
```

Check that the fingerprint matches the key above. Expected guest output:

```text
linuxguard-target
bonzo
```

Use `SSH_AUTH_SOCK` for every independent tool command that runs SSH or SCP, or
export it inside that tool's shell. Exporting it in one short-lived execution does
not necessarily preserve it for later executions. The user's terminal environment
also does not automatically update a running coding session's environment.

If that socket is stale, first check the execution environment's existing
`SSH_AUTH_SOCK`. Other user-owned sockets may be listed with
`ls -l /home/phoenix/.ssh/agent/`; query a candidate with
`env SSH_AUTH_SOCK=/actual/socket/path ssh-add -l` and use one containing the expected
key. Do not reconnect to a different VM or accept a changed host key blindly.
Only request user action if no usable agent/key is available.

### If the key needs unlocking again

Ask the user to run this in their **Fish terminal**. If they already have a working
agent, reuse it and omit the first line:

```fish
eval (ssh-agent -c)
ssh-add ~/.ssh/id_ed25519_linuxguard
ssh -o BatchMode=yes lg 'hostname; id -un'
echo $SSH_AUTH_SOCK
```

They enter the key passphrase locally and share only the verification output and
socket path. In Bash the first line is `eval "$(ssh-agent -s)"`. No new key,
`ssh-copy-id`, or SSH configuration is needed for ordinary session changes.

### Run remote scripts using the correct shell

The guest login shell is Fish. Simple commands separated by semicolons work, but
POSIX `if ...; then ...; fi` does not. For multi-line POSIX scripts use:

```bash
env SSH_AUTH_SOCK=/actual/socket/path ssh -o BatchMode=yes -o StrictHostKeyChecking=yes lg 'sh -s' <<'SH'
hostname
id
systemctl is-active auditd
if test -r /var/log/audit/audit.log; then
    echo AUDIT_LOG_READABLE
else
    echo AUDIT_LOG_NOT_READABLE
fi
SH
```

Use a real verified socket in place of `/actual/socket/path`. The quoted heredoc
keeps the host shell from expanding remote script contents.

## 4. How the access and audit setup was completed

This is the rebuild procedure for this same lab VM, **not work to repeat on a
normally configured VM**.

1. The host Python foundation was created and installed with
   `uv sync --project code --inexact`. `uv.lock` records exact dependency versions.
2. Local Git was initialized at the repository root on `main`. No remote was added.
3. The user created the dedicated SSH key on the host:

   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_linuxguard -C linuxguard-local
   ssh-copy-id -i ~/.ssh/id_ed25519_linuxguard.pub bonzo@192.168.122.164
   ```

   Do not rerun key generation over an existing key. The user supplied their VM
   account password to `ssh-copy-id` in their own terminal.
4. The `Host lg` block above was placed in the actual `~/.ssh/config` file, with
   permissions `600`. Key login returned `linuxguard-target` and `bonzo`.
5. The user started an SSH agent, unlocked the key, and supplied the socket path.
   The coding session then passed that socket explicitly to SSH.
6. Read-only checks found auditd active, no loaded project rules, synchronized time,
   about 21 GB free, and no audit-log access for `bonzo`. Sudo required a password.
7. The agent prepared these versioned files:

   - `code/config/audit/linuxguard.rules`
   - `code/scripts/setup-audit.sh`
   - `code/tests/test_audit_setup.py`

8. From `code/` on the host, with `SSH_AUTH_SOCK` set, the files were staged:

   ```bash
   ssh -o BatchMode=yes lg 'mkdir -p /home/bonzo/linuxguard-setup'
   scp -o BatchMode=yes scripts/setup-audit.sh config/audit/linuxguard.rules lg:linuxguard-setup/
   ssh -o BatchMode=yes lg 'sh -n /home/bonzo/linuxguard-setup/setup-audit.sh'
   ```

   SHA-256 checks confirmed the uploaded copies matched the local files.
9. The user ran the privileged command from their host terminal:

   ```bash
   ssh -t lg 'sudo sh /home/bonzo/linuxguard-setup/setup-audit.sh'
   ```

   They entered **bonzo's VM sudo password**, not the SSH-key passphrase. The
   installer backs up `/etc/audit` and kernel rule/status output before changing
   configuration. It verifies the intended VM and architecture, checks active and
   unlocked auditing, then installs and loads the project rules. It sets
   `log_group = adm`, adds `bonzo` to `adm`, grants group log access, and signals
   auditd to reload. It does not create passwordless sudo access.
10. Installer output confirmed `enabled 1`, `lost 0`, and all project rule keys,
    ending with `LINUXGUARD_AUDIT_SETUP_COMPLETE`. The printed backup path was
    `/root/linuxguard-audit-backup.GZiTLr`. The initial `No rules` described the
    pre-install state. Legacy watch-performance messages did not prevent loading.
11. A fresh coding-session SSH connection confirmed `adm` membership, active auditd,
    and unprivileged log reading. The log directory is `root:adm` mode `750`; the
    current audit log is `root:adm` mode `640`.

12. The user ran `check-audit-triggers.sh` at `2026-11-15T11:22:19Z`.
    Kernel status before and after showed `enabled 1`, `lost 0`. The agent matched
    each exact probe path to successful SYSCALL records in the same event as PATH
    evidence and confirmed the files had been removed:

    | Key | Probe path | Successful audit event IDs |
    |---|---|---|
    | `lg_priv` | `/etc/sudoers.d/.linuxguard-probe.6Pwhem` | `1794741739.956:691`, `1794741739.956:697` |
    | `lg_ssh` | `/home/bonzo/.ssh/.linuxguard-probe.AXpS2q` | `1794741739.956:693`, `1794741739.960:699` |
    | `lg_persist` | `/etc/cron.d/.linuxguard-probe.VEfAW3` | `1794741739.956:695`, `1794741739.960:701` |

13. After checking the snapshot name and host disk space, the agent created:

    ```bash
    virsh -c qemu:///system snapshot-create-as debian13 rules-loaded --description 'Project audit rules loaded and seven audit keys verified; SSH key and adm log access configured' --atomic
    ```

    This succeeded; the running snapshot contains project rules, working SSH-key
    access, adm membership, and the setup/probe log history. It is not an ML baseline.
14. The agent implemented and tested collection and batch parsing. The frozen local
    development capture `code/data/captures/setup-and-probes.audit` contains 3,285
    records grouped into 1,151 events with zero malformed lines. The event count
    agrees with an independent audit-ID count, and its raw local replay is
    byte-identical. Repeating unchanged replay collects zero bytes. Live SSH
    collection and a later incremental collection also succeeded. All 231 groups
    containing EXECVE records in the frozen capture reconstructed complete argv.

The source rule file has no blanket `-D` command. `augenrules --load` merges all
installed persistent rule files, retaining existing rule-file coverage. The script
also adds `/root/.ssh` coverage if that directory exists (it did in this VM).
Use the script source for the exact operations, and inspect new changes before
uploading an updated version. Do not repeatedly run the installer just to check
access. It changes system configuration and is not a connection health check.

## 5. Verified state and remaining gaps

All seven keys appeared in the successful installer output:

| Key | Coverage | Real matching SYSCALL records observed after setup? |
|---|---|---|
| `lg_exec` | `execve` / `execveat`, b64 and b32 rules | Yes |
| `lg_mode` | `chmod` / `fchmod` / `fchmodat`, b64 and b32 rules | Yes |
| `lg_identity` | Writes/attribute changes to passwd, shadow, group | Yes |
| `lg_priv` | Sudoers file/directory changes | Yes, exact temporary probe matched |
| `lg_ssh` | SSH config and SSH-directory changes | Yes, collector-user directory probe matched |
| `lg_persist` | Cron and systemd configuration changes | Yes, cron-directory probe matched |
| `lg_shadow_read` | Shadow-file reads | Yes |

`USER_AUTH`, `USER_LOGIN`, `USER_CMD`, and `USER_START` records were also observed.
When checking rule firing, count actual `type=SYSCALL` records with the key.
`CONFIG_CHANGE` records created while installing a rule are not proof that its
watched activity has been captured. The presence of b32 rules also does not prove
that a 32-bit program has been tested.

Collection, batch normalization, SQLite storage, and the collect → parse → store
pipeline are implemented. SQLite has events, alerts, evidence links and a features
table, indexed queries, and replay-safe ingestion. A later cumulative group updates
the same event ID; stale shorter groups cannot erase evidence. Divergent evidence
rolls back the batch. Host, canonical UTC timestamp and serial form event identity.
Raw bytes and the complete normalized JSON are retained. Identical alert replay
reuses its ID and retains investigation status. No detector generates alerts yet.

The frozen real capture was ingested into a local database: 1,151 rows on the first
run, then zero new bytes, zero inserted/updated rows, and 1,151 unchanged rows.
`/usr/bin/sqlite3` reported `integrity_check = ok` and no foreign-key violations.
Live SSH pipeline ingestion also succeeded. Use separate databases for independent
snapshot runs. Streaming completion and wider timeline correlation remain pending.
The new scripted interval is in `code/data/linuxguard.db` as 508 events; see section 8.

There is no validated ML baseline, scenario dataset, trained model, dashboard, or
evaluation output yet. The whole audit log includes setup and SSH checks; do not
label it as a clean training baseline. Detection, ML, reports, dashboard and
evaluation modules remain placeholders. Historical key verification covers the
listed probes, not every watched path or possible action.

There are 140 passing local tests: the earlier 83, 27 rule-engine, seven scenario-runner,
nine Phase 7 feature/ML/evaluation tests, and seven Phase 8 storage/report/dashboard tests. The rule tests use synthetic, clearly labelled audit
fixtures; the scenario tests invoke no privileged action. They cover rotations, copy-truncate, missing archives,
partial lines, cursor/capture corruption, SSH failures, safe remote argument passing,
enriched records, fragmented arguments, identities, paths, malformed input, replay,
late-group updates, transactional evidence links, timestamp bounds, conflicting
evidence rollback, failed database recovery and preservation of sample inputs. The
privileged install was verified separately through the user's successful VM run;
unit tests do not simulate a full privileged install.

Reproduce local checks from `code/`:

```bash
uv sync --locked --inexact
uv run --locked --inexact python -m linuxguard check-config
uv run --locked --inexact pytest
```

`--inexact` preserves unrelated packages already in the existing environment.
Raw captures and generated artifacts are ignored by Git; keep that boundary.

## 6. Collector/parser commands and operational limits

Run from `code/`, with the verified SSH agent available:

```bash
uv run --locked --inexact python -m linuxguard collect --output data/captures/live-development.audit --state data/live-development-state.json
uv run --locked --inexact python -m linuxguard parse --file data/captures/live-development.audit --output data/captures/live-development.events.jsonl --host linuxguard-target --passwd-file data/captures/target-passwd
```

`data/captures/target-passwd` is the captured guest `/etc/passwd` for UID names. To
refresh it, use SCP against the same target. Do not resolve guest UIDs against the
host's `pwd` database. The parser uses enriched identity names when available and
otherwise retains numeric IDs if no target mapping is supplied.

Local replay uses its own cursor/output pair:

```bash
uv run --locked --inexact python -m linuxguard collect --file data/captures/setup-and-probes.audit --output data/captures/replay-check.audit --state data/replay-check-state.json
```

Do not mix sources or outputs under one cursor. Run only one collector per pair.
The reader keeps partial physical lines for the next poll and follows retained
numbered rotations. It reports missing rotation data or changed state/capture as
errors. Preserve failed captures and cursors; use a fresh pair to replay/recover
instead of deleting evidence or resetting offsets silently. A stop after raw data
is flushed but before state is committed is detected as a size mismatch on resume.
Compressed archives and multiple concurrent collectors are not supported.

The parser is a batch view of the cumulative raw capture. It groups by host,
timestamp and serial, preserves all raw records and PATH entries, and rewrites its
JSONL output atomically. It does not determine end-of-event completion for the
latest live group; collect and reparse once that event has settled. Do not present
this as an online detection pipeline until streaming completion and detection are added.

Local ignored development artifacts:

- `code/data/captures/setup-and-probes.audit`: frozen mixed capture for parser development.
- `code/data/captures/setup-and-probes.metadata.json`: provenance and probe IDs.
- `code/data/captures/setup-and-probes.events.jsonl`: its normalized view.
- `code/data/captures/target-passwd`: target UID mapping.
- `code/data/captures/live-development.audit` and matching JSONL: cumulative SSH capture.
- `code/data/live-development-state.json`: its live cursor; preserve it with the raw capture.
- `code/data/captures/replay-check.audit` and `code/data/replay-check-state.json`: local replay check.

These files are not shared through Git. Another checkout may need new captures,
not newly generated credentials or reinstallation of an already configured VM.

## 7. What to do next

1. Reconnect with the existing agent and verify current access. Audit installation,
   deliberate key-trigger checks, and `rules-loaded` snapshot creation are complete;
   do not ask the user to repeat them simply because this is a new session.
2. The user authorized agents to automate normal VM activity; they do not have to
   operate the VM manually for every benign sample. `scripts/benign-workload.py`
   runs a bounded, unprivileged workload and records a real command/timestamp/result
   manifest. `scripts/extract-benign-sample.py` selects whole groups by its interval,
   retains the original capture, and writes hash/provenance metadata. A scripted
   benign workload must be identified as such, not presented as representative human
   behaviour or a validated ML baseline. Review actual logs and background activity.
   Human-use intervals remain useful and optional; obtain VM UTC start/end times
   and an activity description when collecting them.
   The first scripted sample is captured and reviewed (section 8). Do not repeat
   the interval just to reconnect. The user supplied the post-capture kernel status
   check: `enabled 1`, `lost 0`, `backlog 0` (section 8). Do not request this same
   completed check again. Representativeness for a broader ML baseline remains
   pending; no validated ML baseline is claimed.
3. Phases 5 and 6 and their real replay verification are complete (section 9).
   Detection has a settle horizon; do not feed partially observed live groups into it
   without `--settled`, which is only for finished offline captures.
4. Continue with ML, dashboard/reports, independently
   labelled scenarios, and the rules-only versus rules-plus-ML evaluation. The
   proposal's main contribution is the measured comparison; AI is optional.
5. For future root changes or a fresh kernel-status check, prepare the command and
   have the user run it interactively. No passwordless sudo was added. For example:

   ```bash
   ssh -t lg 'sudo auditctl -s'
   ```

   Expect `enabled 1` and `lost 0`. Investigate any lost records before treating a
   capture as complete. Reverting `rules-loaded` later also reverts guest audit logs;
   keep dataset/cursor pairs distinct across independent snapshot runs.

## 8. Scripted development capture — 2026-11-28

The current agent socket was supplied by the user and its key fingerprint matched.
Fresh SSH verified `linuxguard-target`, user `bonzo`, `adm` membership, active
auditd, readable logs, and about 21 GB free. No privileged configuration changed.

The versioned workload script was uploaded to
`/home/bonzo/linuxguard-setup/benign-workload.py`; local and remote SHA-256 matched:
`9a5c507561001709195481cb8b697e35e9098ddcb2d431a760af8bb797f93f01`.
Its manifest and generated files remain on the VM at
`/home/bonzo/linuxguard-workloads/benign-t96w3zj8/`.

- VM UTC interval: `2026-11-27T20:56:30.120328Z` to `2026-11-27T21:11:30.146051Z`
  (2026-11-28, about 01:56–02:11 Asia/Karachi).
- 94 commands completed successfully over 900 seconds: file/text tools, searching,
  copying/comparing, archiving and Python compilation/assertions. No probes or attacks.
- Interval extraction retained 2,544 records / 508 whole groups, with zero malformed
  lines. Groups were unchanged across two post-run captures separated by at least
  ten seconds. All 224 groups containing EXECVE reconstruct complete arguments.
- Background login/service and SSH collection activity is also present. All 127
  failed events are SYSCALL `exit=-2` (ENOENT), consistent with executable lookup;
  no failed authentication events were observed. Shadow reads came from login,
  unix_chkpwd and sshd-session; mode records came from login and systemd-logind.
  This is a scripted development sample with background activity, not a broad human
  workload or an ML training baseline.
- `code/data/linuxguard.db` has 508 events and zero generated alerts. Repeat replay
  collected zero bytes and inserted/updated zero rows. Integrity and foreign-key
  checks passed; all stored raw groups match original source bytes independently.

Local ignored run directory: `code/data/captures/scripted-benign-20261128/`.
It contains the frozen `full.audit` and `collector-state.json`, `manifest.json`,
`workload-output.jsonl`, `target-passwd`, `sample.audit`, `sample.metadata.json`,
`sample.events.jsonl`, `verification.json`, and a separate sample replay/cursor pair.
It also holds the 1,151-event frozen setup replay database and a mixed live
development database. Preserve these pairs. The interval's metadata hashes refer
to the frozen cumulative capture; do not resume appending to it when collecting a
different interval—use a new pair.

Reproduce the sample database replay from `code/`:

```bash
uv run --locked --inexact python -m linuxguard pipeline --file data/captures/scripted-benign-20261128/sample.audit --output data/captures/scripted-benign-20261128/sample-replay.audit --state data/captures/scripted-benign-20261128/sample-replay-state.json --host linuxguard-target --passwd-file data/captures/scripted-benign-20261128/target-passwd
/usr/bin/sqlite3 data/linuxguard.db 'SELECT count(*) FROM events; PRAGMA integrity_check; PRAGMA foreign_key_check;'
```

**Completed:** the user ran the following read-only check in their host terminal
and supplied its output. The VM password was entered locally:

```bash
ssh -t lg 'date -u +%Y-%m-%dT%H:%M:%SZ; sudo auditctl -s'
```

The command printed `2026-11-27T21:16:31Z` (2026-11-28 02:16:31 Asia/Karachi),
then reported `enabled 1`, `failure 1`, `pid 763`, `rate_limit 0`,
`backlog_limit 8192`, `lost 0`, `backlog 0`, `backlog_wait_time 60000`,
`backlog_wait_time_actual 0`, and `loginuid_immutable 0 unlocked`.
Source: the user's pasted terminal output, not an unattended root query by the agent.
The full supplied status is preserved locally in the ignored run directory as
`audit-status.txt` and `audit-status.json`; sample and verification metadata link
to it. The post-capture audit-loss verification is complete. Phase 2 is complete
for this scripted development sample; continue Phase 6. The broader normal-only
ML baseline and assessment of representativeness remain pending in Phase 7.

Keep [the roadmap](../timeline/LinuxGuard_Roadmap.md), this handoff, and
[the setup guide](../code/README.md) consistent as work proceeds.

## 9. Phase 6 detection and Phase 9 scenarios — 2026-11-28

Phase 6 is implemented: `linuxguard/rules.py` (validated YAML format, single-event
`match` and sliding-window `threshold` detection, evidence-linked alerts), ten shipped
rules in `config/rules.yaml` (R01–R10), and `pipeline --detect [--settled]`.
`check-config` reports the rule count. Predicates read normalized fields and PATH
evidence; read/write intent comes from PATH nametypes and decoded open flags, and a
SUID bit from the chmod-family mode argument — never from an audit key or file mode
alone. File rules require `event_type: SYSCALL` and `success: true`.

Real replay used separate experiment databases and fresh capture/cursor pairs under
`code/data/experiments/phase6-rules-20261128/` (Git-ignored). The originals were
byte-identical before and after (sha256 of `sample.audit`, `setup-and-probes.audit`
and `data/linuxguard.db` unchanged):

- Scripted benign sample (508 events): **0 alerts**. Second replay collected 0 bytes,
  inserted/updated 0 rows, and raised 0 new alerts.
- Mixed `setup-and-probes` capture (1,151 events): exactly **2 alerts** — R03 and R08
  on the authorized trigger-verification probe files created in `/etc/sudoers.d` and
  `/etc/cron.d` (audit ids `1794741739.956:691` and `:695`). These are real creation
  events, true positives for "config file created", not false positives. The `.ssh`
  probe correctly did not match R09 (it is not an `authorized_keys` file). Integrity
  and foreign-key checks passed on both experiment databases.

Narrowed rules, by design: R06's "shell from /tmp" is covered by R07 (no parent-process
correlation); R10 fires on any successful SUID set because "on a new file" cannot be
established from one event. Known gaps: `sh /tmp/x.sh` (the script path is not an
execve PATH entry), openat paths relative to a dirfd, b32 syscall numbers decoded only
by the enriched `SYSCALL=` name or the small b64 number table, and
`/etc/ssh/sshd_config.d` (not watched).

Phase 9: `scenarios/run.py` generates labelled benign and malicious telemetry; it runs
only as root on the VM, every action is inert, reversible and loopback-only, and labels
come from the catalogue, not a detector. Host-side tests cover the catalogue and
`--list` without any privileged action. Repeated-failed-authentication scenarios
(R04/R05) are deferred because the VM has no user-creation tool and no `sshpass`; those
rules are covered by synthetic tests and the real mistyped logins in the setup capture.

**Development run — 2026-11-28 (run_id `20261127T220019-336bab`).** The user ran the
runner once on the VM with their sudo password (`--repeats 1 --gap 3`); 21 scenarios,
clean teardown, `auditctl -s` reported `enabled 1` / `lost 0` before and after. Two
collector bugs were fixed first: `sh()` forced `capture_output` (broke the two
read-to-/dev/null scenarios; a regression test was added) and `mal_tmp_exec` ran the
script via `/bin/sh script` instead of executing it directly.

The interval was collected over the unprivileged agent into a Git-ignored experiment
database (`code/data/experiments/scenario-dev-<run_id>/`) and detected with
`pipeline --detect --settled`. Alerts were attributed to the nearest scenario start
(audit timestamps land a few ms before the Python-recorded `start_ts`, so boundary
matching at a 3 s gap mis-assigns; scenarios are 3 s apart and finish in <1 s, so
nearest-start is unambiguous). Result after the fixes below: **9 of 9 rule-targeted
malicious scenarios fired their rule (R01, R02, R03, R06×2, R07, R08, R09, R10), zero
benign false positives across the ten benign scenarios, and both ML-only scenarios were
correctly silent.** Integrity and foreign-key checks passed.

The initial run's one miss was MAL-TMPEXEC (R07): the scenario ran `/bin/sh /dev/shm/script`, so the
execve recorded the interpreter `/usr/bin/dash` with argv path `/bin/sh`, never the
script path — exactly the documented R07 gap (an interpreted script is not an execve
target). The scenario was corrected to execute the script directly (so `/dev/shm/...` is the
execve target); a confirmation run (`--only MAL-TMPEXEC`, run_id
`20261127T220711-952c87`) then fired R07 on `/dev/shm/lg-scenario.sh`, giving the 9/9
above. R07's unit test already covers a `/dev/shm` path as evidence.

The 10× evaluation runs remain for later, after the rules are frozen and Phase 7 exists,
so test data never tunes the rules. Experiment databases and collected captures stay
Git-ignored; the catalogue, runner and labels format are the tracked artifacts.

## 10. Phase 7 ML + evaluation code — 2026-11-28

Phase 7 code is implemented and unit-tested (no VM needed): `linuxguard/features.py`
(fixed per-user windows aligned to epoch boundaries; counts/ratios incl. never-seen exes
and temp-dir execs), `linuxguard/ml.py` (`train` → scaler + IsolationForest with the `ml`
config, threshold at `threshold_percentile` of baseline scores; `score` inserts
`source='ml'` alerts — "unusual activity", anomaly score, top features, evidence links;
same settle horizon and replay-idempotence as rules; refuses <20 baseline windows), the
`train` CLI command, `pipeline --model`, and `eval/evaluate.py` (A=rules vs B=rules+ML,
nearest-start matching, precision/recall/FPR/latency + per-scenario table). 134 tests pass.

**Honest limitation:** model quality depends entirely on a rich, representative baseline.
On a thin/uniform baseline the detector flags ordinary small windows and misses real
anomalies (observed in a CLI smoke run). The unit test uses a varied 60-window baseline
where a concentrated attack burst scores lowest; that is the behaviour to expect only with
a good baseline.

**Baseline collected and model trained — 2026-11-28.** The scripted workload
(`benign-workload.py --duration 3600`) ran its full 3600 s of active time but spanned
22:27:28Z→06:11:02Z wall-clock because the host was **suspended** partway through
(`time.monotonic()` does not advance during suspend); status `completed`, 301 steps. The
workload interval was extracted (whole groups) with `extract-benign-sample.py` — **786
events / 4372 records**, sha256 `5ae397b8eaff0a8fa9eb60f53eb64e9f77902179ad49b9c0978f26f9a10c2602` — which excludes the earlier malicious scenario runs
(22:00-22:07Z). Ingested into `data/experiments/baseline-20261128/baseline.db` and trained:
**59 windows** (54 bonzo, 4 root, 1 unknown), threshold **-0.2718**, saved to
`data/model.joblib` (PROVISIONAL: scripted file/text/python activity only, 59 windows — a
modest first baseline). Still owed: a user `sudo auditctl -s` to confirm `lost 0` across the
suspend; collect more varied/longer normal activity before any final model.

**Remaining data steps (staged; user runs the VM parts, agent collects over the socket):**

1. ~~Normal-only baseline~~ **done (above).** To improve it later, run the scripted workload again on the VM:
   `ssh lg 'nohup python3 /home/bonzo/linuxguard-setup/benign-workload.py --duration 7200 >/tmp/lg-baseline.out 2>&1 &'`
   (upload `scripts/benign-workload.py` first if not staged). When done, collect over the
   agent into `data/experiments/baseline-<date>/baseline.db` (pipeline, no `--detect`) and
   `train --database … --model data/model.joblib`. The scripted workload is limited variety;
   note it. A user-supplied `auditctl -s` (`lost 0`) confirms no drops.
2. **10× scenario test capture (one sudo run).**
   `ssh -t lg 'sudo python3 /home/bonzo/linuxguard-setup/scenario-run.py --repeats 10 --gap 10'`
   (~45-70 min). Copy `labels.csv`, collect the interval into `test.db`, run
   `pipeline --file … --detect --settled --model data/model.joblib`.
3. **Evaluate A vs B:** `python3 eval/evaluate.py --test-db test.db --labels …/labels.csv`;
   record precision/recall/FPR/latency and the per-scenario table honestly.

The model (`data/model.joblib`) and all captures stay Git-ignored; record provenance
(hashes, window counts, UTC interval, threshold) here when the runs land.

## 11. Phase 8 dashboard + reports — 2026-11-28

Implemented, local-only (reads the SQLite evidence DB; no VM, no AI): three EvidenceStore
helpers (`list_alerts` with filters, `set_alert_status`, `related_events` basic correlation
on pid/ppid/user/src_ip within +/-N min, plus `get_alert`); `linuxguard/reports.py`
`incident_markdown` (standard-mode report, AI fallback); and `linuxguard/dashboard/app.py`
(Streamlit: Overview, Alerts with status-setting + timeline + raw evidence + report download,
Evaluation). `streamlit run linuxguard/dashboard/app.py`. FastAPI skipped. 133 tests pass
(new: storage, reports, and a headless `streamlit.testing` smoke test). The Evaluation page
populates once the 10× `test.db` + `labels.csv` exist.

## 12. Phase 9 10x capture + Phase 10 A/B evaluation — 2026-11-28

The 10x labelled scenario run completed (run_id `20261128T072137-d905c5`): **210 runs**
(110 malicious, 100 benign across 21 scenarios x 10 repetitions). `auditctl -s` reported
`enabled 1` / `lost 0` **before and after** (from `run.json`), so no records were dropped.
The scenario interval (+/-120 s margin) was collected over the unprivileged agent (3,029
events), ingested into a Git-ignored `test.db`, and scored with rules + the provisional ML
model: 107 rule alerts, 21 ML alerts; integrity ok. `evaluate.py` was fixed to score each
scenario *run* (keyed by scenario_id + repetition) rather than collapsing repetitions.

**A (rules only) vs B (rules + ML), per scenario run:**

| Config | Precision | Recall | FPR | TP | FP | FN | latency med/max |
|---|---|---|---|---|---|---|---|
| A rules | 1.00 | 0.80 | 0.00 | 88 | 0 | 22 | 0.0 / 0.5 s |
| B rules+ML | 0.89 | 0.82 | 0.11 | 90 | 11 | 20 | 0.0 / 3.3 s |

Rules caught every rule-targeted scenario (R01 shadow 9/10, R09 authkeys 9/10, the other
seven 10/10) with **zero false positives**, and missed the two ML-only scenarios
(ML-ENUM, ML-BINBURST) entirely — the 22 false negatives. Adding ML recovered only **2 of
those 20 ML-target runs** (ENUM 1/10, BINBURST 1/10) while introducing **11 benign false
positives** (notably BEN-FIND 4/10), dropping precision 1.00 -> 0.89 and raising FPR to 0.11.

**Honest conclusion (proposal 10.7):** on this provisional, thin, scripted baseline ML did
**not** clearly help — rules alone gave perfect precision at 0.80 recall, and ML traded a lot
of precision for marginal recall. A richer/longer normal-only baseline (Phase 7.2) may change
this and should be collected before drawing final conclusions; the numbers above are reported
as-is, not tuned. Metrics JSON: `data/experiments/scenario-10x-.../evaluation.json` (ignored).

Still pending for a full Phase 10: resource-use sampling (10.4), an ML threshold sweep
(7.6/10.6), and the written results chapter/charts (Phase 12).

## 13. Phase 12 report + remaining metrics — 2026-11-28

Final technical report delivered as **`docs/REPORT.md`** (source of truth) and
**`docs/LinuxGuard_Report_Group17.docx`** (submittable), with a committed architecture diagram
(`docs/figures/architecture.svg/.png`) and result figures (`metrics_ab`, `per_scenario`,
`threshold_sweep`). The two previously-missing proposal metrics were measured and added:

- **Resource consumption:** host pipeline on the 3,029-event capture ~1.7 s (parse 0.25 / store
  0.10 / rules 1.11 / ML 0.27), peak ~256 MiB RSS (mostly sklearn/NumPy import); train 0.12 s on
  59 windows; VM auditd ~2.3 MiB at ~0% CPU; test.db 13 MiB, baseline.db 3.3 MiB, model 0.6 MiB.
- **ML threshold sweep** (`eval/sweep.py`): recall flat at 0.82 across baseline percentiles
  0.5–10 %; precision 0.89→0.83, FPR 0.11→0.19 — no threshold makes ML worthwhile.

New code: `ml.window_scores` (shared by `score` and the sweep), `eval/sweep.py`,
`eval/make_figures.py`; `code/requirements.txt` exported from `uv.lock`. 135 tests pass.
Figures regenerate with `python eval/make_figures.py`; the DOCX rebuilds from a docx-js script
(scratch) — re-run if `REPORT.md` changes. Report authored in the students' voice (no AI
self-attribution inside the document). Remaining optional work: Phase 11 AI explanations and a
richer ML baseline.

## 14. Phase 11 AI explanations (local Ollama/Gemma) — 2026-11-28

Implemented `linuxguard/ai.py`: `explain(alert, evidence, *, mode, model, endpoint, timeout) ->
(text, mode_used)`. Modes: `standard` (local template, default + fallback), `local` (Ollama),
`cloud` (disabled). Uses the standard library (urllib) — no new dependency; the `local-ai` extra
stays unused. Strict prompt (explain only from evidence, say "unknown", never suggest commands).
Wired into `reports.incident_markdown(..., explanation=...)`, the dashboard alert view (radio
standard/local + "produced by" badge), and a new CLI `explain` command. Config gained `ai.model`
and `ai.endpoint`; `timeout_seconds` raised to 120. Default `ai.mode` stays `standard` so a
fresh checkout and the test suite never need Ollama. 140 tests pass (AI tests mock the model; a
live test runs only with `LINUXGUARD_OLLAMA_TEST=1`).

**Gotcha found and fixed:** the installed model `igorls/gemma-4-12B-it-heretic-GGUF:Q4_K_M` is a
*thinking* model — it spent its token budget on hidden reasoning (`done_reason: length`) and
returned an empty `response`. The client now sends `think:false` and falls back to the `thinking`
field if `response` is empty.

**Assessment (11.6), real alerts from the 10x test.db, model `…gemma-4-12B…`:**
- Alert 1 (rule R01, shadow read): local output — "bonzo used cat to open /etc/shadow … shadow
  file contains sensitive password hashes and is typically only accessed by privileged
  processes." Clear, accurate, grounded; no invented facts, no commands.
- Alert 108 (ML, unusual window): local output — summarised the window's tar/gzip/shell execs and
  the sshd shadow read as unusual activity with an anomaly score. Consistent with the evidence.
- Latency: ~37 s first call (model load), ~5 s after.
- Fallback verified two ways: unreachable endpoint and empty model response both return the
  template with mode "standard (fallback)"; detection/evaluation output is unchanged with AI on
  or off. Local only (localhost) — no data leaves the host; cloud mode intentionally off.
