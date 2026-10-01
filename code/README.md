# LinuxGuard development

The project foundation is ready. Collection, parsing, SQLite storage, detection,
dashboard, scenarios, and evaluation are still pending. Placeholder modules contain
docstrings only; they do not implement monitoring.

## Setup and checks

Run these commands on the **host**, from this `code/` directory. Python 3.12,
`uv`, Git, and the host's OpenSSH client are required. SQLite comes with Python.

```bash
uv sync --locked --inexact
uv run --locked --inexact python -m linuxguard check-config
uv run --locked --inexact pytest
```

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
config/                 Settings and future detection rules
linuxguard/config.py    Configuration loading and validation
linuxguard/__main__.py  check-config command
linuxguard/             Placeholder modules for the implementation phases
linuxguard/dashboard/  Future Streamlit dashboard
scenarios/              Future repeatable, labelled VM scenarios
eval/                   Future evaluation runner
tests/                  Foundation tests
tests/data/             Local audit captures (ignored by Git)
data/                   Local state, databases and models (ignored by Git)
```

## Next step: enable SSH access to the VM

Read-only checks during foundation setup confirmed:

- VM `debian13` is running at `192.168.122.164`.
- Snapshot `clean-install` exists.
- Non-interactive SSH as `bonzo` fails with `Permission denied (publickey,password)`.
- No `lg` SSH alias or public key file was found in the host user's `~/.ssh/`.

The remaining login step needs your VM account password in your own terminal.
Do not put passwords or private keys in the repository or chat.

1. On the **host**, create a dedicated key. Run this once; if a file already exists
   at the selected path, keep it rather than overwriting it.

   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_linuxguard -C linuxguard-local
   ```

2. Install its public key using your VM password:

   ```bash
   ssh-copy-id -i ~/.ssh/id_ed25519_linuxguard.pub bonzo@192.168.122.164
   ```

3. Add this block once to `~/.ssh/config` on the **host**:

   ```sshconfig
   Host lg
       HostName 192.168.122.164
       User bonzo
       IdentityFile ~/.ssh/id_ed25519_linuxguard
       IdentitiesOnly yes
   ```

   If the key has a passphrase, load it into your SSH agent with
   `ssh-add ~/.ssh/id_ed25519_linuxguard` before the next check. If no agent is
   running in your terminal, start one with `eval "$(ssh-agent -s)"` first.

4. Verify access without a password prompt:

   ```bash
   ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=5 lg 'hostname; id -un'
   ```

   Successful output should identify the Debian VM and user `bonzo`. Then check
   audit access:

   ```bash
   ssh -o BatchMode=yes lg 'systemctl is-active auditd; if test -r /var/log/audit/audit.log; then echo AUDIT_LOG_READABLE; else echo AUDIT_LOG_NOT_READABLE; fi'
   ```

   Share only the check output or error. If log access is denied, the next phase
   will configure it using your VM administrator access.

## What follows SSH setup

1. Inspect the VM's existing audit rules and paths, then install and verify the
   project rules without removing unrelated audit coverage.
2. Capture 15–20 minutes of ordinary VM activity and copy the raw log to
   `tests/data/sample_benign.log`.
3. Implement the collector and parser against that real log, followed by SQLite
   storage. Verify replay does not duplicate events.
4. Add tested detection rules, then ML, the dashboard, and labelled evaluation.

Use the [roadmap](../timeline/LinuxGuard_Roadmap.md) for the full later phases.
VM audit configuration has not been changed during foundation setup.

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
