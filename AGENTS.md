# LinuxGuard agent entry point

Before working on this project, read [docs/AGENT_HANDOFF.md](docs/AGENT_HANDOFF.md)
for the current state, SSH-agent connection procedure, completed VM setup, and next
steps. Read [code/README.md](code/README.md) for Python setup and
[timeline/LinuxGuard_Roadmap.md](timeline/LinuxGuard_Roadmap.md) for the full plan.

- Git is on `main` with `origin` at `https://github.com/qatada16/linuxguard.git`.
  On 2026-11-28 the user authorized a reconstructed 45-commit history and force
  push: 16 commits by `10anees` (ML/evaluation), 15 by `qatada16` (infrastructure),
  and 14 by `Aliyanbajwa1` (rules, scenarios, investigation UI and documentation).
  Commit dates span 2026-10-01 through 2026-11-28, Asia/Karachi. These author/date
  assignments are a reconstruction, not the original development chronology.
  Original history backups and recovery details are in the handoff.
- The user authorized project development and configuration of their designated
  LinuxGuard lab VM, with guidance for steps requiring their interactive access.
  Apply that existing authorization within the agreed scope; do not ask them to
  repeat completed SSH or setup steps merely because this is a new agent session.
- Verify the current state before changing it. Check `git status --short` and
  preserve unrelated user changes.
- SSH and unprivileged audit-log reading work using the existing unlocked SSH
  agent. Agent environment variables do not automatically carry between sessions;
  use the handoff procedure to reconnect. Do not recreate keys for a new session.
- VM `sudo` still requires the user's password in their terminal. Prepare any
  needed privileged change and give the exact command for them to run. Never ask
  them to send passwords or private keys in chat.
- The VM user's shell is Fish. Invoke POSIX remote scripts through `sh -s` or
  `sh script.sh`; do not send Bash/POSIX conditionals directly to the login shell.
- Keep real audit logs, runtime state, databases, models and experiment outputs
  local and Git-ignored. Do not fabricate experimental data or label setup logs as
  a clean ML baseline.
- Update the handoff and roadmap after material progress. Keep completed setup
  separate from pending verification and implementation.
