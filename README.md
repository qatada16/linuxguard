# LinuxGuard

Group 17's Information Security project: Linux Audit event collection, rule-based
and Isolation Forest detection, and evidence-based investigation.

- [Development setup and next steps](code/README.md)
- [Agent handoff and complete VM access procedure](docs/AGENT_HANDOFF.md)
- [Implementation roadmap](timeline/LinuxGuard_Roadmap.md)
- [Project proposal](Proposal/IS_Project_Proposal_Group17.pdf)

The foundation is implemented: Python packaging, locked dependencies, configuration
validation, tests, and local Git. VM audit rules and unprivileged log-reading access
are configured and verified, and the `rules-loaded` snapshot exists. Incremental
SSH/local-file collection and batch audit normalization are implemented. Storage,
detection, dashboard, and evaluation modules are still placeholders.

Repository: [qatada16/linuxguard](https://github.com/qatada16/linuxguard).

The Git history was reconstructed at the maintainer's request on 2026-11-28:
45 commits with assigned authors and dates spanning 2026-10-01–2026-11-28.
It is not the original development chronology. Recovery information is in the
[agent handoff](docs/AGENT_HANDOFF.md). Real captures, databases and models remain local.
