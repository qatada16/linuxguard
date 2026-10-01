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

Work stays in this local repository. No remote or publishing service is required.
