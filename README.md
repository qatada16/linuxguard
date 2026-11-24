# LinuxGuard

Machine learning-assisted Linux intrusion detection and investigation system.

LinuxGuard collects security events from the Linux audit subsystem and authentication logs, detects suspicious
behaviour with rules and Isolation Forest anomaly detection, stores alerts with their evidence and supports
investigation through timelines, incident reports and optional AI explanations.

Information Security semester project, FAST-NUCES Lahore (Group 17).

## Development

```bash
pip install -e ".[dev]"
pytest
```
