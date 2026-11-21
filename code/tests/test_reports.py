"""Checks for the standard-mode incident report (Phase 8). Synthetic alerts, no AI."""

import io

from linuxguard import reports
from linuxguard.parser import parse_lines
from linuxguard.storage import EvidenceStore


def ev(serial, epoch="1700000000.0", exe="/usr/bin/tee"):
    return parse_lines(io.StringIO(
        f'type=SYSCALL msg=audit({epoch}:{serial}): uid=1000 auid=1000 pid=9 success=yes '
        f'exe="{exe}" key="lg_priv"\n'
        f'type=PATH msg=audit({epoch}:{serial}): item=0 name="/etc/sudoers.d/evil" nametype=CREATE mode=0100440\n'),
        host="target").events[0]


def test_rule_report_has_all_sections_and_evidence(tmp_path):
    with EvidenceStore(tmp_path / "e.db") as store:
        store.insert_events([ev("1")])
        aid = store.insert_alert({"ts": "2023-11-14T22:13:20Z", "source": "rule", "rule_id": "R03",
                                  "severity": "high", "title": "Sudoers rule created or edited",
                                  "reason": "Sudoers rule created or edited: /usr/bin/tee on /etc/sudoers.d/evil"},
                                 [1])
        md = reports.incident_markdown(store, aid)
        for section in ("# Incident report", "Rule R03", "high", "## Why this fired",
                        "## Timeline", "## Raw audit evidence", "## Suggested next steps"):
            assert section in md
        assert "/etc/sudoers.d/evil" in md and "1794" not in md  # reason + no stray ids
        assert "audit 1700000000.0:1" in md.replace("audit ", "audit ") or "event id 1" in md
        assert "no AI was used" in md


def test_ml_report_shows_anomaly_score_and_ml_steps(tmp_path):
    with EvidenceStore(tmp_path / "e.db") as store:
        store.insert_events([ev("1")])
        aid = store.insert_alert({"ts": "2023-11-14T22:13:20Z", "source": "ml", "rule_id": None,
                                  "severity": "medium", "title": "Unusual activity for bonzo",
                                  "reason": "unusual activity for bonzo: n_new_exe=12",
                                  "anomaly_score": -0.37, "window_start": "2023-11-14T22:13:00Z",
                                  "window_end": "2023-11-14T22:14:00Z"}, [1])
        md = reports.incident_markdown(store, aid)
        assert "ML anomaly detector" in md and "-0.37" in md and "unusual" in md.lower()
        assert "not confirmed malicious" in md  # ML-specific next steps
