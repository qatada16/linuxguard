import pytest

from linuxguard.detection.anomaly import IsolationForestDetector
from linuxguard.detection.pipeline import (
    DetectionMode,
    DetectionPipeline,
    anomaly_severity,
    limit_evidence,
)
from linuxguard.detection.rules import RuleEngine, parse_rule
from linuxguard.domain.alerts import AlertStatus, DetectorType, Severity
from linuxguard.domain.events import EventCategory, Outcome, SecurityEvent
from linuxguard.storage.repository import EvidenceStore
from tests.helpers import routine_windows, scan_window

TEMP_RULE = parse_rule(
    {
        "id": "T-1",
        "name": "Temporary execution",
        "description": "Execution from /tmp.",
        "severity": "high",
        "technique": "T1204",
        "match": {"executable": {"prefix": "/tmp/"}},
    }
)
BRUTE_RULE = parse_rule(
    {
        "id": "T-2",
        "name": "Brute force",
        "match": {"category": "authentication", "outcome": "failure"},
        "threshold": {"count": 2, "window_seconds": 60, "group_by": ["session_id"]},
    }
)


def test_rule_alert_carries_rule_metadata(make_event) -> None:
    pipeline = DetectionPipeline(RuleEngine([TEMP_RULE]))
    alerts = pipeline.process(make_event(executable="/tmp/payload"))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == DetectorType.RULE
    assert alert.rule_id == "T-1"
    assert alert.severity == Severity.HIGH
    assert alert.technique == "T1204"
    assert alert.entity == "alice"
    assert pipeline.flush() == []


def test_session_grouped_alerts_name_the_user(make_event) -> None:
    pipeline = DetectionPipeline(RuleEngine([BRUTE_RULE]))
    failure = {"category": EventCategory.AUTHENTICATION, "outcome": Outcome.FAILURE, "session_id": "12"}
    pipeline.process(make_event(**failure))
    alerts = pipeline.process(make_event(**failure))
    assert alerts[0].entity == "alice@session:12"


def test_hybrid_mode_requires_trained_detector() -> None:
    with pytest.raises(ValueError):
        DetectionPipeline(RuleEngine([]), None, DetectionMode.HYBRID)
    with pytest.raises(ValueError):
        DetectionPipeline(RuleEngine([]), IsolationForestDetector(), DetectionMode.HYBRID)


def test_hybrid_pipeline_raises_anomaly_alerts(make_event) -> None:
    detector = IsolationForestDetector(n_estimators=50).fit(routine_windows(make_event))
    pipeline = DetectionPipeline(RuleEngine([TEMP_RULE]), detector, DetectionMode.HYBRID)
    alerts = pipeline.process_all(scan_window(make_event).events)
    anomalies = [alert for alert in alerts if alert.detector == DetectorType.ANOMALY]
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_score is not None
    assert anomalies[0].severity.rank >= Severity.MEDIUM.rank
    assert "not a confirmed intrusion" in anomalies[0].description


def test_rules_mode_ignores_detector(make_event) -> None:
    detector = IsolationForestDetector(n_estimators=50).fit(routine_windows(make_event))
    pipeline = DetectionPipeline(RuleEngine([]), detector, DetectionMode.RULES)
    assert pipeline.process_all(scan_window(make_event).events) == []


def test_evidence_limit_keeps_head_and_tail(make_event) -> None:
    events = [make_event() for _ in range(10)]
    limited = limit_evidence(events, 4)
    assert limited == events[:2] + events[-2:]
    assert limit_evidence(events, 20) == events


def test_anomaly_severity_bands() -> None:
    assert anomaly_severity(0.60, 0.60) == Severity.LOW
    assert anomaly_severity(0.64, 0.60) == Severity.MEDIUM
    assert anomaly_severity(0.70, 0.60) == Severity.HIGH


@pytest.fixture
def store(tmp_path):
    with EvidenceStore.open(tmp_path / "store.db") as opened:
        yield opened


def test_events_round_trip_and_are_idempotent(store, make_event) -> None:
    event = make_event(details={"paths": ["/a", "/b"]}, file_mode=0o755, dest_port=22)
    assert store.save_events([event]) == 1
    assert store.save_events([event]) == 0
    restored = store.events_between(0, 2e9)[0]
    assert isinstance(restored, SecurityEvent)
    assert restored.to_dict() == event.to_dict()


def test_alerts_round_trip_with_evidence_and_filters(store, make_event) -> None:
    pipeline = DetectionPipeline(RuleEngine([TEMP_RULE]))
    first = pipeline.process(make_event(timestamp=10, executable="/tmp/a", correlation_id="c1"))[0]
    second = pipeline.process(make_event(timestamp=500, executable="/tmp/b", correlation_id="c2"))[0]
    store.save_alerts([first, second])
    restored = store.get_alert(first.alert_id)
    assert restored.title == first.title
    assert restored.evidence_ids == first.evidence_ids
    assert [alert.alert_id for alert in store.list_alerts()] == [second.alert_id, first.alert_id]
    assert store.list_alerts(severity="low") == []
    assert len(store.list_alerts(detector="rule", since=100)) == 1
    assert store.get_alert("missing") is None


def test_status_and_explanation_updates(store, make_event) -> None:
    alert = DetectionPipeline(RuleEngine([TEMP_RULE])).process(make_event(executable="/tmp/a"))[0]
    store.save_alert(alert)
    assert store.update_status(alert.alert_id, AlertStatus.FALSE_POSITIVE)
    assert store.save_explanation(alert.alert_id, "text", "template")
    assert not store.update_status("missing", AlertStatus.RESOLVED)
    restored = store.get_alert(alert.alert_id)
    assert restored.status == AlertStatus.FALSE_POSITIVE
    assert restored.explanation == "text"


def test_statistics_and_event_links(store, make_event) -> None:
    alert = DetectionPipeline(RuleEngine([TEMP_RULE])).process(make_event(executable="/tmp/a"))[0]
    store.save_events([make_event(), make_event()])
    store.save_alert(alert)
    statistics = store.statistics()
    assert statistics["events"] == 3
    assert statistics["alerts"] == 1
    assert statistics["by_severity"] == {"high": 1}
    links = store.alert_ids_for_events([alert.evidence[0].event_id, "unknown"])
    assert links == {alert.evidence[0].event_id: [alert.alert_id]}


def test_queries_are_parameterised(store, make_event) -> None:
    store.save_events([make_event(user="alice'; DROP TABLE events; --")])
    assert store.events_between(0, 2e9, users=["alice'; DROP TABLE events; --"])
    assert store.statistics()["events"] == 1


def test_anomaly_contributions_round_trip(store, make_event) -> None:
    detector = IsolationForestDetector(n_estimators=50).fit(routine_windows(make_event))
    pipeline = DetectionPipeline(RuleEngine([]), detector, DetectionMode.HYBRID)
    alert = next(item for item in pipeline.process_all(scan_window(make_event).events))
    store.save_alert(alert)
    restored = store.get_alert(alert.alert_id)
    assert restored.contributions == alert.contributions
    assert restored.anomaly_score == pytest.approx(alert.anomaly_score)
