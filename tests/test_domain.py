from linuxguard.domain import Alert, DetectorType, EventCategory, Outcome, SecurityEvent, Severity
from linuxguard.domain.alerts import format_number


def test_event_identifier_is_stable_and_source_specific(make_event) -> None:
    event = make_event(record_id="1.000:5")
    same = make_event(record_id="1.000:5")
    other_source = make_event(record_id="1.000:5", source="authlog")
    assert event.event_id == same.event_id
    assert event.event_id != other_source.event_id
    assert len(event.event_id) == 32


def test_event_serialisation_round_trip(make_event) -> None:
    event = make_event(details={"group": "sudo"}, outcome=Outcome.FAILURE)
    payload = event.to_dict()
    assert payload["category"] == "process_execution"
    assert payload["outcome"] == "failure"
    assert SecurityEvent.from_dict({**payload, "unknown": 1}) == event


def test_field_access_supports_details(make_event) -> None:
    event = make_event(details={"group": "sudo"})
    assert event.field_value("details.group") == "sudo"
    assert event.field_value("details.missing") is None
    assert event.field_value("user") == "alice"
    assert event.field_value("not_a_field") is None


def test_entity_falls_back_through_identities(make_event) -> None:
    assert make_event().entity == "alice"
    assert make_event(user=None, src_ip="203.0.113.7").entity == "203.0.113.7"
    assert make_event(user=None, effective_user=None).entity == "system"


def test_alert_defaults_and_severity_order(make_event) -> None:
    event = make_event(category=EventCategory.LOGIN)
    alert = Alert(DetectorType.RULE, "title", Severity.HIGH, "description", "alice", 1.0, 2.0, [event])
    assert alert.evidence_ids == [event.event_id]
    assert alert.status.value == "open"
    assert len(alert.alert_id) == 32
    assert Severity.LOW.rank < Severity.MEDIUM.rank < Severity.HIGH.rank < Severity.CRITICAL.rank


def test_number_formatting() -> None:
    assert format_number(3.0) == "3"
    assert format_number(7.33106) == "7.33"
