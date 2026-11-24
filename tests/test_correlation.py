from linuxguard.domain.events import EventCategory, Outcome
from linuxguard.processing.correlation import CrossSourceDeduplicator, EventCorrelator, ProcessTable
from linuxguard.processing.stream import EventProcessor


def test_parent_executable_is_resolved_from_earlier_execution(make_event) -> None:
    correlator = EventCorrelator()
    parent = correlator.correlate(make_event(pid=100, executable="/usr/sbin/php-fpm8.3"))
    child = correlator.correlate(make_event(pid=101, ppid=100, executable="/usr/bin/dash"))
    assert parent.parent_executable is None
    assert child.parent_executable == "/usr/sbin/php-fpm8.3"


def test_correlation_identifier_prefers_session_then_remote_address(make_event) -> None:
    correlator = EventCorrelator()
    assert correlator.correlate(make_event(session_id="7")).correlation_id == "lab/session/7"
    remote = make_event(category=EventCategory.AUTHENTICATION, src_ip="203.0.113.7", user=None)
    assert correlator.correlate(remote).correlation_id == "lab/remote/203.0.113.7"
    assert correlator.correlate(make_event(user="bob")).correlation_id == "lab/user/bob"


def test_duplicate_authentication_from_two_sources_is_merged(make_event) -> None:
    correlator = EventCorrelator(deduplication_window_seconds=2)
    audit = make_event(
        timestamp=100.0,
        category=EventCategory.AUTHENTICATION,
        outcome=Outcome.FAILURE,
        source="auditd",
        user="(invalid user)",
        src_ip="203.0.113.7",
    )
    syslog = make_event(
        timestamp=100.5,
        category=EventCategory.AUTHENTICATION,
        outcome=Outcome.FAILURE,
        source="authlog",
        user="oracle",
        src_ip="203.0.113.7",
        details={"method": "password"},
    )
    assert correlator.correlate(audit) is audit
    assert correlator.correlate(syslog) is None
    assert audit.user == "oracle"
    assert audit.details["method"] == "password"
    assert audit.details["corroborated_by"] == "authlog"


def test_deduplication_pairs_events_one_to_one(make_event) -> None:
    deduplicator = CrossSourceDeduplicator(window_seconds=2)
    events = [
        make_event(timestamp=10.0, category=EventCategory.AUTHENTICATION, source="auditd", src_ip="1.2.3.4"),
        make_event(timestamp=10.1, category=EventCategory.AUTHENTICATION, source="auditd", src_ip="1.2.3.4"),
        make_event(timestamp=10.2, category=EventCategory.AUTHENTICATION, source="authlog", src_ip="1.2.3.4"),
        make_event(timestamp=10.3, category=EventCategory.AUTHENTICATION, source="authlog", src_ip="1.2.3.4"),
        make_event(timestamp=10.4, category=EventCategory.AUTHENTICATION, source="authlog", src_ip="1.2.3.4"),
    ]
    duplicates = [deduplicator.find_original(event) is not None for event in events]
    assert duplicates == [False, False, True, True, False]


def test_events_outside_window_or_category_are_not_deduplicated(make_event) -> None:
    deduplicator = CrossSourceDeduplicator(window_seconds=2)
    first = make_event(timestamp=10.0, category=EventCategory.AUTHENTICATION, source="auditd", src_ip="1.2.3.4")
    late = make_event(timestamp=15.0, category=EventCategory.AUTHENTICATION, source="authlog", src_ip="1.2.3.4")
    execution = make_event(timestamp=15.1, source="authlog")
    assert deduplicator.find_original(first) is None
    assert deduplicator.find_original(late) is None
    assert deduplicator.find_original(execution) is None


def test_account_changes_are_deduplicated_by_target_account(make_event) -> None:
    deduplicator = CrossSourceDeduplicator()
    audit = make_event(category=EventCategory.ACCOUNT_MANAGEMENT, source="auditd", target_user="eve", timestamp=1.0)
    syslog = make_event(
        category=EventCategory.ACCOUNT_MANAGEMENT, source="authlog", target_user="eve", user=None, timestamp=1.1
    )
    assert deduplicator.find_original(audit) is None
    assert deduplicator.find_original(syslog) is audit


def test_process_table_evicts_oldest_entries() -> None:
    table = ProcessTable(capacity=2)
    table.record("h", 1, "/a")
    table.record("h", 2, "/b")
    table.record("h", 3, "/c")
    assert table.executable_for("h", 1) is None
    assert table.executable_for("h", 3) == "/c"


def test_event_processor_merges_sources_in_time_order(fixtures_directory) -> None:
    processor = EventProcessor("lab", syslog_timezone="UTC")
    audit_lines = (fixtures_directory / "audit_sample.log").read_text().splitlines()
    auth_lines = (fixtures_directory / "auth_sample.log").read_text().splitlines()
    events = processor.process_batch(audit_lines, auth_lines)
    timestamps = [event.timestamp for event in events]
    assert timestamps == sorted(timestamps)
    remote_failures = [
        event for event in events if event.category == EventCategory.AUTHENTICATION and event.src_ip == "203.0.113.7"
    ]
    assert len(remote_failures) == 2
