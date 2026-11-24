from linuxguard.collection.audit_parser import (
    AuditEventAssembler,
    decode_field_value,
    iter_audit_events,
    parse_audit_line,
)
from linuxguard.collection.sources import read_lines


def test_parses_syscall_record_fields() -> None:
    record = parse_audit_line(
        'type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes pid=10 comm="cat" '
        'exe="/usr/bin/cat" key="lg_exec"'
    )
    assert record is not None
    assert record.record_type == "SYSCALL"
    assert record.timestamp == 1700000000.123
    assert record.serial == 456
    assert record.fields["syscall"] == "59"
    assert record.fields["exe"] == "/usr/bin/cat"
    assert record.fields["key"] == "lg_exec"


def test_decodes_hex_encoded_execve_arguments_and_proctitle() -> None:
    execve = parse_audit_line('type=EXECVE msg=audit(1.000:1): argc=2 a0="cat" a1=2F746D702F612062')
    proctitle = parse_audit_line("type=PROCTITLE msg=audit(1.000:1): proctitle=636174002F6574632F736861646F77")
    assert execve.fields["a1"] == "/tmp/a b"
    assert proctitle.fields["proctitle"] == "cat /etc/shadow"


def test_does_not_decode_numeric_syscall_arguments() -> None:
    record = parse_audit_line("type=SYSCALL msg=audit(1.000:1): a0=ffffff9c a1=7ffd a2=241")
    assert record.fields["a0"] == "ffffff9c"
    assert record.fields["a2"] == "241"


def test_flattens_nested_user_message() -> None:
    record = parse_audit_line(
        "type=USER_AUTH msg=audit(1.500:2): pid=1 uid=0 auid=4294967295 ses=4294967295 "
        'msg=\'op=PAM:authentication acct="root" exe="/usr/sbin/sshd" addr=203.0.113.7 res=failed\''
    )
    assert record.fields["acct"] == "root"
    assert record.fields["addr"] == "203.0.113.7"
    assert record.fields["res"] == "failed"
    assert record.fields["pid"] == "1"


def test_parses_enriched_format_and_node_prefix() -> None:
    record = parse_audit_line(
        "node=web01 type=DAEMON_START msg=audit(2.000:3): op=start auid=4294967295 res=success"
        '\x1dAUID="unset" UID="root"'
    )
    assert record.node == "web01"
    assert record.enrichment == {"AUID": "unset", "UID": "root"}
    assert "\x1d" not in record.raw


def test_rejects_lines_that_are_not_audit_records() -> None:
    assert parse_audit_line("random text") is None
    assert parse_audit_line("") is None


def test_quoted_values_are_never_hex_decoded() -> None:
    assert decode_field_value("PATH", "name", '"2F746D70"') == "2F746D70"
    assert decode_field_value("PATH", "name", "2F746D70") == "/tmp"
    assert decode_field_value("PATH", "name", "(null)") == "(null)"


def test_assembles_multi_record_event_until_eoe() -> None:
    assembler = AuditEventAssembler()
    lines = [
        'type=SYSCALL msg=audit(1.000:7): syscall=59 exe="/usr/bin/ls"',
        'type=EXECVE msg=audit(1.000:7): argc=1 a0="ls"',
        "type=EOE msg=audit(1.000:7): ",
    ]
    completed = []
    for line in lines:
        completed.extend(assembler.feed(parse_audit_line(line)))
    assert len(completed) == 1
    assert [record.record_type for record in completed[0].records] == ["SYSCALL", "EXECVE"]
    assert completed[0].record_id == "1.000:7"


def test_standalone_records_complete_immediately() -> None:
    assembler = AuditEventAssembler()
    completed = assembler.feed(parse_audit_line("type=USER_LOGIN msg=audit(1.000:8): pid=1 msg='op=login res=success'"))
    assert len(completed) == 1


def test_interleaved_events_are_grouped_by_serial() -> None:
    lines = [
        "type=SYSCALL msg=audit(1.000:10): syscall=59",
        "type=SYSCALL msg=audit(1.001:11): syscall=59",
        'type=EXECVE msg=audit(1.000:10): argc=1 a0="first"',
        'type=EXECVE msg=audit(1.001:11): argc=1 a0="second"',
        "type=EOE msg=audit(1.001:11): ",
        "type=EOE msg=audit(1.000:10): ",
    ]
    events = list(iter_audit_events(lines))
    arguments = {event.serial: event.first("EXECVE").fields["a0"] for event in events}
    assert arguments == {10: "first", 11: "second"}


def test_unterminated_events_are_flushed_at_end_of_stream() -> None:
    events = list(iter_audit_events(["type=SYSCALL msg=audit(1.000:12): syscall=59"]))
    assert len(events) == 1


def test_fixture_file_produces_expected_event_count(fixtures_directory) -> None:
    events = list(iter_audit_events(read_lines(fixtures_directory / "audit_sample.log")))
    assert len(events) == 9
