from datetime import UTC, datetime

import pytest

from linuxguard.collection.audit_parser import iter_audit_events
from linuxguard.collection.sources import read_lines
from linuxguard.collection.syslog_parser import SyslogParser
from linuxguard.domain.events import EventCategory, Outcome
from linuxguard.processing.audit_normalizer import AuditNormalizer, decode_socket_address
from linuxguard.processing.syscalls import is_write_open, resolve_syscall_name
from linuxguard.processing.syslog_normalizer import SyslogNormalizer
from linuxguard.processing.users import UserResolver, parse_identifier


@pytest.fixture
def audit_events(fixtures_directory):
    normalizer = AuditNormalizer("lab", UserResolver({1000: "alice"}))
    events = [
        normalizer.normalize(event) for event in iter_audit_events(read_lines(fixtures_directory / "audit_sample.log"))
    ]
    return [event for event in events if event is not None]


@pytest.fixture
def auth_events(fixtures_directory):
    parser = SyslogParser("UTC", reference_time=datetime(2023, 11, 15, tzinfo=UTC))
    normalizer = SyslogNormalizer()
    records = [parser.parse(line) for line in read_lines(fixtures_directory / "auth_sample.log")]
    return [event for event in (normalizer.normalize(record) for record in records if record) if event]


def test_execution_event_uses_execve_arguments(audit_events) -> None:
    execution = audit_events[0]
    assert execution.category == EventCategory.PROCESS_EXECUTION
    assert execution.command_line == "cat /etc/shadow"
    assert execution.user == "alice"
    assert execution.session_id == "3"
    assert execution.working_directory == "/home/alice"
    assert execution.target_path is None


def test_open_without_write_flags_is_a_file_access(audit_events) -> None:
    access = audit_events[1]
    assert access.category == EventCategory.FILE_ACCESS
    assert access.target_path == "/etc/shadow"
    assert access.effective_user == "root"
    assert access.audit_key == "lg_credentials"


def test_remote_authentication_failure(audit_events) -> None:
    failure = audit_events[2]
    assert failure.category == EventCategory.AUTHENTICATION
    assert failure.outcome == Outcome.FAILURE
    assert failure.user == "root"
    assert failure.src_ip == "203.0.113.7"


def test_nonblocking_connect_is_treated_as_success(audit_events) -> None:
    connection = audit_events[3]
    assert connection.category == EventCategory.NETWORK_CONNECTION
    assert (connection.dest_ip, connection.dest_port) == ("93.184.216.34", 443)
    assert connection.outcome == Outcome.SUCCESS


def test_sudo_command_is_hex_decoded(audit_events) -> None:
    command = audit_events[4]
    assert command.category == EventCategory.PRIVILEGE_ESCALATION
    assert command.command_line == "systemctl restart nginx"
    assert command.effective_user == "root"


def test_relative_path_is_resolved_and_mode_is_parsed(audit_events) -> None:
    chmod = audit_events[5]
    assert chmod.category == EventCategory.PERMISSION_CHANGE
    assert chmod.target_path == "/tmp/backdoor"
    assert chmod.file_mode == 0o4755


def test_audit_configuration_and_account_events(audit_events) -> None:
    configuration, account, daemon = audit_events[6], audit_events[7], audit_events[8]
    assert configuration.category == EventCategory.AUDIT_CONFIGURATION
    assert configuration.action == "remove_rule"
    assert configuration.outcome == Outcome.SUCCESS
    assert account.category == EventCategory.ACCOUNT_MANAGEMENT
    assert account.action == "add_user"
    assert account.target_user == "eve"
    assert daemon.action == "set_enable"
    assert daemon.outcome == Outcome.FAILURE


def test_event_identifiers_are_deterministic(fixtures_directory) -> None:
    normalizer = AuditNormalizer("lab")
    lines = list(read_lines(fixtures_directory / "audit_sample.log"))
    first = [normalizer.normalize(event).event_id for event in iter_audit_events(lines)]
    second = [normalizer.normalize(event).event_id for event in iter_audit_events(lines)]
    assert first == second
    assert len(set(first)) == len(first)


def test_socket_address_decoding_supports_ipv4_and_ipv6() -> None:
    assert decode_socket_address("0200005010000001" + "0" * 16) == ("16.0.0.1", 80)
    ipv6 = "0A00" + "01BB" + "00000000" + "20010DB8000000000000000000000001" + "00000000"
    assert decode_socket_address(ipv6) == ("2001:db8::1", 443)
    assert decode_socket_address("0100") is None
    assert decode_socket_address("zz") is None


def test_syscall_resolution_and_flags() -> None:
    assert resolve_syscall_name("c000003e", "59") == "execve"
    assert resolve_syscall_name("c00000b7", "221") == "execve"
    assert resolve_syscall_name(None, "openat") == "openat"
    assert resolve_syscall_name("c000003e", "9999") == "syscall_9999"
    assert is_write_open(0x241)
    assert not is_write_open(0x0)


def test_identifier_parsing() -> None:
    assert parse_identifier("1000") == 1000
    assert parse_identifier("4294967295") is None
    assert parse_identifier("-1") is None
    assert parse_identifier("abc") is None
    assert UserResolver().name_for(0) == "root"


def test_user_resolver_reads_passwd_file(tmp_path) -> None:
    passwd = tmp_path / "passwd"
    passwd.write_text("root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n")
    resolver = UserResolver.from_passwd_file(passwd)
    assert resolver.name_for(1001) == "alice"
    assert resolver.name_for(4242) == "4242"
    assert UserResolver.from_passwd_file(tmp_path / "missing").name_for(5) == "5"


def test_syslog_ssh_events(auth_events) -> None:
    failure, invalid, accepted = auth_events[0], auth_events[1], auth_events[2]
    assert failure.category == EventCategory.AUTHENTICATION and failure.outcome == Outcome.FAILURE
    assert failure.user == "root" and failure.src_ip == "203.0.113.7"
    assert invalid.user == "oracle" and invalid.details["invalid_user"] is True
    assert accepted.outcome == Outcome.SUCCESS and accepted.details["method"] == "publickey"


def test_syslog_privilege_and_account_events(auth_events) -> None:
    sudo, denied, pam, useradd, usermod, su = auth_events[3:9]
    assert sudo.command_line == "/usr/bin/systemctl restart nginx" and sudo.effective_user == "root"
    assert denied.outcome == Outcome.FAILURE and denied.user == "bob"
    assert pam.category == EventCategory.AUTHENTICATION and pam.user == "bob" and pam.src_ip is None
    assert useradd.action == "add_user" and useradd.target_user == "eve"
    assert usermod.details["group"] == "sudo"
    assert su.action == "su" and su.effective_user == "root"


def test_irrelevant_syslog_messages_are_ignored(auth_events) -> None:
    assert len(auth_events) == 10
    assert auth_events[-1].src_ip == "198.51.100.9"


def test_syslog_timestamp_formats() -> None:
    parser = SyslogParser("UTC", reference_time=datetime(2023, 11, 15, tzinfo=UTC))
    rfc = parser.parse("2023-11-14T22:16:00+0000 lab sudo[1]: message")
    bsd = parser.parse("Nov 14 22:16:00 lab sudo[1]: message")
    zulu = parser.parse("2023-11-14T22:16:00Z lab sudo: message")
    assert rfc.timestamp == bsd.timestamp == zulu.timestamp
    assert zulu.pid is None
    assert parser.parse("not a syslog line") is None


def test_bsd_timestamps_in_the_future_roll_back_one_year() -> None:
    parser = SyslogParser("UTC", reference_time=datetime(2024, 1, 2, tzinfo=UTC))
    record = parser.parse("Dec 31 23:00:00 lab sshd[1]: message")
    assert datetime.fromtimestamp(record.timestamp, UTC).year == 2023


def test_syslog_from_other_programs_cannot_spoof_ssh_failures() -> None:
    parser = SyslogParser("UTC")
    record = parser.parse("2023-11-14T22:16:00Z lab myapp[1]: Failed password for root from 1.2.3.4 port 1 ssh2")
    assert SyslogNormalizer().normalize(record) is None
