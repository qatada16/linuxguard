import hashlib
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from linuxguard.collection.syslog_parser import SyslogRecord
from linuxguard.domain.events import EventCategory, Outcome, SecurityEvent

SOURCE_NAME = "authlog"

EventBuilder = Callable[[re.Match[str]], dict[str, object]]


@dataclass(frozen=True, slots=True)
class MessagePattern:
    programs: frozenset[str]
    expression: re.Pattern[str]
    category: EventCategory
    action: str
    outcome: Outcome
    build: EventBuilder


def _ssh_attempt(match: re.Match[str]) -> dict[str, object]:
    return {
        "user": match.group("user"),
        "src_ip": match.group("ip"),
        "details": {"method": match.group("method"), "src_port": int(match.group("port"))},
    }


def _ssh_failure(match: re.Match[str]) -> dict[str, object]:
    values = _ssh_attempt(match)
    values["details"]["invalid_user"] = bool(match.group("invalid"))
    return values


def _sudo_command(match: re.Match[str]) -> dict[str, object]:
    return {
        "user": match.group("user"),
        "effective_user": match.group("target"),
        "working_directory": match.group("pwd"),
        "command_line": match.group("command"),
        "details": {"terminal": match.group("tty")},
    }


def _sudo_denied(match: re.Match[str]) -> dict[str, object]:
    values = _sudo_command(match)
    values["details"]["reason"] = "not_in_sudoers"
    return values


def _pam_failure(match: re.Match[str]) -> dict[str, object]:
    rhost = match.group("rhost") or None
    return {
        "user": match.group("user") or match.group("logname") or None,
        "src_ip": rhost,
        "details": {"service": match.group("service"), "login_user": match.group("logname") or None},
    }


def _su_switch(match: re.Match[str]) -> dict[str, object]:
    return {
        "user": match.group("user"),
        "effective_user": match.group("target"),
        "details": {"terminal": match.group("tty")},
    }


def _new_user(match: re.Match[str]) -> dict[str, object]:
    return {"target_user": match.group("name"), "details": {"uid": int(match.group("uid"))}}


def _new_group(match: re.Match[str]) -> dict[str, object]:
    return {"details": {"group": match.group("name")}}


def _deleted_user(match: re.Match[str]) -> dict[str, object]:
    return {"target_user": match.group("name")}


def _group_membership(match: re.Match[str]) -> dict[str, object]:
    return {"target_user": match.group("name"), "details": {"group": match.group("group")}}


def _password_change(match: re.Match[str]) -> dict[str, object]:
    return {"target_user": match.group("name")}


_SSH_PROGRAMS = frozenset({"sshd", "sshd-session"})

MESSAGE_PATTERNS: tuple[MessagePattern, ...] = (
    MessagePattern(
        _SSH_PROGRAMS,
        re.compile(
            r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        EventCategory.AUTHENTICATION,
        "ssh_login",
        Outcome.FAILURE,
        _ssh_failure,
    ),
    MessagePattern(
        _SSH_PROGRAMS,
        re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
        EventCategory.AUTHENTICATION,
        "ssh_login",
        Outcome.SUCCESS,
        _ssh_attempt,
    ),
    MessagePattern(
        frozenset({"sudo"}),
        re.compile(
            r"^\s*(?P<user>\S+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.+?) ; "
            r"USER=(?P<target>\S+) ;(?: [A-Z]+=\S+ ;)* COMMAND=(?P<command>.*)$"
        ),
        EventCategory.PRIVILEGE_ESCALATION,
        "sudo",
        Outcome.SUCCESS,
        _sudo_command,
    ),
    MessagePattern(
        frozenset({"sudo"}),
        re.compile(
            r"^\s*(?P<user>\S+) : user NOT in sudoers ; TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.+?) ; "
            r"USER=(?P<target>\S+) ; COMMAND=(?P<command>.*)$"
        ),
        EventCategory.PRIVILEGE_ESCALATION,
        "sudo",
        Outcome.FAILURE,
        _sudo_denied,
    ),
    MessagePattern(
        frozenset({"sudo", "su", "login", "polkit-agent-helper-1", "passwd"}),
        re.compile(
            r"^pam_unix\((?P<service>[\w-]+):auth\): authentication failure; logname=(?P<logname>\S*) "
            r"uid=\d+ euid=\d+ tty=\S* ruser=\S* rhost=(?P<rhost>\S*)(?:\s+user=(?P<user>\S+))?"
        ),
        EventCategory.AUTHENTICATION,
        "pam_auth",
        Outcome.FAILURE,
        _pam_failure,
    ),
    MessagePattern(
        frozenset({"su"}),
        re.compile(r"^\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)"),
        EventCategory.PRIVILEGE_ESCALATION,
        "su",
        Outcome.SUCCESS,
        _su_switch,
    ),
    MessagePattern(
        frozenset({"su"}),
        re.compile(r"^FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)"),
        EventCategory.PRIVILEGE_ESCALATION,
        "su",
        Outcome.FAILURE,
        _su_switch,
    ),
    MessagePattern(
        frozenset({"useradd"}),
        re.compile(r"^new user: name=(?P<name>[^,\s]+), UID=(?P<uid>\d+)"),
        EventCategory.ACCOUNT_MANAGEMENT,
        "add_user",
        Outcome.SUCCESS,
        _new_user,
    ),
    MessagePattern(
        frozenset({"useradd", "groupadd"}),
        re.compile(r"^new group: name=(?P<name>[^,\s]+)"),
        EventCategory.ACCOUNT_MANAGEMENT,
        "add_group",
        Outcome.SUCCESS,
        _new_group,
    ),
    MessagePattern(
        frozenset({"userdel"}),
        re.compile(r"^delete user '(?P<name>[^']+)'"),
        EventCategory.ACCOUNT_MANAGEMENT,
        "del_user",
        Outcome.SUCCESS,
        _deleted_user,
    ),
    MessagePattern(
        frozenset({"usermod", "gpasswd"}),
        re.compile(r"^add '(?P<name>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'"),
        EventCategory.ACCOUNT_MANAGEMENT,
        "add_user_to_group",
        Outcome.SUCCESS,
        _group_membership,
    ),
    MessagePattern(
        frozenset({"passwd", "chpasswd"}),
        re.compile(r"^pam_unix\(\w+:chauthtok\): password changed for (?P<name>\S+)"),
        EventCategory.ACCOUNT_MANAGEMENT,
        "change_password",
        Outcome.SUCCESS,
        _password_change,
    ),
)


class SyslogNormalizer:
    def __init__(self, patterns: tuple[MessagePattern, ...] = MESSAGE_PATTERNS) -> None:
        self._patterns = patterns
        self._occurrences: Counter[str] = Counter()

    def normalize(self, record: SyslogRecord) -> SecurityEvent | None:
        for pattern in self._patterns:
            if record.program not in pattern.programs:
                continue
            match = pattern.expression.search(record.message)
            if match is None:
                continue
            values = pattern.build(match)
            details = dict(values.pop("details", {}) or {})
            details["program"] = record.program
            return SecurityEvent(
                timestamp=record.timestamp,
                category=pattern.category,
                action=pattern.action,
                source=SOURCE_NAME,
                record_id=self._record_id(record.raw),
                outcome=pattern.outcome,
                host=record.host,
                pid=record.pid,
                process_name=record.program,
                details=details,
                raw=record.raw,
                **values,
            )
        return None

    def _record_id(self, raw: str) -> str:
        digest = hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()[:20]
        self._occurrences[digest] += 1
        return f"{digest}:{self._occurrences[digest]}"
