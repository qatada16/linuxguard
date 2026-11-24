import ipaddress
import posixpath

from linuxguard.collection.audit_parser import AuditEvent, AuditRecord
from linuxguard.domain.events import EventCategory, Outcome, SecurityEvent
from linuxguard.processing.syscalls import (
    CHMOD_MODE_ARGUMENT,
    CHMOD_SYSCALLS,
    CHOWN_SYSCALLS,
    EXECUTION_SYSCALLS,
    IDENTITY_SYSCALLS,
    MODIFICATION_SYSCALLS,
    MODULE_SYSCALLS,
    NETWORK_SYSCALLS,
    OPEN_FLAGS_ARGUMENT,
    OPEN_SYSCALLS,
    is_write_open,
    resolve_syscall_name,
)
from linuxguard.processing.users import UserResolver, parse_identifier

SOURCE_NAME = "auditd"
EMPTY_VALUES = frozenset({"", "?", "(null)", "(none)"})
AF_INET = 2
AF_INET6 = 10
CONNECT_IN_PROGRESS_EXIT = "-115"

AUTHENTICATION_TYPES = frozenset({"USER_AUTH"})
LOGIN_TYPES = frozenset({"USER_LOGIN"})
PRIVILEGE_TYPES = frozenset({"USER_CMD"})
ACCOUNT_TYPES = frozenset(
    {
        "ADD_USER",
        "DEL_USER",
        "ADD_GROUP",
        "DEL_GROUP",
        "USER_MGMT",
        "GRP_MGMT",
        "USER_CHAUTHTOK",
        "GRP_CHAUTHTOK",
        "ACCT_LOCK",
        "ACCT_UNLOCK",
    }
)
AUDIT_CONFIGURATION_TYPES = frozenset(
    {"CONFIG_CHANGE", "DAEMON_END", "DAEMON_ABORT", "DAEMON_CONFIG", "DAEMON_ROTATE", "DAEMON_RESUME"}
)
SERVICE_TYPES = frozenset({"SERVICE_START", "SERVICE_STOP"})


def _clean(value: str | None) -> str | None:
    if value is None or value in EMPTY_VALUES:
        return None
    return value


def _action_name(value: str) -> str:
    return value.strip().lower().replace(" ", "_").replace("-", "_")


def _outcome_from(fields: dict[str, str]) -> Outcome:
    result = fields.get("success") or fields.get("res")
    if result in {"yes", "success", "1"}:
        return Outcome.SUCCESS
    if result in {"no", "failed", "0"}:
        return Outcome.FAILURE
    return Outcome.UNKNOWN


def _parse_int(value: str | None, base: int = 10) -> int | None:
    if value is None:
        return None
    try:
        return int(value, base)
    except ValueError:
        return None


def decode_socket_address(saddr: str) -> tuple[str, int] | None:
    try:
        raw = bytes.fromhex(saddr)
    except ValueError:
        return None
    if len(raw) < 8:
        return None
    family = int.from_bytes(raw[0:2], "little")
    port = int.from_bytes(raw[2:4], "big")
    if family == AF_INET:
        return str(ipaddress.IPv4Address(raw[4:8])), port
    if family == AF_INET6 and len(raw) >= 24:
        return str(ipaddress.IPv6Address(raw[8:24])), port
    return None


class AuditNormalizer:
    def __init__(self, host_name: str, user_resolver: UserResolver | None = None) -> None:
        self._host_name = host_name
        self._users = user_resolver or UserResolver()

    def normalize(self, event: AuditEvent) -> SecurityEvent | None:
        primary = event.primary
        record_type = primary.record_type
        if record_type == "SYSCALL":
            return self._normalize_syscall(event, primary)
        if record_type in AUTHENTICATION_TYPES:
            return self._normalize_user_record(event, primary, EventCategory.AUTHENTICATION)
        if record_type in LOGIN_TYPES:
            return self._normalize_user_record(event, primary, EventCategory.LOGIN)
        if record_type in PRIVILEGE_TYPES:
            return self._normalize_command(event, primary)
        if record_type in ACCOUNT_TYPES:
            return self._normalize_account(event, primary)
        if record_type in AUDIT_CONFIGURATION_TYPES:
            return self._normalize_audit_configuration(event, primary)
        if record_type in SERVICE_TYPES:
            return self._normalize_service(event, primary)
        if record_type.startswith("ANOM_"):
            return self._base_event(event, primary, EventCategory.OTHER, _action_name(record_type))
        return None

    def _base_event(
        self, event: AuditEvent, record: AuditRecord, category: EventCategory, action: str
    ) -> SecurityEvent:
        fields = record.fields
        auid = parse_identifier(fields.get("auid"))
        uid = parse_identifier(fields.get("uid"))
        euid = parse_identifier(fields.get("euid"))
        session = parse_identifier(fields.get("ses"))
        user = self._name_from(record, "AUID", auid) or self._name_from(record, "UID", uid)
        return SecurityEvent(
            timestamp=event.timestamp,
            category=category,
            action=action,
            source=SOURCE_NAME,
            record_id=event.record_id,
            outcome=_outcome_from(fields),
            host=event.node or self._host_name,
            user=user,
            effective_user=self._name_from(record, "EUID", euid) or user,
            uid=uid,
            auid=auid,
            euid=euid,
            pid=_parse_int(fields.get("pid")),
            ppid=_parse_int(fields.get("ppid")),
            session_id=str(session) if session is not None else None,
            process_name=_clean(fields.get("comm")),
            executable=_clean(fields.get("exe")),
            audit_key=_clean(fields.get("key")),
            raw=event.raw,
        )

    def _name_from(self, record: AuditRecord, enrichment_key: str, identifier: int | None) -> str | None:
        enriched = _clean(record.enrichment.get(enrichment_key))
        if enriched and enriched != "unset":
            return enriched
        return self._users.name_for(identifier)

    def _normalize_syscall(self, event: AuditEvent, record: AuditRecord) -> SecurityEvent:
        fields = record.fields
        syscall = record.enrichment.get("SYSCALL") or resolve_syscall_name(fields.get("arch"), fields.get("syscall"))
        syscall = syscall or "unknown"
        if syscall in EXECUTION_SYSCALLS:
            return self._execution_event(event, record, syscall)
        if syscall in OPEN_SYSCALLS:
            return self._open_event(event, record, syscall)
        if syscall in MODIFICATION_SYSCALLS:
            normalized = self._base_event(event, record, EventCategory.FILE_MODIFICATION, syscall)
            self._attach_paths(event, normalized)
            return normalized
        if syscall in CHMOD_SYSCALLS or syscall in CHOWN_SYSCALLS:
            return self._permission_event(event, record, syscall)
        if syscall in NETWORK_SYSCALLS:
            return self._network_event(event, record, syscall)
        if syscall in MODULE_SYSCALLS:
            normalized = self._base_event(event, record, EventCategory.KERNEL_MODULE, syscall)
            module = event.first("KERN_MODULE")
            if module is not None:
                normalized.details["module"] = module.fields.get("name")
            self._attach_paths(event, normalized)
            return normalized
        if syscall in IDENTITY_SYSCALLS:
            return self._base_event(event, record, EventCategory.PRIVILEGE_ESCALATION, syscall)
        normalized = self._base_event(event, record, EventCategory.OTHER, syscall)
        self._attach_paths(event, normalized)
        return normalized

    def _execution_event(self, event: AuditEvent, record: AuditRecord, syscall: str) -> SecurityEvent:
        normalized = self._base_event(event, record, EventCategory.PROCESS_EXECUTION, syscall)
        execve = event.first("EXECVE")
        if execve is not None:
            count = _parse_int(execve.fields.get("argc")) or 0
            arguments = [execve.fields.get(f"a{index}", "") for index in range(count)]
            normalized.command_line = " ".join(arguments).strip() or None
        if normalized.command_line is None:
            proctitle = event.first("PROCTITLE")
            if proctitle is not None:
                normalized.command_line = _clean(proctitle.fields.get("proctitle"))
        cwd = event.first("CWD")
        if cwd is not None:
            normalized.working_directory = _clean(cwd.fields.get("cwd"))
        return normalized

    def _open_event(self, event: AuditEvent, record: AuditRecord, syscall: str) -> SecurityEvent:
        flags_argument = OPEN_FLAGS_ARGUMENT.get(syscall)
        flags = _parse_int(record.fields.get(flags_argument), 16) if flags_argument else None
        created = any(path.fields.get("nametype") == "CREATE" for path in event.all("PATH"))
        writes = syscall == "creat" or created or (flags is not None and is_write_open(flags))
        category = EventCategory.FILE_MODIFICATION if writes else EventCategory.FILE_ACCESS
        normalized = self._base_event(event, record, category, "write" if writes else "read")
        normalized.details["syscall"] = syscall
        if flags is not None:
            normalized.details["flags"] = flags
        self._attach_paths(event, normalized)
        return normalized

    def _permission_event(self, event: AuditEvent, record: AuditRecord, syscall: str) -> SecurityEvent:
        normalized = self._base_event(event, record, EventCategory.PERMISSION_CHANGE, syscall)
        mode_argument = CHMOD_MODE_ARGUMENT.get(syscall)
        if mode_argument:
            normalized.file_mode = _parse_int(record.fields.get(mode_argument), 16)
        self._attach_paths(event, normalized)
        return normalized

    def _network_event(self, event: AuditEvent, record: AuditRecord, syscall: str) -> SecurityEvent | None:
        sockaddr = event.first("SOCKADDR")
        address = decode_socket_address(sockaddr.fields.get("saddr", "")) if sockaddr else None
        if address is None:
            return None
        normalized = self._base_event(event, record, EventCategory.NETWORK_CONNECTION, syscall)
        normalized.dest_ip, normalized.dest_port = address
        if record.fields.get("exit") == CONNECT_IN_PROGRESS_EXIT:
            normalized.outcome = Outcome.SUCCESS
        return normalized

    def _attach_paths(self, event: AuditEvent, normalized: SecurityEvent) -> None:
        cwd_record = event.first("CWD")
        cwd = _clean(cwd_record.fields.get("cwd")) if cwd_record else None
        if cwd and normalized.working_directory is None:
            normalized.working_directory = cwd
        resolved: list[tuple[str, str]] = []
        for path_record in event.all("PATH"):
            name = _clean(path_record.fields.get("name"))
            if name is None:
                continue
            if not name.startswith("/") and cwd:
                name = posixpath.normpath(posixpath.join(cwd, name))
            resolved.append((path_record.fields.get("nametype", "NORMAL"), name))
        if not resolved:
            return
        normalized.details["paths"] = [name for _, name in resolved]
        preferred = [name for nametype, name in resolved if nametype == "CREATE"]
        preferred = preferred or [name for nametype, name in resolved if nametype not in {"PARENT"}]
        normalized.target_path = (preferred or [resolved[-1][1]])[-1]

    def _normalize_user_record(self, event: AuditEvent, record: AuditRecord, category: EventCategory) -> SecurityEvent:
        fields = record.fields
        normalized = self._base_event(event, record, category, _action_name(fields.get("op", record.record_type)))
        account = _clean(fields.get("acct"))
        if account is None:
            account = self._users.name_for(parse_identifier(fields.get("id")))
        if normalized.user and account and normalized.user != account:
            normalized.details["login_user"] = normalized.user
        normalized.user = account or normalized.user
        normalized.src_ip = _clean(fields.get("addr"))
        normalized.details["terminal"] = _clean(fields.get("terminal"))
        normalized.details["hostname"] = _clean(fields.get("hostname"))
        return normalized

    def _normalize_command(self, event: AuditEvent, record: AuditRecord) -> SecurityEvent:
        fields = record.fields
        normalized = self._base_event(event, record, EventCategory.PRIVILEGE_ESCALATION, "sudo")
        normalized.command_line = _clean(fields.get("cmd"))
        normalized.working_directory = _clean(fields.get("cwd"))
        normalized.effective_user = "root"
        normalized.details["terminal"] = _clean(fields.get("terminal"))
        return normalized

    def _normalize_account(self, event: AuditEvent, record: AuditRecord) -> SecurityEvent:
        fields = record.fields
        action = _action_name(fields.get("op") or record.record_type)
        normalized = self._base_event(event, record, EventCategory.ACCOUNT_MANAGEMENT, action)
        normalized.details["record_type"] = record.record_type.lower()
        target = _clean(fields.get("acct")) or self._users.name_for(parse_identifier(fields.get("id")))
        normalized.target_user = target
        group = _clean(fields.get("grp"))
        if group:
            normalized.details["group"] = group
        return normalized

    def _normalize_audit_configuration(self, event: AuditEvent, record: AuditRecord) -> SecurityEvent:
        fields = record.fields
        action = _action_name(fields.get("op") or record.record_type)
        normalized = self._base_event(event, record, EventCategory.AUDIT_CONFIGURATION, action)
        normalized.details["record_type"] = record.record_type.lower()
        if "audit_enabled" in fields:
            normalized.details["audit_enabled"] = fields["audit_enabled"]
        return normalized

    def _normalize_service(self, event: AuditEvent, record: AuditRecord) -> SecurityEvent:
        normalized = self._base_event(event, record, EventCategory.SERVICE, record.record_type.lower())
        normalized.details["unit"] = _clean(record.fields.get("unit"))
        return normalized
