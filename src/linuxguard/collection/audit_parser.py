import re
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

ENRICHMENT_SEPARATOR = "\x1d"
UNSET_ID = 4294967295

_RECORD_PATTERN = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>\S+)\s+msg=audit\((?P<seconds>\d+\.\d+):(?P<serial>\d+)\):\s?(?P<body>.*)$"
)
_FIELD_PATTERN = re.compile(r"""([A-Za-z_][\w\-\[\]]*)=("[^"]*"|'[^']*'|\{[^}]*\}|\S*)""")
_HEX_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
_EXECVE_ARGUMENT_PATTERN = re.compile(r"^a\d+$")

ENCODED_STRING_FIELDS = frozenset(
    {"proctitle", "name", "cwd", "comm", "exe", "acct", "key", "cmd", "data", "path", "grp", "new_group"}
)
AUXILIARY_RECORD_TYPES = frozenset(
    {
        "EXECVE",
        "CWD",
        "PATH",
        "PROCTITLE",
        "SOCKADDR",
        "EOE",
        "BPRM_FCAPS",
        "CAPSET",
        "MMAP",
        "OBJ_PID",
        "FD_PAIR",
        "NETFILTER_CFG",
        "KERN_MODULE",
        "SECCOMP",
        "TIME_INJOFFSET",
        "UNKNOWN",
    }
)


@dataclass(frozen=True, slots=True)
class AuditRecord:
    record_type: str
    timestamp: float
    serial: int
    node: str | None
    fields: dict[str, str]
    enrichment: dict[str, str]
    raw: str

    @property
    def event_key(self) -> tuple[str | None, float, int]:
        return self.node, self.timestamp, self.serial


@dataclass(slots=True)
class AuditEvent:
    timestamp: float
    serial: int
    node: str | None
    records: list[AuditRecord] = field(default_factory=list)

    @property
    def record_id(self) -> str:
        prefix = f"{self.node}:" if self.node else ""
        return f"{prefix}{self.timestamp:.3f}:{self.serial}"

    @property
    def primary(self) -> AuditRecord:
        for record in self.records:
            if record.record_type not in AUXILIARY_RECORD_TYPES:
                return record
        return self.records[0]

    @property
    def raw(self) -> str:
        return "\n".join(record.raw for record in self.records)

    def first(self, record_type: str) -> AuditRecord | None:
        for record in self.records:
            if record.record_type == record_type:
                return record
        return None

    def all(self, record_type: str) -> list[AuditRecord]:
        return [record for record in self.records if record.record_type == record_type]


def decode_hex_string(value: str) -> str:
    decoded = bytes.fromhex(value)
    return decoded.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()


def decode_field_value(record_type: str, name: str, value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    is_string_field = name in ENCODED_STRING_FIELDS or (
        record_type == "EXECVE" and _EXECVE_ARGUMENT_PATTERN.match(name) is not None
    )
    if is_string_field and _HEX_PATTERN.match(value):
        return decode_hex_string(value)
    return value


def parse_fields(record_type: str, body: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for name, value in _FIELD_PATTERN.findall(body):
        if name == "msg" and value.startswith("'"):
            parsed.update(parse_fields(record_type, value[1:-1]))
            continue
        parsed[name] = decode_field_value(record_type, name, value)
    return parsed


def parse_audit_line(line: str) -> AuditRecord | None:
    stripped = line.rstrip("\r\n")
    match = _RECORD_PATTERN.match(stripped)
    if match is None:
        return None
    body, _, enrichment_text = match.group("body").partition(ENRICHMENT_SEPARATOR)
    record_type = match.group("type")
    return AuditRecord(
        record_type=record_type,
        timestamp=float(match.group("seconds")),
        serial=int(match.group("serial")),
        node=match.group("node"),
        fields=parse_fields(record_type, body),
        enrichment=parse_fields(record_type, enrichment_text) if enrichment_text else {},
        raw=stripped.replace(ENRICHMENT_SEPARATOR, " "),
    )


class AuditEventAssembler:
    def __init__(self, max_pending_events: int = 32) -> None:
        self._max_pending_events = max_pending_events
        self._pending: OrderedDict[tuple[str | None, float, int], AuditEvent] = OrderedDict()

    def feed(self, record: AuditRecord) -> list[AuditEvent]:
        key = record.event_key
        completed: list[AuditEvent] = []
        event = self._pending.get(key)
        if event is None:
            event = AuditEvent(timestamp=record.timestamp, serial=record.serial, node=record.node)
            self._pending[key] = event
        if record.record_type != "EOE":
            event.records.append(record)
        if record.record_type == "EOE" or self._is_standalone(event):
            completed.append(self._pending.pop(key))
        while len(self._pending) > self._max_pending_events:
            completed.append(self._pending.popitem(last=False)[1])
        return [item for item in completed if item.records]

    def flush(self) -> list[AuditEvent]:
        completed = [event for event in self._pending.values() if event.records]
        self._pending.clear()
        return completed

    @staticmethod
    def _is_standalone(event: AuditEvent) -> bool:
        if len(event.records) != 1:
            return False
        record_type = event.records[0].record_type
        return record_type != "SYSCALL" and record_type not in AUXILIARY_RECORD_TYPES


def iter_audit_events(lines: Iterable[str]) -> Iterator[AuditEvent]:
    assembler = AuditEventAssembler()
    for line in lines:
        record = parse_audit_line(line)
        if record is not None:
            yield from assembler.feed(record)
    yield from assembler.flush()
