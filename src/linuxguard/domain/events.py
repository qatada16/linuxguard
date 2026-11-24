import hashlib
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class EventCategory(StrEnum):
    PROCESS_EXECUTION = "process_execution"
    FILE_ACCESS = "file_access"
    FILE_MODIFICATION = "file_modification"
    PERMISSION_CHANGE = "permission_change"
    AUTHENTICATION = "authentication"
    LOGIN = "login"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ACCOUNT_MANAGEMENT = "account_management"
    NETWORK_CONNECTION = "network_connection"
    KERNEL_MODULE = "kernel_module"
    AUDIT_CONFIGURATION = "audit_configuration"
    SERVICE = "service"
    OTHER = "other"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class SecurityEvent:
    timestamp: float
    category: EventCategory
    action: str
    source: str
    record_id: str
    outcome: Outcome = Outcome.UNKNOWN
    host: str = ""
    user: str | None = None
    effective_user: str | None = None
    target_user: str | None = None
    uid: int | None = None
    auid: int | None = None
    euid: int | None = None
    pid: int | None = None
    ppid: int | None = None
    session_id: str | None = None
    process_name: str | None = None
    executable: str | None = None
    parent_executable: str | None = None
    command_line: str | None = None
    working_directory: str | None = None
    target_path: str | None = None
    file_mode: int | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    audit_key: str | None = None
    correlation_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    event_id: str = ""

    def __post_init__(self) -> None:
        if not self.event_id:
            self.event_id = self.compute_event_id()

    def compute_event_id(self) -> str:
        identity = f"{self.host}|{self.source}|{self.record_id}|{self.action}"
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]

    def field_value(self, name: str) -> Any:
        if name.startswith("details."):
            return self.details.get(name.removeprefix("details."))
        return getattr(self, name, None)

    @property
    def entity(self) -> str:
        return self.user or self.src_ip or self.effective_user or "system"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["category"] = self.category.value
        payload["outcome"] = self.outcome.value
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecurityEvent":
        values = dict(payload)
        values["category"] = EventCategory(values["category"])
        values["outcome"] = Outcome(values.get("outcome") or Outcome.UNKNOWN)
        values["details"] = dict(values.get("details") or {})
        known = {name for name in cls.__dataclass_fields__}
        return cls(**{key: value for key, value in values.items() if key in known})
