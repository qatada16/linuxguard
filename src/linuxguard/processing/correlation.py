import os
from collections import OrderedDict, defaultdict, deque

from linuxguard.domain.events import EventCategory, SecurityEvent

DEDUPLICATED_CATEGORIES = frozenset(
    {EventCategory.AUTHENTICATION, EventCategory.PRIVILEGE_ESCALATION, EventCategory.ACCOUNT_MANAGEMENT}
)
PLACEHOLDER_ACCOUNTS = frozenset({"?", "UNKNOWN", "NOUSER", "INVALID"})


class ProcessTable:
    def __init__(self, capacity: int = 65536, resolve_from_procfs: bool = False) -> None:
        self._capacity = capacity
        self._resolve_from_procfs = resolve_from_procfs
        self._executables: OrderedDict[tuple[str, int], str] = OrderedDict()

    def record(self, host: str, pid: int, executable: str) -> None:
        key = (host, pid)
        self._executables[key] = executable
        self._executables.move_to_end(key)
        while len(self._executables) > self._capacity:
            self._executables.popitem(last=False)

    def executable_for(self, host: str, pid: int) -> str | None:
        known = self._executables.get((host, pid))
        if known is not None or not self._resolve_from_procfs:
            return known
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return None


def is_placeholder_account(name: str | None) -> bool:
    return name is None or name.startswith("(") or name.upper() in PLACEHOLDER_ACCOUNTS


def merge_duplicate(kept: SecurityEvent, duplicate: SecurityEvent) -> None:
    if is_placeholder_account(kept.user) and not is_placeholder_account(duplicate.user):
        kept.user = duplicate.user
    for attribute in ("user", "effective_user", "command_line", "working_directory", "src_ip", "target_user"):
        if getattr(kept, attribute) in (None, "") and getattr(duplicate, attribute) not in (None, ""):
            setattr(kept, attribute, getattr(duplicate, attribute))
    for key, value in duplicate.details.items():
        kept.details.setdefault(key, value)
    kept.details.setdefault("corroborated_by", duplicate.source)


def deduplication_identity(event: SecurityEvent) -> tuple[str | None, ...]:
    if event.src_ip:
        return ("remote", event.src_ip)
    if event.category == EventCategory.ACCOUNT_MANAGEMENT:
        return ("account", event.target_user, event.details.get("group"))
    return ("local", event.user)


class CrossSourceDeduplicator:
    def __init__(self, window_seconds: float = 2.0) -> None:
        self._window_seconds = window_seconds
        self._recent: dict[tuple, deque[SecurityEvent]] = defaultdict(deque)

    def find_original(self, event: SecurityEvent) -> SecurityEvent | None:
        if event.category not in DEDUPLICATED_CATEGORIES:
            return None
        key = (event.category, event.outcome, deduplication_identity(event))
        queue = self._recent[key]
        while queue and event.timestamp - queue[0].timestamp > self._window_seconds:
            queue.popleft()
        for index, candidate in enumerate(queue):
            if candidate.source != event.source:
                del queue[index]
                return candidate
        queue.append(event)
        return None


class EventCorrelator:
    def __init__(self, deduplication_window_seconds: float = 2.0, resolve_from_procfs: bool = False) -> None:
        self._processes = ProcessTable(resolve_from_procfs=resolve_from_procfs)
        self._deduplicator = CrossSourceDeduplicator(deduplication_window_seconds)

    def correlate(self, event: SecurityEvent) -> SecurityEvent | None:
        original = self._deduplicator.find_original(event)
        if original is not None:
            merge_duplicate(original, event)
            return None
        if event.ppid is not None and event.parent_executable is None:
            event.parent_executable = self._processes.executable_for(event.host, event.ppid)
        if event.category == EventCategory.PROCESS_EXECUTION and event.pid is not None and event.executable:
            self._processes.record(event.host, event.pid, event.executable)
        event.correlation_id = self.correlation_id_for(event)
        return event

    @staticmethod
    def correlation_id_for(event: SecurityEvent) -> str:
        if event.session_id is not None:
            return f"{event.host}/session/{event.session_id}"
        if event.src_ip:
            return f"{event.host}/remote/{event.src_ip}"
        if event.user:
            return f"{event.host}/user/{event.user}"
        return f"{event.host}/process/{event.pid}"
