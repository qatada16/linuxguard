from dataclasses import dataclass, field
from datetime import UTC, datetime

from linuxguard.domain.alerts import Alert
from linuxguard.domain.events import SecurityEvent
from linuxguard.storage.repository import EvidenceStore

DEFAULT_CONTEXT_SECONDS = 300.0


def format_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def summarize_event(event: SecurityEvent) -> str:
    actor = event.user or "unknown"
    if event.command_line:
        subject = event.command_line
    elif event.target_path:
        subject = event.target_path
    elif event.dest_ip:
        subject = f"{event.dest_ip}:{event.dest_port}"
    elif event.target_user:
        subject = event.target_user
    else:
        subject = event.executable or event.process_name or ""
    origin = f" from {event.src_ip}" if event.src_ip else ""
    return f"{actor} {event.category.value}/{event.action} [{event.outcome.value}] {subject}{origin}".strip()


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    event: SecurityEvent
    is_evidence: bool
    related_alert_ids: tuple[str, ...] = ()

    @property
    def time_text(self) -> str:
        return format_timestamp(self.event.timestamp)

    @property
    def summary(self) -> str:
        return summarize_event(self.event)


@dataclass(slots=True)
class Timeline:
    start: float
    end: float
    entries: list[TimelineEntry] = field(default_factory=list)

    @property
    def evidence_count(self) -> int:
        return sum(1 for entry in self.entries if entry.is_evidence)


class TimelineBuilder:
    def __init__(self, store: EvidenceStore, context_seconds: float = DEFAULT_CONTEXT_SECONDS) -> None:
        self._store = store
        self._context_seconds = context_seconds

    def for_alert(self, alert: Alert, include_context: bool = True) -> Timeline:
        evidence = alert.evidence or self._store.evidence_for(alert.alert_id)
        evidence_ids = {event.event_id for event in evidence}
        start = alert.first_seen - self._context_seconds
        end = alert.last_seen + self._context_seconds
        events = {event.event_id: event for event in evidence}
        if include_context:
            correlation_ids = sorted({event.correlation_id for event in evidence if event.correlation_id})
            users = sorted({event.user for event in evidence if event.user})
            for event in self._store.events_between(start, end, correlation_ids, users):
                events.setdefault(event.event_id, event)
        return self._build(start, end, list(events.values()), evidence_ids)

    def for_range(self, start: float, end: float, users: list[str] | None = None) -> Timeline:
        events = self._store.events_between(start, end, users=users)
        return self._build(start, end, events, set())

    def _build(self, start: float, end: float, events: list[SecurityEvent], evidence_ids: set[str]) -> Timeline:
        ordered = sorted(events, key=lambda event: (event.timestamp, event.event_id))
        links = self._store.alert_ids_for_events([event.event_id for event in ordered])
        entries = [
            TimelineEntry(
                event=event,
                is_evidence=event.event_id in evidence_ids,
                related_alert_ids=tuple(links.get(event.event_id, ())),
            )
            for event in ordered
        ]
        return Timeline(start, end, entries)
