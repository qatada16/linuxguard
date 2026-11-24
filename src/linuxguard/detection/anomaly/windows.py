import math
from dataclasses import dataclass, field

from linuxguard.domain.events import EventCategory, SecurityEvent

REMOTE_CATEGORIES = frozenset({EventCategory.AUTHENTICATION, EventCategory.LOGIN})


def anomaly_entity(event: SecurityEvent) -> str:
    if event.category in REMOTE_CATEGORIES and event.src_ip:
        return f"remote:{event.src_ip}"
    user = event.user or event.effective_user or "system"
    if event.session_id is not None:
        return f"{user}@session:{event.session_id}"
    return user


@dataclass(slots=True)
class ActivityWindow:
    entity: str
    start: float
    end: float
    events: list[SecurityEvent] = field(default_factory=list)


class WindowAggregator:
    def __init__(self, window_seconds: float = 60.0, lateness_seconds: float = 5.0) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._window_seconds = window_seconds
        self._lateness_seconds = lateness_seconds
        self._open: dict[tuple[str, int], ActivityWindow] = {}
        self._watermark = -math.inf

    @property
    def window_seconds(self) -> float:
        return self._window_seconds

    def add(self, event: SecurityEvent) -> list[ActivityWindow]:
        index = int(event.timestamp // self._window_seconds)
        entity = anomaly_entity(event)
        key = (entity, index)
        window = self._open.get(key)
        if window is None:
            start = index * self._window_seconds
            window = ActivityWindow(entity, start, start + self._window_seconds)
            self._open[key] = window
        window.events.append(event)
        self._watermark = max(self._watermark, event.timestamp)
        return self._close_expired()

    def advance(self, watermark: float) -> list[ActivityWindow]:
        self._watermark = max(self._watermark, watermark)
        return self._close_expired()

    def flush(self) -> list[ActivityWindow]:
        closed = sorted(self._open.values(), key=lambda window: (window.end, window.entity))
        self._open.clear()
        return closed

    def _close_expired(self) -> list[ActivityWindow]:
        horizon = self._watermark - self._lateness_seconds
        expired = [key for key, window in self._open.items() if window.end <= horizon]
        closed = [self._open.pop(key) for key in expired]
        return sorted(closed, key=lambda window: (window.end, window.entity))


def split_into_windows(events: list[SecurityEvent], window_seconds: float = 60.0) -> list[ActivityWindow]:
    aggregator = WindowAggregator(window_seconds, lateness_seconds=math.inf)
    for event in events:
        aggregator.add(event)
    return aggregator.flush()
