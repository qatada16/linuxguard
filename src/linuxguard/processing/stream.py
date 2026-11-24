from collections.abc import Iterable

from linuxguard.collection.audit_parser import AuditEventAssembler, parse_audit_line
from linuxguard.collection.syslog_parser import SyslogParser
from linuxguard.domain.events import SecurityEvent
from linuxguard.processing.audit_normalizer import AuditNormalizer
from linuxguard.processing.correlation import EventCorrelator
from linuxguard.processing.syslog_normalizer import SyslogNormalizer
from linuxguard.processing.users import UserResolver


class AuditLineProcessor:
    def __init__(self, normalizer: AuditNormalizer) -> None:
        self._normalizer = normalizer
        self._assembler = AuditEventAssembler()

    def process(self, lines: Iterable[str]) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        for line in lines:
            record = parse_audit_line(line)
            if record is None:
                continue
            for audit_event in self._assembler.feed(record):
                normalized = self._normalizer.normalize(audit_event)
                if normalized is not None:
                    events.append(normalized)
        return events

    def flush(self) -> list[SecurityEvent]:
        events = [self._normalizer.normalize(audit_event) for audit_event in self._assembler.flush()]
        return [event for event in events if event is not None]


class SyslogLineProcessor:
    def __init__(self, parser: SyslogParser, normalizer: SyslogNormalizer) -> None:
        self._parser = parser
        self._normalizer = normalizer

    def process(self, lines: Iterable[str]) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        for line in lines:
            record = self._parser.parse(line)
            if record is None:
                continue
            normalized = self._normalizer.normalize(record)
            if normalized is not None:
                events.append(normalized)
        return events


class EventProcessor:
    def __init__(
        self,
        host_name: str,
        user_resolver: UserResolver | None = None,
        syslog_timezone: str = "local",
        deduplication_window_seconds: float = 2.0,
        resolve_from_procfs: bool = False,
    ) -> None:
        self.audit = AuditLineProcessor(AuditNormalizer(host_name, user_resolver))
        self.syslog = SyslogLineProcessor(SyslogParser(syslog_timezone), SyslogNormalizer())
        self._correlator = EventCorrelator(deduplication_window_seconds, resolve_from_procfs)

    def correlate(self, events: Iterable[SecurityEvent]) -> list[SecurityEvent]:
        ordered = sorted(events, key=lambda event: (event.timestamp, event.source, event.record_id))
        correlated = (self._correlator.correlate(event) for event in ordered)
        return [event for event in correlated if event is not None]

    def process_batch(self, audit_lines: Iterable[str], auth_lines: Iterable[str]) -> list[SecurityEvent]:
        events = self.audit.process(audit_lines)
        events.extend(self.audit.flush())
        events.extend(self.syslog.process(auth_lines))
        return self.correlate(events)
