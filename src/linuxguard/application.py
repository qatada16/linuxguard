import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from linuxguard.collection.sources import FileFollower, read_lines
from linuxguard.config import Settings
from linuxguard.detection.anomaly.detector import IsolationForestDetector
from linuxguard.detection.anomaly.model_store import load_detector, save_detector
from linuxguard.detection.anomaly.windows import split_into_windows
from linuxguard.detection.pipeline import DetectionMode, DetectionPipeline
from linuxguard.detection.rules.engine import RuleEngine
from linuxguard.detection.rules.loader import load_rules
from linuxguard.detection.rules.model import Rule
from linuxguard.domain.alerts import Alert
from linuxguard.domain.events import SecurityEvent
from linuxguard.explanation.base import Explanation
from linuxguard.explanation.service import create_explanation_service
from linuxguard.investigation.reports import IncidentReport, ReportBuilder
from linuxguard.investigation.timeline import TimelineBuilder
from linuxguard.processing.stream import EventProcessor
from linuxguard.processing.users import UserResolver
from linuxguard.storage.repository import EvidenceStore

AlertCallback = Callable[[Alert], None]


@dataclass(frozen=True, slots=True)
class IngestionSummary:
    events: int
    stored_events: int
    alerts: list[Alert]
    mode: DetectionMode


@dataclass(frozen=True, slots=True)
class TrainingSummary:
    events: int
    windows: int
    threshold: float
    model_path: Path


def _lines_from(paths: Iterable[str | Path]) -> Iterable[str]:
    for path in paths:
        yield from read_lines(path)


class LinuxGuard:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._rules: list[Rule] | None = None

    @property
    def rules(self) -> list[Rule]:
        if self._rules is None:
            self._rules = load_rules(self.settings.resolved_rules_path())
        return self._rules

    def open_store(self) -> EvidenceStore:
        return EvidenceStore.open(self.settings.storage.database_path)

    def event_processor(self, passwd_path: str | None = None, live: bool = False) -> EventProcessor:
        collection = self.settings.collection
        return EventProcessor(
            host_name=collection.host_name,
            user_resolver=UserResolver.from_passwd_file(passwd_path or collection.passwd_path),
            syslog_timezone=collection.syslog_timezone,
            deduplication_window_seconds=collection.deduplication_window_seconds,
            resolve_from_procfs=live and os.path.isdir("/proc/self"),
        )

    def load_detector(self) -> IsolationForestDetector:
        return load_detector(self.settings.detection.model_path)

    def resolve_mode(self, mode: str | None = None) -> DetectionMode:
        return DetectionMode(mode or self.settings.detection.mode)

    def build_pipeline(self, mode: str | None = None) -> DetectionPipeline:
        selected = self.resolve_mode(mode)
        detector = self.load_detector() if selected == DetectionMode.HYBRID else None
        return DetectionPipeline(
            RuleEngine(self.rules),
            detector,
            selected,
            lateness_seconds=self.settings.detection.anomaly.lateness_seconds,
            evidence_limit=self.settings.detection.evidence_limit,
        )

    def read_events(
        self,
        audit_paths: Iterable[str | Path] = (),
        auth_paths: Iterable[str | Path] = (),
        passwd_path: str | None = None,
    ) -> list[SecurityEvent]:
        processor = self.event_processor(passwd_path)
        return processor.process_batch(_lines_from(audit_paths), _lines_from(auth_paths))

    def ingest(
        self,
        audit_paths: Iterable[str | Path] = (),
        auth_paths: Iterable[str | Path] = (),
        mode: str | None = None,
        passwd_path: str | None = None,
    ) -> IngestionSummary:
        events = self.read_events(audit_paths, auth_paths, passwd_path)
        pipeline = self.build_pipeline(mode)
        alerts = pipeline.process_all(events)
        with self.open_store() as store:
            stored = store.save_events(events) if self.settings.storage.store_all_events else 0
            store.save_alerts(alerts)
        return IngestionSummary(len(events), stored, alerts, pipeline.mode)

    def train(
        self,
        audit_paths: Iterable[str | Path] = (),
        auth_paths: Iterable[str | Path] = (),
        output: str | Path | None = None,
        passwd_path: str | None = None,
    ) -> TrainingSummary:
        anomaly = self.settings.detection.anomaly
        events = self.read_events(audit_paths, auth_paths, passwd_path)
        windows = split_into_windows(events, anomaly.window_seconds)
        detector = IsolationForestDetector(
            n_estimators=anomaly.n_estimators,
            max_samples=anomaly.max_samples,
            threshold_quantile=anomaly.threshold_quantile,
            random_state=anomaly.random_state,
            window_seconds=anomaly.window_seconds,
            range_guard=anomaly.range_guard,
            guard_factor=anomaly.guard_factor,
            guard_margin=anomaly.guard_margin,
        ).fit(windows)
        model_path = save_detector(detector, output or self.settings.detection.model_path)
        return TrainingSummary(len(events), len(windows), float(detector.threshold), model_path)

    def monitor(
        self,
        on_alert: AlertCallback,
        mode: str | None = None,
        from_start: bool = False,
        should_stop: Callable[[], bool] = lambda: False,
        sleep: Callable[[float], None] = time.sleep,
    ) -> int:
        collection = self.settings.collection
        processor = self.event_processor(live=True)
        pipeline = self.build_pipeline(mode)
        audit_follower = FileFollower(collection.audit_log_path, start_at_end=not from_start)
        auth_followers = [FileFollower(path, start_at_end=not from_start) for path in collection.auth_log_paths]
        processed = 0
        with self.open_store() as store:
            while not should_stop():
                events = processor.audit.process(audit_follower.poll())
                for follower in auth_followers:
                    events.extend(processor.syslog.process(follower.poll()))
                correlated = processor.correlate(events)
                alerts: list[Alert] = []
                for event in correlated:
                    alerts.extend(pipeline.process(event))
                alerts.extend(pipeline.advance(time.time()))
                if correlated and self.settings.storage.store_all_events:
                    store.save_events(correlated)
                if alerts:
                    store.save_alerts(alerts)
                    for alert in alerts:
                        on_alert(alert)
                processed += len(correlated)
                sleep(collection.poll_interval_seconds)
            remaining = processor.correlate(processor.audit.flush())
            final_alerts = [alert for event in remaining for alert in pipeline.process(event)]
            final_alerts.extend(pipeline.flush())
            store.save_events(remaining)
            store.save_alerts(final_alerts)
            for alert in final_alerts:
                on_alert(alert)
        return processed + len(remaining)

    def explain(
        self, store: EvidenceStore, alert_id: str, mode: str | None = None, cloud_consent: bool | None = None
    ) -> Explanation:
        alert = self._require_alert(store, alert_id)
        service = create_explanation_service(self.settings.explanation, self.rules, mode, cloud_consent)
        explanation = service.explain(alert)
        store.save_explanation(alert_id, explanation.text, explanation.provider_label)
        return explanation

    def report(self, store: EvidenceStore, alert_id: str) -> IncidentReport:
        alert = self._require_alert(store, alert_id)
        return ReportBuilder(TimelineBuilder(store), self.rules).build(alert)

    @staticmethod
    def _require_alert(store: EvidenceStore, alert_id: str) -> Alert:
        alert = store.get_alert(alert_id)
        if alert is None:
            raise KeyError(f"Alert not found: {alert_id}")
        return alert
