import statistics
import tempfile
import time
import tracemalloc
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil

from linuxguard.config import AnomalySettings
from linuxguard.detection.anomaly.detector import IsolationForestDetector
from linuxguard.detection.anomaly.windows import split_into_windows
from linuxguard.detection.pipeline import DetectionMode, DetectionPipeline
from linuxguard.detection.rules.engine import RuleEngine
from linuxguard.detection.rules.model import Rule
from linuxguard.domain.alerts import Alert
from linuxguard.domain.events import SecurityEvent
from linuxguard.evaluation.labels import Case, CaseLabeler
from linuxguard.evaluation.metrics import DetectionMetrics, ResourceUsage, score_alerts
from linuxguard.evaluation.synthetic.dataset import LabeledDataset, build_dataset
from linuxguard.processing.stream import EventProcessor
from linuxguard.processing.users import UserResolver
from linuxguard.storage.repository import EvidenceStore

UNLIMITED_EVIDENCE = 1_000_000
TRAINING_SEED_OFFSET = 10_000

ProgressCallback = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class ConfigurationSpec:
    key: str
    label: str
    use_rules: bool
    threshold_quantile: float | None
    range_guard: bool = True

    @property
    def uses_anomaly_detection(self) -> bool:
        return self.threshold_quantile is not None


BASELINE_RULES = ConfigurationSpec("rules", "Baseline A: rules only", True, None)
BASELINE_HYBRID = ConfigurationSpec("hybrid", "Baseline B: rules + anomaly detector", True, 0.995)
DEFAULT_CONFIGURATIONS: tuple[ConfigurationSpec, ...] = (
    BASELINE_RULES,
    BASELINE_HYBRID,
    ConfigurationSpec("hybrid_forest_only", "Rules + Isolation Forest without range guard", True, 0.995, False),
    ConfigurationSpec("anomaly_only", "Anomaly detector only (reference)", False, 0.995),
    ConfigurationSpec("forest_only", "Isolation Forest only, no guard (reference)", False, 0.995, False),
    ConfigurationSpec("hybrid_q990", "Rules + anomaly detector (q=0.990)", True, 0.99),
    ConfigurationSpec("hybrid_q999", "Rules + anomaly detector (q=0.999)", True, 0.999),
)


@dataclass(slots=True)
class ConfigurationRun:
    spec: ConfigurationSpec
    metrics: DetectionMetrics
    usage: ResourceUsage
    alerts: list[Alert] = field(default_factory=list)


@dataclass(slots=True)
class SeedResult:
    seed: int
    events: int
    cases: int
    parsing: ResourceUsage
    training: ResourceUsage
    training_windows: int
    runs: dict[str, ConfigurationRun]


class ResourceMonitor:
    def __init__(self) -> None:
        self._wall_start = 0.0
        self._cpu_start = 0.0
        self.wall_seconds = 0.0
        self.cpu_seconds = 0.0
        self.peak_memory_mb = 0.0

    def __enter__(self) -> "ResourceMonitor":
        tracemalloc.start()
        self._wall_start = time.perf_counter()
        self._cpu_start = time.process_time()
        return self

    def __exit__(self, *_: object) -> None:
        self.wall_seconds = time.perf_counter() - self._wall_start
        self.cpu_seconds = time.process_time() - self._cpu_start
        self.peak_memory_mb = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
        tracemalloc.stop()

    def usage(self, events: int, storage_bytes: int = 0) -> ResourceUsage:
        return ResourceUsage(self.wall_seconds, self.cpu_seconds, self.peak_memory_mb, events, storage_bytes)


def resolver_for(dataset: LabeledDataset) -> UserResolver:
    names = {}
    for line in dataset.passwd_lines:
        parts = line.split(":")
        if len(parts) > 2 and parts[2].isdigit():
            names[int(parts[2])] = parts[0]
    return UserResolver(names)


def extract_events(dataset: LabeledDataset) -> tuple[list[SecurityEvent], ResourceUsage]:
    processor = EventProcessor(dataset.host, resolver_for(dataset), syslog_timezone="UTC")
    with ResourceMonitor() as monitor:
        events = processor.process_batch(dataset.audit_lines, dataset.auth_lines)
    return events, monitor.usage(len(events))


def train_detector(
    events: list[SecurityEvent], settings: AnomalySettings
) -> tuple[IsolationForestDetector, ResourceUsage, int]:
    with ResourceMonitor() as monitor:
        windows = split_into_windows(events, settings.window_seconds)
        detector = IsolationForestDetector(
            n_estimators=settings.n_estimators,
            max_samples=settings.max_samples,
            threshold_quantile=settings.threshold_quantile,
            random_state=settings.random_state,
            window_seconds=settings.window_seconds,
            range_guard=settings.range_guard,
            guard_factor=settings.guard_factor,
            guard_margin=settings.guard_margin,
        ).fit(windows)
    return detector, monitor.usage(len(events)), len(windows)


def measure_storage(events: list[SecurityEvent], alerts: list[Alert]) -> int:
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / "evaluation.db"
        store = EvidenceStore.open(database)
        try:
            store.save_events(events)
            store.save_alerts(alerts)
            store.checkpoint()
        finally:
            store.close()
        return sum(path.stat().st_size for path in Path(directory).iterdir())


def run_configuration(
    spec: ConfigurationSpec,
    events: list[SecurityEvent],
    rules: list[Rule],
    detector: IsolationForestDetector | None,
    cases: list[Case],
    labels: dict[str, str],
    lateness_seconds: float,
) -> ConfigurationRun:
    variant = None
    if spec.uses_anomaly_detection:
        if detector is None:
            raise ValueError(f"Configuration {spec.key} needs a trained detector")
        variant = detector.with_threshold_quantile(spec.threshold_quantile).with_range_guard(spec.range_guard)
    pipeline = DetectionPipeline(
        RuleEngine(rules if spec.use_rules else []),
        variant,
        DetectionMode.HYBRID if variant is not None else DetectionMode.RULES,
        lateness_seconds=lateness_seconds,
        evidence_limit=UNLIMITED_EVIDENCE,
    )
    with ResourceMonitor() as monitor:
        alerts = pipeline.process_all(events)
    storage = measure_storage(events, alerts)
    return ConfigurationRun(spec, score_alerts(alerts, cases, labels), monitor.usage(len(events), storage), alerts)


def evaluate_seed(
    seed: int,
    rules: list[Rule],
    settings: AnomalySettings,
    configurations: tuple[ConfigurationSpec, ...] = DEFAULT_CONFIGURATIONS,
    training_days: int = 3,
    test_days: int = 1,
    progress: ProgressCallback | None = None,
) -> SeedResult:
    report = progress or (lambda message: None)
    report(f"seed {seed}: generating baseline ({training_days} days) and test data ({test_days} day)")
    training = build_dataset(seed + TRAINING_SEED_OFFSET, days=training_days, malicious_per_scenario=0)
    test = build_dataset(seed, days=test_days, start=training.end)
    training_events, _ = extract_events(training)
    test_events, parsing = extract_events(test)
    report(f"seed {seed}: training Isolation Forest on {len(training_events)} benign events")
    detector, training_usage, training_windows = train_detector(training_events, settings)
    labels = CaseLabeler(test.cases).label_all(test_events)
    runs = {}
    for spec in configurations:
        report(f"seed {seed}: running {spec.label}")
        runs[spec.key] = run_configuration(
            spec, test_events, rules, detector, test.cases, labels, settings.lateness_seconds
        )
    return SeedResult(seed, len(test_events), len(test.cases), parsing, training_usage, training_windows, runs)


def evaluate_dataset(
    dataset: LabeledDataset,
    rules: list[Rule],
    detector: IsolationForestDetector | None,
    configurations: tuple[ConfigurationSpec, ...],
    lateness_seconds: float = 5.0,
) -> dict[str, ConfigurationRun]:
    events, _ = extract_events(dataset)
    labels = CaseLabeler(dataset.cases).label_all(events)
    selected = tuple(spec for spec in configurations if detector is not None or not spec.uses_anomaly_detection)
    return {
        spec.key: run_configuration(spec, events, rules, detector, dataset.cases, labels, lateness_seconds)
        for spec in selected
    }


def _mean_and_deviation(values: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values) if values else 0.0,
        "std": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def summarize(results: list[SeedResult]) -> dict[str, Any]:
    configurations: dict[str, Any] = {}
    for key in results[0].runs:
        runs = [result.runs[key] for result in results]
        metric_names = runs[0].metrics.summary().keys()
        metrics = {
            name: _mean_and_deviation([float(run.metrics.summary()[name]) for run in runs]) for name in metric_names
        }
        usage = {
            "wall_seconds": _mean_and_deviation([run.usage.wall_seconds for run in runs]),
            "cpu_seconds": _mean_and_deviation([run.usage.cpu_seconds for run in runs]),
            "peak_memory_mb": _mean_and_deviation([run.usage.peak_memory_mb for run in runs]),
            "milliseconds_per_event": _mean_and_deviation([run.usage.milliseconds_per_event for run in runs]),
            "events_per_second": _mean_and_deviation([run.usage.events_per_second for run in runs]),
            "storage_kb": _mean_and_deviation([run.usage.storage_bytes / 1024 for run in runs]),
        }
        scenarios: dict[str, list[int]] = {}
        for run in runs:
            for name, (detected, total) in run.metrics.detected_by_scenario.items():
                totals = scenarios.setdefault(name, [0, 0])
                totals[0] += detected
                totals[1] += total
        configurations[key] = {
            "label": runs[0].spec.label,
            "metrics": metrics,
            "resources": usage,
            "scenarios": {name: {"detected": value[0], "total": value[1]} for name, value in scenarios.items()},
        }
    return {
        "seeds": [result.seed for result in results],
        "test_events": _mean_and_deviation([result.events for result in results]),
        "test_cases": _mean_and_deviation([result.cases for result in results]),
        "training_windows": _mean_and_deviation([result.training_windows for result in results]),
        "parsing": {
            "events_per_second": _mean_and_deviation([result.parsing.events_per_second for result in results]),
            "peak_memory_mb": _mean_and_deviation([result.parsing.peak_memory_mb for result in results]),
        },
        "training": {
            "wall_seconds": _mean_and_deviation([result.training.wall_seconds for result in results]),
            "peak_memory_mb": _mean_and_deviation([result.training.peak_memory_mb for result in results]),
        },
        "process_rss_mb": psutil.Process().memory_info().rss / (1024 * 1024),
        "configurations": configurations,
    }
