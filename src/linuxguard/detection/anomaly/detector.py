import copy
from collections.abc import Sequence
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest

from linuxguard.detection.anomaly.features import FEATURE_DESCRIPTIONS, FEATURE_NAMES, FeatureExtractor
from linuxguard.detection.anomaly.windows import ActivityWindow
from linuxguard.domain.alerts import FeatureContribution

MINIMUM_TRAINING_WINDOWS = 20
DEVIATION_FLOOR = 0.25
TOP_CONTRIBUTIONS = 4
GUARDED_FEATURES = (
    "execution_count",
    "file_change_count",
    "network_count",
    "external_network_count",
    "auth_failure_count",
    "privileged_count",
    "security_change_count",
    "distinct_executables",
    "distinct_destinations",
    "distinct_directories",
)


class DetectorNotFittedError(RuntimeError):
    pass


@dataclass(slots=True)
class AnomalyFinding:
    window: ActivityWindow
    score: float
    threshold: float
    contributions: list[FeatureContribution]
    exceeded_features: list[str] = field(default_factory=list)


class IsolationForestDetector:
    def __init__(
        self,
        n_estimators: int = 100,
        max_samples: int = 256,
        threshold_quantile: float = 0.995,
        random_state: int = 42,
        window_seconds: float = 60.0,
        range_guard: bool = True,
        guard_factor: float = 2.0,
        guard_margin: float = 5.0,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.threshold_quantile = threshold_quantile
        self.random_state = random_state
        self.window_seconds = window_seconds
        self.range_guard = range_guard
        self.guard_factor = guard_factor
        self.guard_margin = guard_margin
        self.extractor = FeatureExtractor()
        self.threshold: float | None = None
        self.training_scores: np.ndarray = np.empty(0)
        self.training_windows = 0
        self._model: IsolationForest | None = None
        self._baseline_mean: np.ndarray | None = None
        self._baseline_std: np.ndarray | None = None
        self._baseline_raw_mean: dict[str, float] = {}
        self._baseline_maximum: dict[str, float] = {}

    @property
    def is_fitted(self) -> bool:
        return self._model is not None and self.threshold is not None

    def fit(self, windows: Sequence[ActivityWindow]) -> "IsolationForestDetector":
        if len(windows) < MINIMUM_TRAINING_WINDOWS:
            raise ValueError(f"At least {MINIMUM_TRAINING_WINDOWS} activity windows are required to train the baseline")
        self.extractor.fit(windows)
        raw = [self.extractor.raw_features(window) for window in windows]
        matrix = self.extractor.transform_raw(raw)
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=min(self.max_samples, len(windows)),
            contamination="auto",
            random_state=self.random_state,
        ).fit(matrix)
        self.training_scores = -self._model.score_samples(matrix)
        self.threshold = float(np.quantile(self.training_scores, self.threshold_quantile))
        self._baseline_mean = matrix.mean(axis=0)
        self._baseline_std = matrix.std(axis=0)
        self._baseline_raw_mean = {name: float(np.mean([row[name] for row in raw])) for name in FEATURE_NAMES}
        self._baseline_maximum = {name: float(max(row[name] for row in raw)) for name in FEATURE_NAMES}
        self.training_windows = len(windows)
        return self

    def with_threshold_quantile(self, quantile: float) -> "IsolationForestDetector":
        self._require_model()
        if not 0.5 < quantile < 1.0:
            raise ValueError("quantile must be between 0.5 and 1.0")
        variant = copy.copy(self)
        variant.threshold_quantile = quantile
        variant.threshold = float(np.quantile(self.training_scores, quantile))
        return variant

    def with_range_guard(self, enabled: bool) -> "IsolationForestDetector":
        self._require_model()
        variant = copy.copy(self)
        variant.range_guard = enabled
        return variant

    def guard_limit(self, feature: str) -> float:
        maximum = self._baseline_maximum.get(feature, 0.0)
        return max(maximum * self.guard_factor, maximum + self.guard_margin)

    def exceeded_features(self, raw_row: dict[str, float]) -> list[str]:
        if not self.range_guard:
            return []
        return [feature for feature in GUARDED_FEATURES if raw_row[feature] > self.guard_limit(feature)]

    def score(self, windows: Sequence[ActivityWindow]) -> np.ndarray:
        model = self._require_model()
        if not windows:
            return np.empty(0)
        return -model.score_samples(self.extractor.transform(windows))

    def detect(self, windows: Sequence[ActivityWindow]) -> list[AnomalyFinding]:
        model = self._require_model()
        if not windows:
            return []
        raw = [self.extractor.raw_features(window) for window in windows]
        matrix = self.extractor.transform_raw(raw)
        scores = -model.score_samples(matrix)
        findings = []
        threshold = float(self.threshold)
        for window, row, raw_row, score in zip(windows, matrix, raw, scores, strict=True):
            exceeded = self.exceeded_features(raw_row)
            if score > threshold or exceeded:
                contributions = self._contributions(row, raw_row, exceeded)
                findings.append(AnomalyFinding(window, float(score), threshold, contributions, exceeded))
        return findings

    def _contributions(
        self, row: np.ndarray, raw_row: dict[str, float], exceeded: list[str]
    ) -> list[FeatureContribution]:
        deviations = (row - self._baseline_mean) / np.maximum(self._baseline_std, DEVIATION_FLOOR)
        ranked = sorted(
            range(len(FEATURE_NAMES)),
            key=lambda index: (FEATURE_NAMES[index] not in exceeded, -abs(deviations[index])),
        )
        return [
            FeatureContribution(
                name=FEATURE_NAMES[index],
                value=raw_row[FEATURE_NAMES[index]],
                baseline_mean=self._baseline_raw_mean[FEATURE_NAMES[index]],
                deviation=float(deviations[index]),
                description=FEATURE_DESCRIPTIONS[FEATURE_NAMES[index]],
            )
            for index in ranked[:TOP_CONTRIBUTIONS]
            if abs(deviations[index]) > 0
        ]

    def _require_model(self) -> IsolationForest:
        if self._model is None or self.threshold is None:
            raise DetectorNotFittedError("The anomaly detector has not been trained")
        return self._model
