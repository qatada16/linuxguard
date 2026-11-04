"""Isolation Forest anomaly detection over window features (Phase 7).

An unsupervised model trained on a normal-only baseline flags windows whose activity is
unusual relative to that baseline. Alerts are deliberately labelled "unusual activity", not
"intrusion", and carry source='ml' so they stay distinct from rule alerts. The detector is a
pure function of stored events, so replaying evidence adds no duplicate alerts (insert_alert is
fingerprinted). A model trained on too little or non-representative data is marked provisional.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from linuxguard.features import FEATURE_NAMES, extract_windows
from linuxguard.storage import EvidenceStore, utc_timestamp

MIN_WINDOWS = 20  # fewer than this cannot characterise "normal"; refuse rather than mislead.


@dataclass(frozen=True)
class MlResult:
    evaluated: int
    deferred: int
    alerts: int
    new_alerts: int


def _matrix(rows):
    return np.array([[row["features"][name] for name in FEATURE_NAMES] for row in rows], dtype=float)


def train(store: EvidenceStore, *, window_seconds, n_estimators, random_state,
          threshold_percentile, provisional=False) -> dict:
    """Fit a scaler and Isolation Forest on baseline windows; derive the alert threshold."""
    events = store.events()
    baseline_exes = {event["exe"] for event in events if event.get("exe")}
    rows = extract_windows(events, window_seconds=window_seconds, baseline_exes=baseline_exes)
    if len(rows) < MIN_WINDOWS:
        raise ValueError(f"only {len(rows)} windows; need at least {MIN_WINDOWS} for a baseline "
                         f"(collect a longer normal-only capture)")
    matrix = _matrix(rows)
    scaler = StandardScaler().fit(matrix)
    model = IsolationForest(n_estimators=n_estimators, contamination="auto",
                            random_state=random_state).fit(scaler.transform(matrix))
    scores = model.decision_function(scaler.transform(matrix))
    threshold = float(np.percentile(scores, threshold_percentile))
    return {"model": model, "scaler": scaler, "feature_order": list(FEATURE_NAMES),
            "baseline_exes": sorted(baseline_exes), "window_seconds": window_seconds,
            "threshold": threshold, "n_windows": len(rows), "provisional": provisional}


def save(bundle, path):
    joblib.dump(bundle, path)


def load(path) -> dict:
    return joblib.load(path)






