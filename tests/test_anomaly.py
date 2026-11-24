import math

import numpy as np
import pytest

from linuxguard.detection.anomaly import (
    DetectorNotFittedError,
    IsolationForestDetector,
    ModelIntegrityError,
    WindowAggregator,
    load_detector,
    save_detector,
    split_into_windows,
)
from linuxguard.detection.anomaly.features import FEATURE_NAMES, FeatureExtractor, is_public_address
from linuxguard.detection.anomaly.windows import ActivityWindow, anomaly_entity
from linuxguard.domain.events import EventCategory, Outcome
from tests.helpers import routine_windows, scan_window


@pytest.fixture
def trained_detector(make_event):
    return IsolationForestDetector(n_estimators=50, random_state=1).fit(routine_windows(make_event))


def test_window_aggregator_closes_windows_after_lateness(make_event) -> None:
    aggregator = WindowAggregator(window_seconds=60, lateness_seconds=5)
    assert aggregator.add(make_event(timestamp=0.0)) == []
    assert aggregator.add(make_event(timestamp=30.0)) == []
    assert aggregator.add(make_event(timestamp=62.0)) == []
    closed = aggregator.add(make_event(timestamp=66.0))
    assert len(closed) == 1 and len(closed[0].events) == 2
    assert aggregator.advance(200.0)[0].start == 60.0
    assert aggregator.flush() == []


def test_entities_separate_sessions_and_remote_sources(make_event) -> None:
    assert anomaly_entity(make_event(session_id="4")) == "alice@session:4"
    remote = make_event(category=EventCategory.AUTHENTICATION, src_ip="203.0.113.7")
    assert anomaly_entity(remote) == "remote:203.0.113.7"
    assert anomaly_entity(make_event(user=None, effective_user=None)) == "system"
    windows = split_into_windows([make_event(timestamp=1.0, session_id="1"), make_event(timestamp=2.0, session_id="2")])
    assert len(windows) == 2


def test_feature_extraction_counts_activity(make_event) -> None:
    window = ActivityWindow(
        "alice",
        9 * 3600.0,
        9 * 3600.0 + 60,
        [
            make_event(executable="/tmp/x", auid=1001),
            make_event(executable="/usr/bin/ls", effective_user="root", user="alice"),
            make_event(category=EventCategory.NETWORK_CONNECTION, dest_ip="8.8.8.8", dest_port=53),
            make_event(category=EventCategory.NETWORK_CONNECTION, dest_ip="10.0.0.5", dest_port=22),
            make_event(category=EventCategory.FILE_MODIFICATION, target_path="/etc/passwd"),
            make_event(category=EventCategory.AUTHENTICATION, outcome=Outcome.FAILURE),
            make_event(category=EventCategory.KERNEL_MODULE),
        ],
    )
    features = FeatureExtractor().fit([window]).raw_features(window)
    assert set(features) == set(FEATURE_NAMES)
    assert features["execution_count"] == 2
    assert features["network_count"] == 2
    assert features["external_network_count"] == 1
    assert features["distinct_destinations"] == 2
    assert features["auth_failure_count"] == 1
    assert features["privileged_count"] == 1
    assert features["security_change_count"] == 3
    assert features["off_hours_activity"] == 0


def test_off_hours_activity_only_counts_interactive_users(make_event) -> None:
    night = 3 * 3600.0
    interactive = ActivityWindow("alice", night, night + 60, [make_event(auid=1001), make_event(auid=1001)])
    system = ActivityWindow("root", night, night + 60, [make_event(auid=0, user="root")])
    extractor = FeatureExtractor()
    assert extractor.raw_features(interactive)["off_hours_activity"] == 2
    assert extractor.raw_features(system)["off_hours_activity"] == 0


def test_rarity_is_higher_for_unseen_values(make_event) -> None:
    windows = routine_windows(make_event, count=50)
    extractor = FeatureExtractor().fit(windows)
    known = ActivityWindow("a", 0, 60, [make_event(executable="/usr/bin/ls")])
    unknown = ActivityWindow("a", 0, 60, [make_event(executable="/home/a/.cache/miner")])
    assert extractor.raw_features(unknown)["executable_rarity"] > extractor.raw_features(known)["executable_rarity"]


def test_public_address_classification() -> None:
    assert is_public_address("8.8.8.8")
    assert is_public_address("203.0.113.5")
    assert not is_public_address("10.1.2.3")
    assert not is_public_address("127.0.0.1")
    assert not is_public_address("fe80::1")
    assert not is_public_address("not-an-ip")
    assert not is_public_address(None)


def test_detector_requires_training(make_event) -> None:
    detector = IsolationForestDetector()
    with pytest.raises(DetectorNotFittedError):
        detector.detect([scan_window(make_event)])
    with pytest.raises(ValueError):
        detector.fit(routine_windows(make_event, count=5))


def test_detector_threshold_matches_training_quantile(trained_detector) -> None:
    flagged = np.mean(trained_detector.training_scores > trained_detector.threshold)
    assert flagged <= 1 - trained_detector.threshold_quantile + 0.01
    assert trained_detector.training_windows == 400


def test_detector_flags_scan_and_explains_it(trained_detector, make_event) -> None:
    findings = trained_detector.detect([scan_window(make_event)])
    assert len(findings) == 1
    finding = findings[0]
    assert "distinct_destinations" in finding.exceeded_features
    assert finding.contributions[0].name in finding.exceeded_features
    assert all(not math.isnan(item.deviation) for item in finding.contributions)


def test_routine_windows_are_rarely_flagged(trained_detector, make_event) -> None:
    fresh = routine_windows(make_event, count=200, seed=11)
    assert len(trained_detector.detect(fresh)) <= 6


def test_range_guard_can_be_disabled(trained_detector, make_event) -> None:
    window = scan_window(make_event)
    plain = trained_detector.with_range_guard(False)
    assert plain.exceeded_features(plain.extractor.raw_features(window)) == []
    assert trained_detector.range_guard is True


def test_threshold_variants_do_not_modify_original(trained_detector) -> None:
    strict = trained_detector.with_threshold_quantile(0.999)
    assert strict.threshold >= trained_detector.threshold
    assert trained_detector.threshold_quantile == 0.995
    with pytest.raises(ValueError):
        trained_detector.with_threshold_quantile(1.5)


def test_model_round_trip_and_integrity_check(trained_detector, make_event, tmp_path) -> None:
    path = save_detector(trained_detector, tmp_path / "models" / "model.joblib")
    restored = load_detector(path)
    window = scan_window(make_event)
    assert restored.threshold == trained_detector.threshold
    assert np.allclose(restored.score([window]), trained_detector.score([window]))
    with open(path, "ab") as handle:
        handle.write(b"tampered")
    with pytest.raises(ModelIntegrityError):
        load_detector(path)


def test_model_without_digest_is_refused(trained_detector, tmp_path) -> None:
    path = save_detector(trained_detector, tmp_path / "model.joblib")
    (tmp_path / "model.joblib.sha256").unlink()
    with pytest.raises(ModelIntegrityError):
        load_detector(path)
    with pytest.raises(FileNotFoundError):
        load_detector(tmp_path / "missing.joblib")
