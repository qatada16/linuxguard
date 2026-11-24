import pytest

from linuxguard.config import default_rules_path
from linuxguard.detection.rules import load_rules
from linuxguard.domain.alerts import Alert, DetectorType, Severity
from linuxguard.evaluation import Case, CaseLabeler, load_cases, save_cases, score_alerts
from linuxguard.evaluation.metrics import ResourceUsage, safe_ratio
from linuxguard.evaluation.reporting import render_evaluation_markdown
from linuxguard.evaluation.runner import (
    BASELINE_RULES,
    DEFAULT_CONFIGURATIONS,
    evaluate_dataset,
    extract_events,
    summarize,
)
from linuxguard.evaluation.synthetic import MALICIOUS_SCENARIOS, SCENARIOS, LabeledDataset, build_dataset


@pytest.fixture(scope="module")
def dataset():
    return build_dataset(seed=21)


@pytest.fixture(scope="module")
def dataset_events(dataset):
    return extract_events(dataset)[0]


def alert_with(events) -> Alert:
    return Alert(DetectorType.RULE, "t", Severity.LOW, "d", "e", events[0].timestamp, events[-1].timestamp, events)


def test_case_matching_uses_time_and_selectors(make_event) -> None:
    case = Case("c1", "s", True, 100, 200, {"session_id": ["5"]})
    assert case.contains(make_event(timestamp=150, session_id="5"))
    assert case.contains(make_event(timestamp=200.5, session_id="5"))
    assert not case.contains(make_event(timestamp=250, session_id="5"))
    assert not case.contains(make_event(timestamp=150, session_id="6"))
    assert Case("c2", "s", False, 100, 200).contains(make_event(timestamp=150))


def test_labeler_prefers_malicious_cases(make_event) -> None:
    benign = Case("b", "work", False, 0, 1000, {"user": ["alice"]})
    malicious = Case("m", "attack", True, 100, 200, {"user": ["alice"]})
    labeler = CaseLabeler([benign, malicious])
    assert labeler.label(make_event(timestamp=150)) == "m"
    assert labeler.label(make_event(timestamp=500)) == "b"
    assert labeler.label(make_event(timestamp=5000)) is None


def test_cases_round_trip_through_json(tmp_path) -> None:
    cases = [Case("c1", "s", True, 1.0, 2.0, {"src_ip": ["1.2.3.4"]}, True, "desc")]
    save_cases(cases, tmp_path / "labels.json")
    assert load_cases(tmp_path / "labels.json") == cases
    (tmp_path / "bad.json").write_text("{}")
    with pytest.raises(ValueError):
        load_cases(tmp_path / "bad.json")


def test_scoring_counts_cases_and_ignores_benign_context_of_true_alerts(make_event) -> None:
    attack_event = make_event(timestamp=110)
    benign_context = make_event(timestamp=120)
    false_alarm = make_event(timestamp=600)
    cases = [
        Case("m1", "attack", True, 100, 200),
        Case("m2", "attack", True, 300, 400),
        Case("b1", "work", False, 100, 200),
        Case("b2", "work", False, 500, 700),
    ]
    labels = {attack_event.event_id: "m1", benign_context.event_id: "b1", false_alarm.event_id: "b2"}
    metrics = score_alerts([alert_with([attack_event, benign_context]), alert_with([false_alarm])], cases, labels)
    assert metrics.alerts == 2 and metrics.correct_alerts == 1
    assert metrics.alert_precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.false_positive_rate == 0.5
    assert metrics.case_precision == 0.5
    assert metrics.f1 == 0.5
    assert metrics.detection_delays == [20.0]
    assert metrics.detected_by_scenario == {"attack": (1, 2), "work": (1, 2)}


def test_metric_helpers_handle_empty_inputs() -> None:
    assert safe_ratio(1, 0) == 0.0
    empty = score_alerts([], [], {})
    assert empty.recall == 0.0 and empty.mean_delay_seconds == 0.0 and empty.f1 == 0.0
    usage = ResourceUsage(wall_seconds=2.0, cpu_seconds=1.0, peak_memory_mb=1.0, events=100)
    assert usage.events_per_second == 50.0 and usage.milliseconds_per_event == 20.0


def test_synthetic_dataset_is_deterministic(dataset) -> None:
    again = build_dataset(seed=21)
    assert again.audit_lines == dataset.audit_lines
    assert again.auth_lines == dataset.auth_lines
    assert [case.case_id for case in again.cases] == [case.case_id for case in dataset.cases]
    assert build_dataset(seed=22).audit_lines != dataset.audit_lines


def test_synthetic_dataset_contains_every_scenario(dataset) -> None:
    scenarios = {case.scenario for case in dataset.cases}
    assert {spec.name for spec in SCENARIOS} <= scenarios
    assert len(dataset.malicious_cases) == 2 * len(MALICIOUS_SCENARIOS)


def test_nearly_every_parsed_event_is_labelled(dataset, dataset_events) -> None:
    labels = CaseLabeler(dataset.cases).label_all(dataset_events)
    assert len(dataset_events) > 3000
    assert len(labels) / len(dataset_events) > 0.99


def test_rules_detect_every_rule_covered_scenario(dataset) -> None:
    runs = evaluate_dataset(dataset, load_rules(default_rules_path()), None, (BASELINE_RULES,))
    by_scenario = runs["rules"].metrics.detected_by_scenario
    for spec in MALICIOUS_SCENARIOS:
        detected, total = by_scenario[spec.name]
        if spec.covered_by_rules:
            assert detected == total, spec.name
        else:
            assert detected == 0, spec.name


def test_dataset_save_and_load(tmp_path, dataset) -> None:
    dataset.save(tmp_path / "data")
    loaded = LabeledDataset.load(tmp_path / "data")
    assert loaded.audit_lines == dataset.audit_lines
    assert len(loaded.cases) == len(dataset.cases)


def test_summary_and_markdown_report(dataset) -> None:
    from linuxguard.config import AnomalySettings
    from linuxguard.evaluation.runner import SeedResult, train_detector

    baseline = build_dataset(seed=99, malicious_per_scenario=0)
    detector, training, windows = train_detector(extract_events(baseline)[0], AnomalySettings(n_estimators=30))
    runs = evaluate_dataset(dataset, load_rules(default_rules_path()), detector, DEFAULT_CONFIGURATIONS)
    result = SeedResult(21, 100, len(dataset.cases), training, training, windows, runs)
    summary = summarize([result, result])
    assert set(summary["configurations"]) == {spec.key for spec in DEFAULT_CONFIGURATIONS}
    assert summary["configurations"]["rules"]["metrics"]["recall"]["std"] == 0.0
    hybrid = summary["configurations"]["hybrid"]["metrics"]["recall"]["mean"]
    assert hybrid >= summary["configurations"]["rules"]["metrics"]["recall"]["mean"]
    markdown = render_evaluation_markdown(summary)
    assert "Baseline A: rules only" in markdown and "Detection by Scenario" in markdown
