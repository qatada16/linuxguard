from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from linuxguard.detection.rules.conditions import EventMatcher, RuleDefinitionError, validate_field_name
from linuxguard.detection.rules.model import (
    DEFAULT_SUPPRESSION_SECONDS,
    Rule,
    RuleSequence,
    SequenceStep,
    Threshold,
)
from linuxguard.domain.alerts import Severity

ALLOWED_RULE_KEYS = frozenset(
    {
        "id",
        "name",
        "description",
        "severity",
        "match",
        "exclude",
        "threshold",
        "sequence",
        "tactic",
        "technique",
        "explanation",
        "response",
        "enabled",
        "tags",
        "suppress_seconds",
    }
)


def _group_by(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    fields = (value,) if isinstance(value, str) else tuple(str(item) for item in value)
    for field in fields:
        validate_field_name(field)
    return fields


def _positive(value: Any, name: str, rule_id: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise RuleDefinitionError(f"Rule {rule_id}: {name} must be a number") from error
    if number <= 0:
        raise RuleDefinitionError(f"Rule {rule_id}: {name} must be positive")
    return number


def _non_negative(value: Any, name: str, rule_id: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise RuleDefinitionError(f"Rule {rule_id}: {name} must be a number") from error
    if number < 0:
        raise RuleDefinitionError(f"Rule {rule_id}: {name} must not be negative")
    return number


def _parse_threshold(specification: Mapping[str, Any], rule_id: str) -> Threshold:
    distinct = specification.get("distinct")
    if distinct is not None:
        validate_field_name(str(distinct))
    return Threshold(
        count=int(_positive(specification.get("count"), "threshold.count", rule_id)),
        window_seconds=_positive(specification.get("window_seconds"), "threshold.window_seconds", rule_id),
        group_by=_group_by(specification.get("group_by")),
        distinct=str(distinct) if distinct is not None else None,
    )


def _parse_sequence(specification: Mapping[str, Any], rule_id: str) -> RuleSequence:
    raw_steps = specification.get("steps") or []
    if len(raw_steps) < 2:
        raise RuleDefinitionError(f"Rule {rule_id}: a sequence needs at least two steps")
    steps = tuple(
        SequenceStep(
            matcher=EventMatcher.from_mapping(step.get("match", {})),
            min_count=int(_positive(step.get("min_count", 1), "min_count", rule_id)),
        )
        for step in raw_steps
    )
    return RuleSequence(
        steps=steps,
        within_seconds=_positive(specification.get("within_seconds"), "sequence.within_seconds", rule_id),
        group_by=_group_by(specification.get("group_by")),
    )


def parse_rule(specification: Mapping[str, Any]) -> Rule:
    rule_id = str(specification.get("id", "")).strip()
    if not rule_id:
        raise RuleDefinitionError("Every rule requires an id")
    unknown = set(specification) - ALLOWED_RULE_KEYS
    if unknown:
        raise RuleDefinitionError(f"Rule {rule_id}: unknown keys {sorted(unknown)}")
    has_match = "match" in specification
    has_sequence = "sequence" in specification
    if has_match == has_sequence:
        raise RuleDefinitionError(f"Rule {rule_id}: define exactly one of 'match' or 'sequence'")
    if has_sequence and "threshold" in specification:
        raise RuleDefinitionError(f"Rule {rule_id}: a sequence rule cannot also define a threshold")
    try:
        severity = Severity(str(specification.get("severity", "medium")).lower())
    except ValueError as error:
        raise RuleDefinitionError(f"Rule {rule_id}: invalid severity") from error
    exclusions = specification.get("exclude") or []
    if isinstance(exclusions, Mapping):
        exclusions = [exclusions]
    return Rule(
        rule_id=rule_id,
        name=str(specification.get("name", rule_id)),
        description=str(specification.get("description", "")).strip(),
        severity=severity,
        matcher=EventMatcher.from_mapping(specification["match"]) if has_match else None,
        exclusions=tuple(EventMatcher.from_mapping(item) for item in exclusions),
        threshold=_parse_threshold(specification["threshold"], rule_id) if "threshold" in specification else None,
        sequence=_parse_sequence(specification["sequence"], rule_id) if has_sequence else None,
        tactic=specification.get("tactic"),
        technique=specification.get("technique"),
        explanation=(specification.get("explanation") or "").strip() or None,
        response=tuple(str(item) for item in specification.get("response") or ()),
        enabled=bool(specification.get("enabled", True)),
        suppress_seconds=_non_negative(
            specification.get("suppress_seconds", DEFAULT_SUPPRESSION_SECONDS), "suppress_seconds", rule_id
        ),
        tags=tuple(str(item) for item in specification.get("tags") or ()),
    )


def parse_rules(document: Any) -> list[Rule]:
    if not isinstance(document, Mapping) or not isinstance(document.get("rules"), list):
        raise RuleDefinitionError("A rule file must contain a top-level 'rules' list")
    rules = [parse_rule(item) for item in document["rules"]]
    identifiers = [rule.rule_id for rule in rules]
    duplicates = {identifier for identifier in identifiers if identifiers.count(identifier) > 1}
    if duplicates:
        raise RuleDefinitionError(f"Duplicate rule ids: {sorted(duplicates)}")
    return rules


def load_rules(path: str | Path) -> list[Rule]:
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return [rule for rule in parse_rules(document) if rule.enabled]
