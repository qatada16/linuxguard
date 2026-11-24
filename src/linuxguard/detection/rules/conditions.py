import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from linuxguard.domain.events import SecurityEvent


class RuleDefinitionError(ValueError):
    pass


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _as_sequence(value: Any) -> tuple[Any, ...]:
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(value)
    return (value,)


def _as_mode(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 8)
    raise RuleDefinitionError(f"Invalid permission mask: {value!r}")


def _equals(actual: Any, expected: Any) -> bool:
    if actual is None:
        return expected is None
    return str(actual) == str(expected)


def _starts_with(actual: Any, expected: tuple[str, ...]) -> bool:
    text = _as_text(actual)
    return text is not None and text.startswith(expected)


def _ends_with(actual: Any, expected: tuple[str, ...]) -> bool:
    text = _as_text(actual)
    return text is not None and text.endswith(expected)


def _contains(actual: Any, expected: tuple[str, ...]) -> bool:
    text = _as_text(actual)
    return text is not None and any(item in text for item in expected)


def _numeric(actual: Any) -> float | None:
    try:
        return float(actual)
    except (TypeError, ValueError):
        return None


Comparator = Callable[[Any, Any], bool]


@dataclass(frozen=True, slots=True)
class Condition:
    field: str
    operator: str
    expected: Any
    comparator: Comparator

    def matches(self, event: SecurityEvent) -> bool:
        return self.comparator(event.field_value(self.field), self.expected)


def _compile_regex(value: Any) -> re.Pattern[str]:
    try:
        return re.compile(str(value))
    except re.error as error:
        raise RuleDefinitionError(f"Invalid regular expression {value!r}: {error}") from error


def _build_comparator(operator: str, value: Any) -> tuple[Any, Comparator]:
    if operator == "equals":
        return value, _equals
    if operator == "not_equals":
        return value, lambda actual, expected: not _equals(actual, expected)
    if operator == "in":
        expected = tuple(str(item) for item in _as_sequence(value))
        return expected, lambda actual, items: actual is not None and str(actual) in items
    if operator == "not_in":
        expected = tuple(str(item) for item in _as_sequence(value))
        return expected, lambda actual, items: actual is None or str(actual) not in items
    if operator == "prefix":
        return tuple(str(item) for item in _as_sequence(value)), _starts_with
    if operator == "not_prefix":
        expected = tuple(str(item) for item in _as_sequence(value))
        return expected, lambda actual, items: not _starts_with(actual, items)
    if operator == "suffix":
        return tuple(str(item) for item in _as_sequence(value)), _ends_with
    if operator == "contains":
        return tuple(str(item) for item in _as_sequence(value)), _contains
    if operator == "regex":
        pattern = _compile_regex(value)
        return (
            pattern,
            lambda actual, compiled: actual is not None and compiled.search(str(actual)) is not None,
        )
    if operator == "exists":
        return bool(value), lambda actual, required: (actual not in (None, "")) == required
    if operator == "gte":
        return float(value), lambda actual, limit: (number := _numeric(actual)) is not None and number >= limit
    if operator == "lte":
        return float(value), lambda actual, limit: (number := _numeric(actual)) is not None and number <= limit
    if operator == "mode_any":
        return _as_mode(value), lambda actual, mask: isinstance(actual, int) and bool(actual & mask)
    raise RuleDefinitionError(f"Unknown condition operator: {operator}")


EVENT_FIELDS = frozenset(SecurityEvent.__dataclass_fields__)


def validate_field_name(field: str) -> None:
    if field in EVENT_FIELDS or (field.startswith("details.") and len(field) > len("details.")):
        return
    raise RuleDefinitionError(f"Unknown event field: {field}")


def build_conditions(field: str, specification: Any) -> list[Condition]:
    if isinstance(specification, Mapping):
        conditions = []
        for operator, value in specification.items():
            expected, comparator = _build_comparator(str(operator), value)
            conditions.append(Condition(field, str(operator), expected, comparator))
        if not conditions:
            raise RuleDefinitionError(f"Empty condition for field {field}")
        return conditions
    operator = "in" if isinstance(specification, Sequence) and not isinstance(specification, str) else "equals"
    expected, comparator = _build_comparator(operator, specification)
    return [Condition(field, operator, expected, comparator)]


ANY_OF_KEY = "any_of"


class Matchable(Protocol):
    def matches(self, event: SecurityEvent) -> bool: ...


@dataclass(frozen=True, slots=True)
class AnyOf:
    alternatives: tuple["EventMatcher", ...]

    def matches(self, event: SecurityEvent) -> bool:
        return any(alternative.matches(event) for alternative in self.alternatives)


@dataclass(frozen=True, slots=True)
class EventMatcher:
    conditions: tuple[Matchable, ...]

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "EventMatcher":
        if not isinstance(mapping, Mapping) or not mapping:
            raise RuleDefinitionError("A matcher must be a non-empty mapping of fields to conditions")
        conditions: list[Matchable] = []
        for field, specification in mapping.items():
            if field == ANY_OF_KEY:
                conditions.append(cls._any_of(specification))
                continue
            validate_field_name(str(field))
            conditions.extend(build_conditions(str(field), specification))
        return cls(tuple(conditions))

    @classmethod
    def _any_of(cls, specification: Any) -> AnyOf:
        if not isinstance(specification, list) or len(specification) < 2:
            raise RuleDefinitionError("any_of requires a list of at least two matchers")
        return AnyOf(tuple(cls.from_mapping(item) for item in specification))

    def matches(self, event: SecurityEvent) -> bool:
        return all(condition.matches(event) for condition in self.conditions)
