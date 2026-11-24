import math
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

from linuxguard.detection.rules.model import Rule, RuleMatch
from linuxguard.domain.events import SecurityEvent

MISSING_GROUP_VALUE = "-"
EXPIRY_INTERVAL = 1000


def group_key_for(event: SecurityEvent, fields: tuple[str, ...]) -> tuple[str, ...]:
    values = []
    for name in fields:
        value = event.field_value(name)
        values.append(MISSING_GROUP_VALUE if value in (None, "") else str(value))
    return tuple(values)


def describe_group(fields: tuple[str, ...], key: tuple[str, ...]) -> str:
    if not fields:
        return "all events"
    return ", ".join(f"{name}={value}" for name, value in zip(fields, key, strict=True))


class RuleEvaluator(Protocol):
    rule: Rule

    def evaluate(self, event: SecurityEvent) -> RuleMatch | None: ...

    def expire(self, now: float) -> None: ...


class SingleEventEvaluator:
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self._suppressed_until: dict[str, float] = {}

    def evaluate(self, event: SecurityEvent) -> RuleMatch | None:
        if not self.rule.matches(event):
            return None
        scope = event.correlation_id or event.entity
        if event.timestamp < self._suppressed_until.get(scope, -math.inf):
            return None
        if self.rule.suppress_seconds > 0:
            self._suppressed_until[scope] = event.timestamp + self.rule.suppress_seconds
        return RuleMatch(self.rule, [event], (scope,), f"Event matched the conditions of '{self.rule.name}'")

    def expire(self, now: float) -> None:
        self._suppressed_until = {scope: until for scope, until in self._suppressed_until.items() if until > now}


class ThresholdEvaluator:
    def __init__(self, rule: Rule) -> None:
        if rule.threshold is None:
            raise ValueError("ThresholdEvaluator requires a threshold rule")
        self.rule = rule
        self._threshold = rule.threshold
        self._windows: dict[tuple[str, ...], deque[SecurityEvent]] = {}
        self._cooldowns: dict[tuple[str, ...], float] = {}

    def evaluate(self, event: SecurityEvent) -> RuleMatch | None:
        if not self.rule.matches(event):
            return None
        threshold = self._threshold
        key = group_key_for(event, threshold.group_by)
        if event.timestamp < self._cooldowns.get(key, -math.inf):
            return None
        window = self._windows.setdefault(key, deque())
        window.append(event)
        while window and event.timestamp - window[0].timestamp > threshold.window_seconds:
            window.popleft()
        measured = self._measure(window)
        if measured < threshold.count:
            return None
        evidence = list(window)
        window.clear()
        self._cooldowns[key] = event.timestamp + threshold.window_seconds
        return RuleMatch(self.rule, evidence, key, self._reason(measured, key))

    def _measure(self, window: deque[SecurityEvent]) -> int:
        if self._threshold.distinct is None:
            return len(window)
        values = {event.field_value(self._threshold.distinct) for event in window}
        values.discard(None)
        return len(values)

    def _reason(self, measured: int, key: tuple[str, ...]) -> str:
        threshold = self._threshold
        quantity = f"{measured} distinct {threshold.distinct} values" if threshold.distinct else f"{measured} events"
        scope = describe_group(threshold.group_by, key)
        return f"{quantity} within {threshold.window_seconds:g}s for {scope} (threshold {threshold.count})"

    def expire(self, now: float) -> None:
        horizon = now - self._threshold.window_seconds
        stale = [key for key, window in self._windows.items() if not window or window[-1].timestamp < horizon]
        for key in stale:
            del self._windows[key]
        self._cooldowns = {key: until for key, until in self._cooldowns.items() if until > now}


@dataclass(slots=True)
class SequenceProgress:
    started_at: float
    step_index: int
    counts: list[int]
    events: list[SecurityEvent] = field(default_factory=list)


class SequenceEvaluator:
    def __init__(self, rule: Rule) -> None:
        if rule.sequence is None:
            raise ValueError("SequenceEvaluator requires a sequence rule")
        self.rule = rule
        self._sequence = rule.sequence
        self._progress: dict[tuple[str, ...], SequenceProgress] = {}

    def evaluate(self, event: SecurityEvent) -> RuleMatch | None:
        if self.rule.is_excluded(event):
            return None
        steps = self._sequence.steps
        matching = [index for index, step in enumerate(steps) if step.matcher.matches(event)]
        if not matching:
            return None
        key = group_key_for(event, self._sequence.group_by)
        progress = self._progress.get(key)
        if progress is not None and event.timestamp - progress.started_at > self._sequence.within_seconds:
            del self._progress[key]
            progress = None
        if progress is None:
            if 0 not in matching:
                return None
            progress = SequenceProgress(event.timestamp, 0, [0] * len(steps))
            self._progress[key] = progress
        current = progress.step_index
        if current in matching:
            progress.counts[current] += 1
            progress.events.append(event)
            if progress.counts[current] >= steps[current].min_count:
                progress.step_index += 1
        elif any(index < current for index in matching):
            progress.counts[max(index for index in matching if index < current)] += 1
            progress.events.append(event)
        if progress.step_index < len(steps):
            return None
        del self._progress[key]
        reason = (
            f"Completed a {len(steps)}-step sequence within {self._sequence.within_seconds:g}s for "
            f"{describe_group(self._sequence.group_by, key)} (step counts {progress.counts})"
        )
        return RuleMatch(self.rule, progress.events, key, reason)

    def expire(self, now: float) -> None:
        horizon = now - self._sequence.within_seconds
        stale = [key for key, progress in self._progress.items() if progress.started_at < horizon]
        for key in stale:
            del self._progress[key]


def create_evaluator(rule: Rule) -> RuleEvaluator:
    if rule.sequence is not None:
        return SequenceEvaluator(rule)
    if rule.threshold is not None:
        return ThresholdEvaluator(rule)
    return SingleEventEvaluator(rule)


class RuleEngine:
    def __init__(self, rules: Iterable[Rule]) -> None:
        self._evaluators = [create_evaluator(rule) for rule in rules if rule.enabled]
        self._processed = 0

    @property
    def rules(self) -> list[Rule]:
        return [evaluator.rule for evaluator in self._evaluators]

    def process(self, event: SecurityEvent) -> list[RuleMatch]:
        matches = []
        for evaluator in self._evaluators:
            match = evaluator.evaluate(event)
            if match is not None:
                matches.append(match)
        self._processed += 1
        if self._processed % EXPIRY_INTERVAL == 0:
            for evaluator in self._evaluators:
                evaluator.expire(event.timestamp)
        return matches
