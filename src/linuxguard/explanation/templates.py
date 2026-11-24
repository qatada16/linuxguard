import string
from collections import Counter
from typing import Any

from linuxguard.detection.rules.model import Rule
from linuxguard.domain.alerts import Alert, DetectorType, format_number
from linuxguard.domain.events import SecurityEvent
from linuxguard.explanation.base import Explanation
from linuxguard.investigation.timeline import format_timestamp

UNKNOWN_VALUE = "unknown"
PROVIDER_NAME = "template"


class _SafeValues(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return UNKNOWN_VALUE


def _most_common(events: list[SecurityEvent], attribute: str) -> str | None:
    values = [event.field_value(attribute) for event in events]
    counted = Counter(str(value) for value in values if value not in (None, ""))
    return counted.most_common(1)[0][0] if counted else None


def template_context(alert: Alert) -> dict[str, Any]:
    events = alert.evidence
    trigger = events[-1] if events else None
    context: dict[str, Any] = _SafeValues(
        host=_most_common(events, "host") or UNKNOWN_VALUE,
        entity=alert.entity,
        count=len(events),
        first_seen=format_timestamp(alert.first_seen),
        last_seen=format_timestamp(alert.last_seen),
    )
    for attribute in (
        "user",
        "src_ip",
        "target_path",
        "target_user",
        "executable",
        "parent_executable",
        "process_name",
        "command_line",
        "dest_ip",
        "dest_port",
        "action",
    ):
        value = trigger.field_value(attribute) if trigger is not None else None
        context[attribute] = value if value not in (None, "") else (_most_common(events, attribute) or UNKNOWN_VALUE)
    context["group"] = (trigger.details.get("group") if trigger else None) or UNKNOWN_VALUE
    for attribute in ("user", "process_name"):
        distinct = sorted({str(event.field_value(attribute)) for event in events if event.field_value(attribute)})
        if distinct:
            context["distinct_values"] = ", ".join(distinct[:10])
            if len(distinct) > 1:
                break
    return context


def render_template(template: str, alert: Alert) -> str:
    return string.Formatter().vformat(template, (), template_context(alert))


class TemplateExplainer:
    name = PROVIDER_NAME

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = {rule.rule_id: rule for rule in rules or []}

    def explain(self, alert: Alert) -> Explanation:
        if alert.detector == DetectorType.ANOMALY:
            return Explanation(self._anomaly_text(alert), PROVIDER_NAME)
        rule = self._rules.get(alert.rule_id or "")
        if rule is not None and rule.explanation:
            text = render_template(rule.explanation, alert)
        else:
            text = f"{alert.title}: {alert.description}"
        return Explanation(f"{text} Detection basis: {alert.description}", PROVIDER_NAME)

    @staticmethod
    def _anomaly_text(alert: Alert) -> str:
        details = "; ".join(
            f"{item.description} was {format_number(item.value)} compared with a baseline average of "
            f"{item.baseline_mean:.2f}"
            for item in alert.contributions
        )
        return (
            f"The activity of {alert.entity} between {format_timestamp(alert.first_seen)} and "
            f"{format_timestamp(alert.last_seen)} differed from the learned baseline "
            f"(anomaly score {alert.anomaly_score:.3f}, threshold {alert.threshold:.3f}). "
            f"The most unusual characteristics were: {details or 'not available'}. "
            "Anomaly detection highlights unusual behaviour and does not by itself prove that an "
            "intrusion occurred; review the timeline to confirm whether the activity was authorised."
        )
