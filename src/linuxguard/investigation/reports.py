import hashlib
import html
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from linuxguard import __version__
from linuxguard.detection.rules.model import Rule
from linuxguard.domain.alerts import Alert, DetectorType, format_number
from linuxguard.domain.events import SecurityEvent
from linuxguard.investigation.timeline import Timeline, TimelineBuilder, format_timestamp

MAX_TIMELINE_ENTRIES = 200
MAX_RAW_RECORDS = 20

GENERIC_RULE_RESPONSE = (
    "Validate the evidence below with the system owner.",
    "Preserve relevant logs before making changes to the host.",
)
GENERIC_ANOMALY_RESPONSE = (
    "Review the timeline to decide whether the unusual activity was legitimate.",
    "If the activity is legitimate and recurring, include it in the next baseline training run.",
    "If it is not legitimate, escalate and preserve the host's logs and volatile data.",
)


@dataclass(frozen=True, slots=True)
class AffectedEntities:
    users: tuple[str, ...]
    hosts: tuple[str, ...]
    source_addresses: tuple[str, ...]
    destinations: tuple[str, ...]
    files: tuple[str, ...]
    executables: tuple[str, ...]

    @classmethod
    def from_events(cls, events: list[SecurityEvent]) -> "AffectedEntities":
        def collect(values: object) -> tuple[str, ...]:
            return tuple(sorted({str(value) for value in values if value}))

        return cls(
            users=collect(value for event in events for value in (event.user, event.target_user)),
            hosts=collect(event.host for event in events),
            source_addresses=collect(event.src_ip for event in events),
            destinations=collect(f"{event.dest_ip}:{event.dest_port}" for event in events if event.dest_ip is not None),
            files=collect(event.target_path for event in events),
            executables=collect(event.executable for event in events),
        )


@dataclass(slots=True)
class IncidentReport:
    alert: Alert
    timeline: Timeline
    entities: AffectedEntities
    recommendations: tuple[str, ...]
    generated_at: float = field(default_factory=time.time)
    report_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        alert = self.alert
        return {
            "report_id": self.report_id,
            "generated_at": format_timestamp(self.generated_at),
            "tool_version": __version__,
            "alert": {
                "alert_id": alert.alert_id,
                "title": alert.title,
                "detector": alert.detector.value,
                "rule_id": alert.rule_id,
                "severity": alert.severity.value,
                "status": alert.status.value,
                "entity": alert.entity,
                "first_seen": format_timestamp(alert.first_seen),
                "last_seen": format_timestamp(alert.last_seen),
                "tactic": alert.tactic,
                "technique": alert.technique,
                "description": alert.description,
                "anomaly_score": alert.anomaly_score,
                "threshold": alert.threshold,
                "contributions": [
                    {
                        "feature": item.name,
                        "description": item.description,
                        "value": item.value,
                        "baseline_mean": item.baseline_mean,
                        "deviation": item.deviation,
                    }
                    for item in alert.contributions
                ],
            },
            "explanation": {"text": alert.explanation, "provider": alert.explanation_provider},
            "entities": {
                "users": list(self.entities.users),
                "hosts": list(self.entities.hosts),
                "source_addresses": list(self.entities.source_addresses),
                "destinations": list(self.entities.destinations),
                "files": list(self.entities.files),
                "executables": list(self.entities.executables),
            },
            "recommendations": list(self.recommendations),
            "timeline": [
                {
                    "time": entry.time_text,
                    "evidence": entry.is_evidence,
                    "summary": entry.summary,
                    "event_id": entry.event.event_id,
                    "source": entry.event.source,
                }
                for entry in self.timeline.entries[:MAX_TIMELINE_ENTRIES]
            ],
            "evidence_records": [event.raw for event in alert.evidence[:MAX_RAW_RECORDS]],
        }


class ReportBuilder:
    def __init__(self, timeline_builder: TimelineBuilder, rules: list[Rule] | None = None) -> None:
        self._timelines = timeline_builder
        self._rules = {rule.rule_id: rule for rule in rules or []}

    def build(self, alert: Alert) -> IncidentReport:
        timeline = self._timelines.for_alert(alert)
        return IncidentReport(
            alert=alert,
            timeline=timeline,
            entities=AffectedEntities.from_events(alert.evidence),
            recommendations=self._recommendations(alert),
        )

    def _recommendations(self, alert: Alert) -> tuple[str, ...]:
        if alert.detector == DetectorType.ANOMALY:
            return GENERIC_ANOMALY_RESPONSE
        rule = self._rules.get(alert.rule_id or "")
        if rule is not None and rule.response:
            return rule.response
        return GENERIC_RULE_RESPONSE


def _markdown_text(value: object) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "'")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return " ".join(text.split())


def render_markdown(report: IncidentReport) -> str:
    payload = report.to_dict()
    alert = payload["alert"]
    lines = [
        f"# Incident Report: {_markdown_text(alert['title'])}",
        "",
        f"- **Report ID:** {payload['report_id']}",
        f"- **Generated:** {payload['generated_at']} by LinuxGuard {payload['tool_version']}",
        f"- **Alert ID:** {alert['alert_id']}",
        f"- **Severity:** {alert['severity'].upper()}",
        f"- **Detector:** {alert['detector']}" + (f" ({alert['rule_id']})" if alert["rule_id"] else ""),
        f"- **Status:** {alert['status']}",
        f"- **Entity:** {_markdown_text(alert['entity'])}",
        f"- **Observed:** {alert['first_seen']} to {alert['last_seen']}",
    ]
    if alert["tactic"] or alert["technique"]:
        lines.append(f"- **ATT&CK:** {alert['tactic'] or '-'} / {alert['technique'] or '-'}")
    lines += ["", "## Detection", "", _markdown_text(alert["description"]), ""]
    if alert["anomaly_score"] is not None:
        lines += [
            f"Anomaly score **{alert['anomaly_score']:.3f}** against threshold **{alert['threshold']:.3f}**.",
            "",
            "| Feature | Observed | Baseline mean | Deviation |",
            "| --- | ---: | ---: | ---: |",
        ]
        lines += [
            f"| {_markdown_text(item['description'])} | {format_number(item['value'])} | {item['baseline_mean']:.2f} | "
            f"{item['deviation']:+.2f} |"
            for item in alert["contributions"]
        ]
        lines.append("")
    explanation = payload["explanation"]
    lines += ["## Explanation", ""]
    if explanation["text"]:
        lines += [
            _markdown_text(explanation["text"]),
            "",
            f"_Source: {_markdown_text(explanation['provider'])}_",
        ]
    else:
        lines.append("_No explanation has been generated for this alert._")
    lines += ["", "## Affected Entities", ""]
    for label, key in (
        ("Users", "users"),
        ("Hosts", "hosts"),
        ("Source addresses", "source_addresses"),
        ("Destinations", "destinations"),
        ("Files", "files"),
        ("Executables", "executables"),
    ):
        values = payload["entities"][key]
        if values:
            lines.append(f"- **{label}:** {', '.join(_markdown_text(value) for value in values)}")
    lines += ["", "## Recommended Actions", ""]
    lines += [f"{index}. {_markdown_text(item)}" for index, item in enumerate(payload["recommendations"], 1)]
    lines += [
        "",
        "## Timeline",
        "",
        "| Time (UTC) | Evidence | Source | Activity |",
        "| --- | :---: | --- | --- |",
    ]
    lines += [
        f"| {entry['time']} | {'yes' if entry['evidence'] else ''} | {entry['source']} | "
        f"{_markdown_text(entry['summary'])} |"
        for entry in payload["timeline"]
    ]
    lines += ["", "## Raw Evidence Records", "", "```text"]
    lines += [record.replace("```", "'''") for record in payload["evidence_records"]]
    lines += ["```", ""]
    return "\n".join(lines)


def render_html(report: IncidentReport) -> str:
    payload = report.to_dict()
    alert = payload["alert"]
    escape = html.escape

    def definition(label: str, value: object) -> str:
        return f"<dt>{escape(label)}</dt><dd>{escape('' if value is None else str(value))}</dd>"

    entity_items = "".join(
        f"<li><strong>{escape(label.replace('_', ' ').capitalize())}:</strong> {escape(', '.join(values))}</li>"
        for label, values in payload["entities"].items()
        if values
    )
    contribution_rows = "".join(
        f"<tr><td>{escape(item['description'])}</td><td>{format_number(item['value'])}</td>"
        f"<td>{item['baseline_mean']:.2f}</td><td>{item['deviation']:+.2f}</td></tr>"
        for item in alert["contributions"]
    )
    timeline_rows = "".join(
        f'<tr class="{"evidence" if entry["evidence"] else ""}"><td>{escape(entry["time"])}</td>'
        f"<td>{'&#10003;' if entry['evidence'] else ''}</td><td>{escape(entry['source'])}</td>"
        f"<td>{escape(entry['summary'])}</td></tr>"
        for entry in payload["timeline"]
    )
    recommendations = "".join(f"<li>{escape(item)}</li>" for item in payload["recommendations"])
    explanation = payload["explanation"]
    explanation_html = (
        f'<p>{escape(explanation["text"])}</p><p class="muted">Source: {escape(explanation["provider"] or "")}</p>'
        if explanation["text"]
        else '<p class="muted">No explanation has been generated for this alert.</p>'
    )
    anomaly_html = ""
    if alert["anomaly_score"] is not None:
        anomaly_html = (
            f"<p>Anomaly score <strong>{alert['anomaly_score']:.3f}</strong> against threshold "
            f"<strong>{alert['threshold']:.3f}</strong>.</p><table><thead><tr><th>Feature</th><th>Observed</th>"
            f"<th>Baseline mean</th><th>Deviation</th></tr></thead><tbody>{contribution_rows}</tbody></table>"
        )
    raw_records = escape("\n".join(payload["evidence_records"]))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>LinuxGuard Incident Report</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; color: #1d2430; }}
h1 {{ font-size: 1.6rem; }} h2 {{ border-bottom: 1px solid #d0d7de; padding-bottom: .3rem; margin-top: 2rem; }}
dl {{ display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; }} dt {{ font-weight: 600; }}
table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
th, td {{ border: 1px solid #d0d7de; padding: .35rem .5rem; text-align: left; vertical-align: top; }}
tr.evidence {{ background: #fff4e5; }} .muted {{ color: #57606a; }}
pre {{ background: #f6f8fa; padding: 1rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
.severity {{ text-transform: uppercase; font-weight: 700; }}
</style>
</head>
<body>
<h1>Incident Report: {escape(alert["title"])}</h1>
<dl>
{definition("Report ID", payload["report_id"])}
{definition("Generated", f"{payload['generated_at']} (LinuxGuard {payload['tool_version']})")}
{definition("Alert ID", alert["alert_id"])}
<dt>Severity</dt><dd class="severity">{escape(alert["severity"])}</dd>
{definition("Detector", alert["detector"] + (f" ({alert['rule_id']})" if alert["rule_id"] else ""))}
{definition("Status", alert["status"])}
{definition("Entity", alert["entity"])}
{definition("Observed", f"{alert['first_seen']} to {alert['last_seen']}")}
{definition("ATT&CK", f"{alert['tactic'] or '-'} / {alert['technique'] or '-'}")}
</dl>
<h2>Detection</h2>
<p>{escape(alert["description"])}</p>
{anomaly_html}
<h2>Explanation</h2>
{explanation_html}
<h2>Affected Entities</h2>
<ul>{entity_items}</ul>
<h2>Recommended Actions</h2>
<ol>{recommendations}</ol>
<h2>Timeline</h2>
<table><thead><tr><th>Time (UTC)</th><th>Evidence</th><th>Source</th><th>Activity</th></tr></thead>
<tbody>{timeline_rows}</tbody></table>
<h2>Raw Evidence Records</h2>
<pre>{raw_records}</pre>
</body>
</html>
"""


def render_json(report: IncidentReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


RENDERERS = {"markdown": render_markdown, "md": render_markdown, "html": render_html, "json": render_json}


def render_report(report: IncidentReport, report_format: str) -> str:
    renderer = RENDERERS.get(report_format.lower())
    if renderer is None:
        raise ValueError(f"Unsupported report format: {report_format}")
    return renderer(report)


def content_digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
