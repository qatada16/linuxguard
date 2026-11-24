from collections.abc import Sequence

from linuxguard.domain.alerts import Alert, format_number
from linuxguard.domain.events import SecurityEvent
from linuxguard.investigation.timeline import Timeline, format_timestamp, summarize_event

MAX_CELL_WIDTH = 60


def _truncate(value: object, width: int = MAX_CELL_WIDTH) -> str:
    text = " ".join(str(value if value is not None else "").split())
    return text if len(text) <= width else text[: width - 3] + "..."


def render_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    cells = [[_truncate(value) for value in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in cells:
        widths = [max(width, len(cell)) for width, cell in zip(widths, row, strict=True)]
    divider = "  ".join("-" * width for width in widths)
    lines = ["  ".join(header.ljust(width) for header, width in zip(headers, widths, strict=True)), divider]
    lines += ["  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)) for row in cells]
    return "\n".join(lines)


def alert_line(alert: Alert) -> str:
    rule = f" {alert.rule_id}" if alert.rule_id else ""
    return (
        f"[{alert.severity.value.upper():8s}] {format_timestamp(alert.last_seen)} {alert.detector.value}{rule}: "
        f"{alert.title} ({alert.entity}) id={alert.alert_id}"
    )


def render_alerts(alerts: Sequence[Alert]) -> str:
    if not alerts:
        return "No alerts found."
    rows = [
        (
            alert.alert_id[:12],
            format_timestamp(alert.last_seen),
            alert.severity.value,
            alert.detector.value,
            alert.rule_id or "-",
            alert.status.value,
            alert.title,
            alert.entity,
        )
        for alert in alerts
    ]
    return render_table(("ID", "Last seen (UTC)", "Severity", "Detector", "Rule", "Status", "Title", "Entity"), rows)


def render_alert_detail(alert: Alert) -> str:
    lines = [
        f"Alert {alert.alert_id}",
        f"  Title:      {alert.title}",
        f"  Severity:   {alert.severity.value}",
        f"  Detector:   {alert.detector.value}" + (f" ({alert.rule_id})" if alert.rule_id else ""),
        f"  Status:     {alert.status.value}",
        f"  Entity:     {alert.entity}",
        f"  Observed:   {format_timestamp(alert.first_seen)} -> {format_timestamp(alert.last_seen)}",
        f"  ATT&CK:     {alert.tactic or '-'} / {alert.technique or '-'}",
        f"  Detection:  {alert.description}",
    ]
    if alert.anomaly_score is not None:
        lines.append(f"  Score:      {alert.anomaly_score:.3f} (threshold {alert.threshold:.3f})")
        for item in alert.contributions:
            lines.append(
                f"    - {item.description}: {format_number(item.value)} (baseline mean {item.baseline_mean:.2f}, "
                f"deviation {item.deviation:+.2f})"
            )
    if alert.explanation:
        lines += [f"  Explanation ({alert.explanation_provider}):", f"    {alert.explanation}"]
    lines.append(f"  Evidence ({len(alert.evidence)} events):")
    lines += [f"    {format_timestamp(event.timestamp)}  {summarize_event(event)}" for event in alert.evidence]
    return "\n".join(lines)


def render_timeline(timeline: Timeline) -> str:
    if not timeline.entries:
        return "No events in the selected time range."
    rows = [
        (
            entry.time_text,
            "*" if entry.is_evidence else "",
            entry.event.source,
            ",".join(alert_id[:8] for alert_id in entry.related_alert_ids),
            entry.summary,
        )
        for entry in timeline.entries
    ]
    return render_table(("Time (UTC)", "Evidence", "Source", "Alerts", "Activity"), rows)


def render_events(events: Sequence[SecurityEvent]) -> str:
    rows = [(format_timestamp(event.timestamp), event.source, summarize_event(event)) for event in events]
    return render_table(("Time (UTC)", "Source", "Activity"), rows)
