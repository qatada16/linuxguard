from datetime import UTC, datetime, timedelta

import streamlit as st

from linuxguard.application import LinuxGuard
from linuxguard.dashboard.data import (
    SEVERITY_ORDER,
    alerts_frame,
    alerts_per_hour,
    evaluation_frame,
    load_evaluation,
    timeline_frame,
)
from linuxguard.domain.alerts import AlertStatus, DetectorType
from linuxguard.investigation.reports import render_html, render_markdown
from linuxguard.investigation.timeline import TimelineBuilder, format_timestamp

ALERT_LIMIT = 5000


def render_overview(app: LinuxGuard) -> None:
    st.header("Overview")
    with app.open_store() as store:
        statistics = store.statistics()
        alerts = store.list_alerts(limit=ALERT_LIMIT)
    columns = st.columns(4)
    columns[0].metric("Events stored", f"{statistics['events']:,}")
    columns[1].metric("Alerts", f"{statistics['alerts']:,}")
    columns[2].metric("Open alerts", f"{statistics['by_status'].get('open', 0):,}")
    columns[3].metric(
        "High or critical",
        f"{statistics['by_severity'].get('high', 0) + statistics['by_severity'].get('critical', 0):,}",
    )
    frame = alerts_frame(alerts)
    if frame.empty:
        st.info("No alerts yet. Ingest logs with `linuxguard ingest` or start `linuxguard monitor`.")
        return
    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by severity")
        counts = frame["severity"].value_counts().reindex(SEVERITY_ORDER, fill_value=0)
        st.bar_chart(counts, sort=False)
    with right:
        st.subheader("Alerts by detector")
        st.bar_chart(frame["detector"].value_counts())
    st.subheader("Alerts over time")
    st.area_chart(alerts_per_hour(frame))
    st.subheader("Most frequent rules")
    rules = frame[frame["detector"] == DetectorType.RULE.value].groupby(["rule", "title"]).size()
    st.dataframe(rules.sort_values(ascending=False).rename("alerts").reset_index(), hide_index=True)


def _alert_filters() -> tuple[str | None, str | None, str | None]:
    columns = st.columns(3)
    severity = columns[0].selectbox("Severity", ["all", *SEVERITY_ORDER])
    status = columns[1].selectbox("Status", ["all", *[item.value for item in AlertStatus]])
    detector = columns[2].selectbox("Detector", ["all", *[item.value for item in DetectorType]])
    return (
        None if severity == "all" else severity,
        None if status == "all" else status,
        None if detector == "all" else detector,
    )


def render_alerts(app: LinuxGuard) -> None:
    st.header("Alerts")
    severity, status, detector = _alert_filters()
    with app.open_store() as store:
        alerts = store.list_alerts(severity, status, detector, limit=ALERT_LIMIT)
    frame = alerts_frame(alerts)
    if frame.empty:
        st.info("No alerts match the selected filters.")
        return
    st.dataframe(frame.drop(columns=["id"]), hide_index=True, use_container_width=True)
    labels = {
        alert.alert_id: f"{format_timestamp(alert.last_seen)} | {alert.severity.value} | {alert.title}"
        for alert in alerts
    }
    selected = st.selectbox("Investigate alert", list(labels), format_func=labels.get)
    if selected:
        render_alert_detail(app, selected)


def render_alert_detail(app: LinuxGuard, alert_id: str) -> None:
    with app.open_store() as store:
        alert = store.get_alert(alert_id)
        timeline = TimelineBuilder(store).for_alert(alert)
    st.subheader(alert.title)
    columns = st.columns(4)
    columns[0].metric("Severity", alert.severity.value)
    columns[1].metric("Detector", alert.detector.value)
    columns[2].metric("Evidence events", len(alert.evidence))
    columns[3].metric("Anomaly score", f"{alert.anomaly_score:.3f}" if alert.anomaly_score is not None else "-")
    st.write(alert.description)
    if alert.technique:
        st.caption(f"MITRE ATT&CK: {alert.tactic} / {alert.technique}")
    if alert.contributions:
        st.dataframe(
            [
                {
                    "feature": item.description,
                    "observed": item.value,
                    "baseline mean": round(item.baseline_mean, 2),
                    "deviation": round(item.deviation, 2),
                }
                for item in alert.contributions
            ],
            hide_index=True,
        )
    _render_explanation(app, alert_id, alert.explanation, alert.explanation_provider)
    _render_status(app, alert_id, alert.status)
    st.subheader("Investigation timeline")
    st.dataframe(timeline_frame(timeline), hide_index=True, use_container_width=True)
    with app.open_store() as store:
        report = app.report(store, alert_id)
    columns = st.columns(2)
    columns[0].download_button(
        "Download HTML report", render_html(report), f"incident-{alert_id[:12]}.html", "text/html"
    )
    columns[1].download_button(
        "Download Markdown report", render_markdown(report), f"incident-{alert_id[:12]}.md", "text/markdown"
    )
    with st.expander("Raw evidence records"):
        st.code("\n".join(event.raw for event in alert.evidence[:50]), language="text")


def _render_explanation(app: LinuxGuard, alert_id: str, text: str | None, provider: str | None) -> None:
    st.subheader("Explanation")
    if text:
        st.write(text)
        st.caption(f"Source: {provider}")
    mode = st.radio("Explanation mode", ["template", "local", "cloud"], horizontal=True, key=f"mode-{alert_id}")
    consent = False
    if mode == "cloud":
        st.warning(
            "Cloud mode sends redacted alert evidence to the configured external model provider. "
            "Only enable it when this is permitted."
        )
        consent = st.checkbox(
            "I consent to sending redacted evidence to the external provider", key=f"consent-{alert_id}"
        )
    if st.button("Generate explanation", key=f"explain-{alert_id}", disabled=mode == "cloud" and not consent):
        with app.open_store() as store:
            explanation = app.explain(store, alert_id, mode, consent if mode == "cloud" else None)
        st.success(explanation.provider_label)
        st.rerun()


def _render_status(app: LinuxGuard, alert_id: str, current: AlertStatus) -> None:
    options = [item.value for item in AlertStatus]
    choice = st.selectbox("Triage status", options, index=options.index(current.value), key=f"status-{alert_id}")
    if choice != current.value and st.button("Update status", key=f"update-{alert_id}"):
        with app.open_store() as store:
            store.update_status(alert_id, AlertStatus(choice))
        st.rerun()


def render_timeline_explorer(app: LinuxGuard) -> None:
    st.header("Timeline explorer")
    with app.open_store() as store:
        statistics = store.statistics()
    if not statistics["events"]:
        st.info("No events stored yet.")
        return
    last = datetime.fromtimestamp(statistics["last_event"], UTC)
    columns = st.columns(3)
    end_date = columns[0].date_input("End date", last.date())
    end_time = columns[1].time_input("End time (UTC)", last.time().replace(microsecond=0))
    hours = columns[2].number_input("Hours to show", min_value=0.25, max_value=72.0, value=1.0, step=0.25)
    user_filter = st.text_input("Users (comma separated, optional)")
    end = datetime.combine(end_date, end_time, tzinfo=UTC)
    start = end - timedelta(hours=hours)
    users = [user.strip() for user in user_filter.split(",") if user.strip()] or None
    with app.open_store() as store:
        timeline = TimelineBuilder(store).for_range(start.timestamp(), end.timestamp(), users)
    frame = timeline_frame(timeline)
    st.caption(f"{len(frame)} events between {start:%Y-%m-%d %H:%M} and {end:%Y-%m-%d %H:%M} UTC")
    st.dataframe(frame, hide_index=True, use_container_width=True)


def render_evaluation(results_path: str) -> None:
    st.header("Evaluation: rules only vs rules + machine learning")
    summary = load_evaluation(results_path)
    if summary is None:
        st.info("Run `linuxguard evaluate` to produce evaluation results.")
        return
    frame = evaluation_frame(summary)
    st.dataframe(frame, hide_index=True, use_container_width=True)
    st.bar_chart(frame.set_index("configuration")[["precision", "recall", "false_positive_rate", "f1"]], stack=False)
    st.caption(f"Mean values across seeds {summary['seeds']}. See the evaluation report for standard deviations.")
