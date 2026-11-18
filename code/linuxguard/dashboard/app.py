"""Streamlit investigation dashboard (Phase 8): alerts, timelines, evidence and reports.

Reads the local SQLite evidence database directly; no AI and no VM access. Run with:

    streamlit run linuxguard/dashboard/app.py

All logic lives in linuxguard.storage and linuxguard.reports (unit-tested); this file is
only the UI, so importing it does not run anything.
"""

import collections
import importlib.util
from pathlib import Path

import pandas as pd
import streamlit as st

from linuxguard.config import load_config
from linuxguard.reports import incident_markdown
from linuxguard.storage import EvidenceStore

_ROOT = Path(__file__).resolve().parents[2]


def _default_db():
    try:
        return str(load_config(_ROOT / "config" / "linuxguard.yaml")["storage"]["database"])
    except Exception:
        return str(_ROOT / "data" / "linuxguard.db")


def _evaluate_module():
    spec = importlib.util.spec_from_file_location("evaluate", _ROOT / "eval" / "evaluate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def overview(store):
    st.header("Overview")
    alerts = store.list_alerts()
    if not alerts:
        st.info("No alerts in this database yet. Run the pipeline with --detect (and --model for ML).")
    col1, col2, col3 = st.columns(3)
    col1.metric("Alerts", len(alerts))
    col2.metric("Rule", sum(a["source"] == "rule" for a in alerts))
    col3.metric("ML", sum(a["source"] == "ml" for a in alerts))
    if alerts:
        sev = collections.Counter(a["severity"] for a in alerts)
        st.subheader("By severity")
        st.bar_chart(pd.Series(sev, name="alerts"))
    events = store.events()
    st.metric("Events", len(events))
    if events:
        minutes = collections.Counter(e["ts"][:16] for e in events)  # bucket by minute
        series = pd.Series(dict(sorted(minutes.items())), name="events")
        st.subheader("Event volume over time (per minute)")
        st.bar_chart(series)


def alerts_page(store):
    st.header("Alerts")
    c1, c2, c3 = st.columns(3)
    source = c1.selectbox("Source", ["(any)", "rule", "ml"])
    severity = c2.selectbox("Severity", ["(any)", "critical", "high", "medium", "low"])
    status = c3.selectbox("Status", ["(any)", "new", "investigating", "closed"])
    rows = store.list_alerts(source=None if source == "(any)" else source,
                             severity=None if severity == "(any)" else severity,
                             status=None if status == "(any)" else status)
    if not rows:
        st.info("No alerts match these filters.")
        return
    st.dataframe(pd.DataFrame(rows)[["id", "ts", "source", "rule_id", "severity", "status",
                                     "evidence_count", "title"]], use_container_width=True, hide_index=True)
    aid = st.selectbox("Inspect alert", [r["id"] for r in rows],
                       format_func=lambda i: f"#{i} " + next(r["title"] for r in rows if r["id"] == i))
    alert = store.get_alert(aid)
    st.markdown(f"**{alert['title']}** — {alert['source']} / {alert['severity']}")
    st.code(alert["reason"], language=None)

    s1, s2 = st.columns([2, 1])
    new_status = s1.selectbox("Set status", ["new", "investigating", "closed"],
                              index=["new", "investigating", "closed"].index(alert["status"]))
    if s2.button("Apply status"):
        store.set_alert_status(aid, new_status)
        st.success(f"Status set to {new_status}.")
        st.rerun()

    minutes = st.slider("Correlation window (+/- minutes)", 1, 15, 2)
    related = store.related_events(aid, minutes=minutes)
    st.subheader(f"Timeline — {len(related)} related events (evidence highlighted)")
    if related:
        frame = pd.DataFrame(related)[["is_evidence", "ts", "event_type", "exe", "user", "pid", "path", "src_ip"]]
        st.dataframe(frame.style.apply(
            lambda row: ["background-color: #5b3a00" if row["is_evidence"] else "" for _ in row], axis=1),
            use_container_width=True, hide_index=True)
    with st.expander("Raw audit evidence"):
        for event in store.timeline(aid):
            st.caption(f"audit {event.get('audit_id')} (event id {event['id']})")
            st.code(event["raw"].rstrip("\n"), language=None)

    report = incident_markdown(store, aid, related_minutes=minutes)
    st.download_button("Download incident report (Markdown)", report,
                       file_name=f"incident-alert-{aid}.md", mime="text/markdown")
    with st.expander("Preview report"):
        st.markdown(report)


def evaluation_page(store_path):
    st.header("Evaluation (A: rules vs B: rules + ML)")
    st.caption("Point this at the labelled scenario test database and its labels.csv.")
    test_db = st.text_input("Test database", value=store_path)
    labels = st.text_input("labels.csv", value=str(_ROOT / "data" / "scenarios"))
    if not st.button("Run evaluation"):
        return
    if not Path(test_db).exists() or not Path(labels).exists():
        st.warning("Set an existing test database and labels.csv (produced by the 10x scenario run).")
        return
    ev = _evaluate_module()
    lbls, alerts = ev._load(test_db, labels)
    a, b, per = ev.compare(lbls, alerts)
    st.subheader("Metrics")
    st.dataframe(pd.DataFrame({"A rules": a, "B rules+ML": b}).T, use_container_width=True)
    st.subheader("Per scenario")
    st.dataframe(pd.DataFrame(per), use_container_width=True, hide_index=True)


def main():
    st.set_page_config(page_title="LinuxGuard", layout="wide")
    st.sidebar.title("LinuxGuard")
    db = st.sidebar.text_input("Evidence database", value=_default_db())
    if not Path(db).exists():
        st.error(f"Database not found: {db}")
        return
    page = st.sidebar.radio("View", ["Overview", "Alerts", "Evaluation"])
    with EvidenceStore(db) as store:
        if page == "Overview":
            overview(store)
        elif page == "Alerts":
            alerts_page(store)
        else:
            evaluation_page(db)


main()
