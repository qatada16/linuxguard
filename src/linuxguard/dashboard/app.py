import argparse
import sys

import streamlit as st

from linuxguard.application import LinuxGuard
from linuxguard.config import load_settings
from linuxguard.dashboard.views import (
    render_alerts,
    render_evaluation,
    render_overview,
    render_timeline_explorer,
)

DEFAULT_EVALUATION_RESULTS = "reports/evaluation/evaluation_results.json"


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config")
    parser.add_argument("--evaluation", default=DEFAULT_EVALUATION_RESULTS)
    known, _ = parser.parse_known_args(argv)
    return known


@st.cache_resource
def create_application(config_path: str | None) -> LinuxGuard:
    return LinuxGuard(load_settings(config_path))


def main() -> None:
    st.set_page_config(page_title="LinuxGuard", layout="wide")
    arguments = parse_arguments(sys.argv[1:])
    app = create_application(arguments.config)
    st.sidebar.title("LinuxGuard")
    st.sidebar.caption("Linux intrusion detection and investigation")
    page = st.sidebar.radio("View", ["Overview", "Alerts", "Timeline", "Evaluation"])
    st.sidebar.caption(f"Database: {app.settings.storage.database_path}")
    if page == "Overview":
        render_overview(app)
    elif page == "Alerts":
        render_alerts(app)
    elif page == "Timeline":
        render_timeline_explorer(app)
    else:
        render_evaluation(arguments.evaluation)


main()
