"""Headless smoke test for the Streamlit dashboard via streamlit.testing (no browser)."""

from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
APP = Path(__file__).resolve().parents[1] / "linuxguard" / "dashboard" / "app.py"
PROBES_DB = Path(__file__).resolve().parents[1] / "data" / "experiments" / "phase6-rules-20261128" / "probes-rules.db"


def test_app_runs_with_a_missing_database_without_crashing():
    at = AppTest.from_file(str(APP)); at.run(timeout=30)
    assert not at.exception
    at.sidebar.text_input[0].set_value("/no/such/file.db").run(timeout=30)
    assert not at.exception and any("not found" in e.value for e in at.error)


@pytest.mark.skipif(not PROBES_DB.exists(), reason="probes experiment DB not present")
def test_alerts_page_renders_real_alerts():
    at = AppTest.from_file(str(APP))
    at.run(timeout=30)
    at.sidebar.text_input[0].set_value(str(PROBES_DB))
    at.sidebar.radio[0].set_value("Alerts")
    at.run(timeout=60)
    assert not at.exception
