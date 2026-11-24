from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from linuxguard.config import Settings
from linuxguard.domain.events import EventCategory, Outcome, SecurityEvent

FIXTURES = Path(__file__).parent / "fixtures"

EventFactory = Callable[..., SecurityEvent]


@pytest.fixture
def fixtures_directory() -> Path:
    return FIXTURES


@pytest.fixture
def make_event() -> EventFactory:
    counter = {"value": 0}

    def factory(**overrides: Any) -> SecurityEvent:
        counter["value"] += 1
        values: dict[str, Any] = {
            "timestamp": 1_700_000_000.0 + counter["value"],
            "category": EventCategory.PROCESS_EXECUTION,
            "action": "execve",
            "source": "auditd",
            "record_id": f"test:{counter['value']}",
            "outcome": Outcome.SUCCESS,
            "host": "lab",
            "user": "alice",
        }
        values.update(overrides)
        return SecurityEvent(**values)

    return factory


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    configured = Settings()
    configured.storage.database_path = str(tmp_path / "linuxguard.db")
    configured.detection.model_path = str(tmp_path / "model.joblib")
    configured.detection.mode = "rules"
    configured.collection.host_name = "lab"
    configured.collection.passwd_path = str(tmp_path / "passwd")
    configured.collection.syslog_timezone = "UTC"
    return configured
