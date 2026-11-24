import pytest

from linuxguard.config import ConfigurationError, Settings, default_rules_path, load_settings


def test_defaults_are_valid() -> None:
    settings = load_settings()
    assert settings.detection.mode == "hybrid"
    assert settings.explanation.mode == "template"
    assert settings.api.host == "127.0.0.1"
    assert settings.explanation.cloud.consent_granted is False
    assert settings.resolved_rules_path() == default_rules_path()


def test_custom_rules_path_is_used() -> None:
    settings = Settings()
    settings.detection.rules_path = "custom.yaml"
    assert str(settings.resolved_rules_path()) == "custom.yaml"


def test_configuration_loading_and_validation(tmp_path, monkeypatch) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("detection:\n  mode: rules\n  anomaly:\n    window_seconds: 120\n")
    settings = load_settings(path)
    assert settings.detection.mode == "rules"
    assert settings.detection.anomaly.window_seconds == 120
    monkeypatch.setenv("LINUXGUARD_DATABASE", "/tmp/override.db")
    assert load_settings(path).storage.database_path == "/tmp/override.db"
    for content in ("detection:\n  mode: magic\n", "unknown: 1\n", "detection: 5\n", "- a\n"):
        path.write_text(content)
        with pytest.raises(ConfigurationError):
            load_settings(path)
    with pytest.raises(ConfigurationError):
        load_settings(tmp_path / "missing.yaml")
