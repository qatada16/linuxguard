from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from linuxguard.config import load_config


CODE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = CODE_DIR / "config" / "linuxguard.yaml"


@pytest.fixture
def config_file(tmp_path):
    settings = yaml.safe_load(DEFAULT_CONFIG.read_text())
    settings["detection"]["rules_path"] = "rules.yaml"
    (tmp_path / "rules.yaml").write_text("[]\n")
    path = tmp_path / "linuxguard.yaml"
    path.write_text(yaml.safe_dump(settings))
    return path, settings


def test_default_config_resolves_paths_without_creating_database():
    config = load_config(DEFAULT_CONFIG)
    assert config["storage"]["database"] == CODE_DIR / "data" / "linuxguard.db"
    assert config["collector"]["ssh_host"] == "lg"
    assert config["ai"]["mode"] == "standard"


@pytest.mark.parametrize(
    "section,field,value,message",
    [
        ("collector", "ssh_host", "", "collector.ssh_host"),
        ("detection", "window_seconds", 0, "positive integer"),
        ("detection", "window_seconds", True, "positive integer"),
        ("ml", "n_estimators", -1, "positive integer"),
        ("ml", "random_state", -1, "ml.random_state"),
        ("ml", "threshold_percentile", float("nan"), "ml.threshold_percentile"),
        ("ml", "threshold_percentile", 100, "ml.threshold_percentile"),
        ("ai", "mode", "unexpected", "ai.mode"),
        ("ai", "timeout_seconds", "15", "positive integer"),
    ],
)
def test_invalid_setting_is_rejected(config_file, section, field, value, message):
    path, settings = config_file
    settings[section][field] = value
    path.write_text(yaml.safe_dump(settings))
    with pytest.raises(ValueError, match=message):
        load_config(path)


@pytest.mark.parametrize("contents", ["", "[one, two]", "collector: [broken", "collector: {}"])
def test_invalid_document_is_rejected(tmp_path, contents):
    path = tmp_path / "bad.yaml"
    path.write_text(contents)
    with pytest.raises(ValueError):
        load_config(path)


def test_paths_follow_config_location_not_working_directory(config_file, monkeypatch):
    path, _ = config_file
    monkeypatch.chdir(path.parent.parent)
    config = load_config(path)
    assert config["storage"]["database"] == (path.parent / "../data/linuxguard.db").resolve()
    assert not config["storage"]["database"].exists()


@pytest.mark.parametrize("contents", ["not: a-list", "[broken"])
def test_bad_rules_file_is_rejected(config_file, contents):
    path, _ = config_file
    (path.parent / "rules.yaml").write_text(contents)
    with pytest.raises(ValueError):
        load_config(path)


def test_missing_rules_file_is_rejected(config_file):
    path, _ = config_file
    (path.parent / "rules.yaml").unlink()
    with pytest.raises(ValueError, match="cannot read rules file"):
        load_config(path)


def test_missing_config_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="cannot read"):
        load_config(tmp_path / "missing.yaml")


def test_cli_reports_valid_config_from_another_directory(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "linuxguard", "check-config", "--config", str(DEFAULT_CONFIG)],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "Configuration valid" in result.stdout
    assert "no collection or detection was run" in result.stdout


def test_cli_reports_missing_config_without_traceback(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "linuxguard", "check-config", "--config", str(tmp_path / "missing.yaml")],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "Configuration error:" in result.stderr
    assert "Traceback" not in result.stderr
