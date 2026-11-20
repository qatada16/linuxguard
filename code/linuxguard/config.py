"""Read local configuration without connecting to services or creating files."""

from pathlib import Path

import yaml

from linuxguard.rules import load_rules


def load_config(path: str | Path) -> dict:
    """Validate foundation settings and resolve local paths from the YAML file."""
    path = Path(path).resolve()
    try:
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError("configuration must be a YAML mapping")

    string_fields = {
        "collector": ("ssh_host", "log_path", "state_path"),
        "storage": ("database",),
        "detection": ("rules_path",),
        "ml": ("model_path",),
        "ai": ("mode", "model", "endpoint"),
    }
    for section, fields in string_fields.items():
        if not isinstance(config.get(section), dict):
            raise ValueError(f"{section} must be a mapping")
        for field in fields:
            value = config[section].get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{section}.{field} must be a non-empty string")

    for section, field in (
        ("detection", "window_seconds"),
        ("detection", "settle_seconds"),
        ("ml", "n_estimators"),
        ("ai", "timeout_seconds"),
    ):
        value = config[section].get(field)
        if type(value) is not int or value <= 0:
            raise ValueError(f"{section}.{field} must be a positive integer")
    if type(config["ml"].get("random_state")) is not int or not (
        0 <= config["ml"]["random_state"] < 2**32
    ):
        raise ValueError("ml.random_state must be an integer from 0 to 4294967295")
    percentile = config["ml"].get("threshold_percentile")
    if type(percentile) not in (int, float) or not 0 < percentile < 100:
        raise ValueError("ml.threshold_percentile must be between 0 and 100 (exclusive)")
    if config["ai"]["mode"] not in ("standard", "local", "cloud"):
        raise ValueError("ai.mode must be standard, local, or cloud")

    for section, field in (
        ("collector", "state_path"),
        ("storage", "database"),
        ("detection", "rules_path"),
        ("ml", "model_path"),
    ):
        config[section][field] = (path.parent / config[section][field]).resolve()
    rules_path = config["detection"]["rules_path"]
    try:
        rules = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot read rules file {rules_path}: {exc}") from exc
    config["detection"]["rules"] = load_rules(rules)
    return config
