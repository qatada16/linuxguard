import os
import socket
from dataclasses import dataclass, field, fields, is_dataclass
from importlib import resources
from pathlib import Path
from typing import Any, TypeVar

import yaml

ConfigSection = TypeVar("ConfigSection")

DEFAULT_RULES_RESOURCE = "rules/default.yaml"
ENVIRONMENT_PREFIX = "LINUXGUARD_"


class ConfigurationError(ValueError):
    pass


@dataclass(slots=True)
class StorageSettings:
    database_path: str = "data/linuxguard.db"
    store_all_events: bool = True


@dataclass(slots=True)
class CollectionSettings:
    audit_log_path: str = "/var/log/audit/audit.log"
    auth_log_paths: list[str] = field(default_factory=lambda: ["/var/log/auth.log"])
    passwd_path: str = "/etc/passwd"
    host_name: str = field(default_factory=socket.gethostname)
    poll_interval_seconds: float = 1.0
    deduplication_window_seconds: float = 2.0
    syslog_timezone: str = "local"


@dataclass(slots=True)
class AnomalySettings:
    window_seconds: int = 60
    n_estimators: int = 100
    max_samples: int = 256
    threshold_quantile: float = 0.995
    random_state: int = 42
    lateness_seconds: float = 5.0
    range_guard: bool = True
    guard_factor: float = 2.0
    guard_margin: float = 5.0


@dataclass(slots=True)
class DetectionSettings:
    mode: str = "hybrid"
    rules_path: str | None = None
    model_path: str = "models/isolation_forest.joblib"
    evidence_limit: int = 50
    anomaly: AnomalySettings = field(default_factory=AnomalySettings)


@dataclass(slots=True)
class OllamaSettings:
    base_url: str = "http://127.0.0.1:11434"
    model: str = "llama3.2"
    timeout_seconds: float = 60.0
    redact: bool = False


@dataclass(slots=True)
class CloudSettings:
    endpoint: str = "https://api.openai.com/v1/chat/completions"
    model: str = "gpt-4o-mini"
    api_key_env: str = "LINUXGUARD_CLOUD_API_KEY"
    consent_granted: bool = False
    timeout_seconds: float = 60.0


@dataclass(slots=True)
class ExplanationSettings:
    mode: str = "template"
    max_evidence_events: int = 20
    ollama: OllamaSettings = field(default_factory=OllamaSettings)
    cloud: CloudSettings = field(default_factory=CloudSettings)


@dataclass(slots=True)
class ApiSettings:
    host: str = "127.0.0.1"
    port: int = 8000
    api_key_env: str = "LINUXGUARD_API_KEY"


@dataclass(slots=True)
class Settings:
    storage: StorageSettings = field(default_factory=StorageSettings)
    collection: CollectionSettings = field(default_factory=CollectionSettings)
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    explanation: ExplanationSettings = field(default_factory=ExplanationSettings)
    api: ApiSettings = field(default_factory=ApiSettings)

    def resolved_rules_path(self) -> Path:
        if self.detection.rules_path:
            return Path(self.detection.rules_path)
        return default_rules_path()


def default_rules_path() -> Path:
    return Path(str(resources.files("linuxguard.resources").joinpath(DEFAULT_RULES_RESOURCE)))


def load_settings(path: str | Path | None = None) -> Settings:
    settings = Settings()
    if path is not None:
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigurationError(f"Configuration file not found: {config_path}")
        document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(document, dict):
            raise ConfigurationError("Configuration root must be a mapping")
        _apply_mapping(settings, document, "")
    _apply_environment(settings)
    _validate(settings)
    return settings


def _apply_mapping(section: Any, mapping: dict[str, Any], prefix: str) -> None:
    known = {item.name: item for item in fields(section)}
    for key, value in mapping.items():
        if key not in known:
            raise ConfigurationError(f"Unknown configuration key: {prefix}{key}")
        current = getattr(section, key)
        if is_dataclass(current):
            if not isinstance(value, dict):
                raise ConfigurationError(f"Configuration key {prefix}{key} must be a mapping")
            _apply_mapping(current, value, f"{prefix}{key}.")
        else:
            setattr(section, key, value)


def _apply_environment(settings: Settings) -> None:
    overrides = {
        "DATABASE": ("storage", "database_path"),
        "MODE": ("detection", "mode"),
        "MODEL": ("detection", "model_path"),
        "RULES": ("detection", "rules_path"),
        "EXPLANATION_MODE": ("explanation", "mode"),
    }
    for suffix, (section_name, attribute) in overrides.items():
        value = os.environ.get(f"{ENVIRONMENT_PREFIX}{suffix}")
        if value:
            setattr(getattr(settings, section_name), attribute, value)


def _validate(settings: Settings) -> None:
    if settings.detection.mode not in {"rules", "hybrid"}:
        raise ConfigurationError("detection.mode must be 'rules' or 'hybrid'")
    if settings.explanation.mode not in {"template", "local", "cloud"}:
        raise ConfigurationError("explanation.mode must be 'template', 'local' or 'cloud'")
    if not 0.5 < settings.detection.anomaly.threshold_quantile < 1.0:
        raise ConfigurationError("detection.anomaly.threshold_quantile must be between 0.5 and 1.0")
    if settings.detection.anomaly.window_seconds <= 0:
        raise ConfigurationError("detection.anomaly.window_seconds must be positive")
    if settings.detection.evidence_limit <= 0:
        raise ConfigurationError("detection.evidence_limit must be positive")
