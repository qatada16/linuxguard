import hashlib
import hmac
from pathlib import Path

import joblib

from linuxguard.detection.anomaly.detector import IsolationForestDetector

MODEL_FORMAT_VERSION = 1
DIGEST_SUFFIX = ".sha256"


class ModelIntegrityError(RuntimeError):
    pass


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            hasher.update(block)
    return hasher.hexdigest()


def digest_path_for(model_path: Path) -> Path:
    return model_path.with_name(model_path.name + DIGEST_SUFFIX)


def save_detector(detector: IsolationForestDetector, path: str | Path) -> Path:
    model_path = Path(path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"format_version": MODEL_FORMAT_VERSION, "detector": detector}, model_path)
    digest_path_for(model_path).write_text(_digest(model_path) + "\n", encoding="ascii")
    return model_path


def load_detector(path: str | Path) -> IsolationForestDetector:
    model_path = Path(path)
    digest_path = digest_path_for(model_path)
    if not model_path.is_file():
        raise FileNotFoundError(f"Model file not found: {model_path}")
    if not digest_path.is_file():
        raise ModelIntegrityError(f"Missing integrity digest {digest_path}; refusing to load the model")
    expected = digest_path.read_text(encoding="ascii").strip()
    if not hmac.compare_digest(expected, _digest(model_path)):
        raise ModelIntegrityError("Model file does not match its recorded SHA-256 digest; refusing to load")
    payload = joblib.load(model_path)
    if not isinstance(payload, dict) or payload.get("format_version") != MODEL_FORMAT_VERSION:
        raise ModelIntegrityError("Unsupported model format")
    detector = payload["detector"]
    if not isinstance(detector, IsolationForestDetector):
        raise ModelIntegrityError("Model file does not contain an IsolationForestDetector")
    return detector
