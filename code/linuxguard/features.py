"""Fixed-window feature extraction from normalized events for anomaly detection (Phase 7).

Windows are aligned to epoch boundaries so a model trained on one capture scores another
consistently, and grouped per user so one noisy account does not mask another. Features are
plain counts and ratios computed from the same normalized fields the rules read; evidence
event ids travel with each window so an ML alert can link back to the events behind it.
"""

from datetime import datetime, timezone
import posixpath

from linuxguard.storage import utc_timestamp

# Order is fixed here so the model's feature vector stays stable across train and score.
FEATURE_NAMES = (
    "n_events", "n_exec", "n_auth_fail", "n_auth_ok", "n_sudo", "n_sensitive_write",
    "n_distinct_exe", "n_distinct_dir", "n_distinct_srcip", "auth_fail_ratio",
    "n_new_exe", "cmdline_len_mean", "cmdline_len_max", "n_tmp_exec",
)
_SENSITIVE_KEYS = {"lg_identity", "lg_priv", "lg_ssh", "lg_persist"}
_TMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")


def _floor(ts, window_seconds):
    moment = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    epoch = moment.timestamp()
    start = (int(epoch) // window_seconds) * window_seconds
    to_iso = lambda e: datetime.fromtimestamp(e, timezone.utc).isoformat().replace("+00:00", "Z")
    return utc_timestamp(to_iso(start)), utc_timestamp(to_iso(start + window_seconds))




