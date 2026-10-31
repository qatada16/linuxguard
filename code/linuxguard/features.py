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


def _features(events, baseline_exes):
    exes = [e["exe"] for e in events if e.get("exe")]
    dirs = set()
    for e in events:
        for value in (e.get("path"), e.get("cwd")):
            if value:
                dirs.add(posixpath.dirname(value) or value)
    lengths = [len(e["cmdline"]) for e in events if e.get("cmdline")]
    fail = sum(1 for e in events if e.get("event_type") == "USER_AUTH" and e.get("success") is False)
    ok = sum(1 for e in events if e.get("event_type") == "USER_AUTH" and e.get("success") is True)
    return {
        "n_events": len(events),
        "n_exec": sum(1 for e in events if "lg_exec" in e.get("keys", [])),
        "n_auth_fail": fail,
        "n_auth_ok": ok,
        "n_sudo": sum(1 for e in events if e.get("exe") == "/usr/bin/sudo" or e.get("event_type") == "USER_CMD"),
        "n_sensitive_write": sum(1 for e in events
                                 if _SENSITIVE_KEYS.intersection(e.get("keys", [])) and e.get("success") is True),
        "n_distinct_exe": len(set(exes)),
        "n_distinct_dir": len(dirs),
        "n_distinct_srcip": len({e["src_ip"] for e in events if e.get("src_ip")}),
        "auth_fail_ratio": fail / (fail + ok) if (fail + ok) else 0.0,
        "n_new_exe": len({exe for exe in exes if exe not in baseline_exes}) if baseline_exes else 0,
        "cmdline_len_mean": sum(lengths) / len(lengths) if lengths else 0.0,
        "cmdline_len_max": max(lengths) if lengths else 0,
        "n_tmp_exec": sum(1 for e in events if (e.get("exe") or "").startswith(_TMP_PREFIXES)),
    }


def extract_windows(events, *, window_seconds, baseline_exes=None):
    """Group events into fixed per-user windows and return one feature row each.

    `baseline_exes` is the set of executables seen during training; `n_new_exe` counts
    executables outside it (0 at train time, when every exe is baseline by definition).
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    buckets = {}
    for event in events:
        start, end = _floor(event["ts"], window_seconds)
        buckets.setdefault((event.get("user") or "unknown", start, end), []).append(event)
    rows = []
    for (user, start, end), group in sorted(buckets.items()):
        rows.append({"window_start": start, "window_end": end, "user": user,
                     "features": _features(group, baseline_exes),
                     "event_ids": [e["id"] for e in group if e.get("id") is not None]})
    return rows
