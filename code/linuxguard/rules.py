"""Configurable match and sliding-window threshold detection over stored events.

Rules are data (``config/rules.yaml``); see ``load_rules`` for the validated format.
Predicates read normalized fields and PATH evidence, never an audit key alone, so a
watch firing does not by itself raise an alert. Read/write intent comes from PATH
nametypes and decoded open flags; a SUID bit comes from the chmod-family mode argument.
Detection is a pure function of the stored events, so replaying evidence adds no
duplicate alerts (``EvidenceStore.insert_alert`` is fingerprinted) and never rewrites
earlier ones.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fnmatch
from pathlib import Path
import posixpath

import yaml

from linuxguard.storage import EvidenceStore, utc_timestamp


_SEVERITIES = {"low", "medium", "high", "critical"}
_GROUP_FIELDS = {"host", "src_ip", "exe", "terminal", "account", "user", "uid", "auid"}
_MATCH_PREDICATES = {"key", "event_type", "success", "exe_in", "exe_not_in",
                     "reads_any", "writes_any", "executes_any", "uid_ranges", "mode_bits_any"}
_THRESHOLD_KEYS = {"event_type", "success", "count", "within_seconds",
                   "group_by", "group_by_fallback", "followed_by"}
# shortcut: minimal x86_64 syscall-number fallback for captures without enriched
# SYSCALL= names; extend if a rule needs a syscall outside this set.
_SYSCALL_NUMBERS = {"2": "open", "257": "openat", "437": "openat2", "85": "creat",
                    "76": "truncate", "77": "ftruncate", "90": "chmod",
                    "91": "fchmod", "268": "fchmodat", "452": "fchmodat2"}
_MODE_ARG = {"chmod": "a1", "fchmod": "a1", "fchmodat": "a2", "fchmodat2": "a2"}


def _syscall(event):
    return event.get("syscall_name") or _SYSCALL_NUMBERS.get(event.get("syscall"))


def _int(value):
    try:
        return int(value, 16) if value is not None else None
    except (TypeError, ValueError):
        return None


def _accesses(event):
    """Return (reads, writes) path sets from every PATH entry, using flags and syscall.

    PARENT entries are directory context; a bare DELETE is not a write. NORMAL entries
    are classified by the open access mode (read vs write) or a known writing syscall.
    """
    syscall = _syscall(event)
    flags = _int(event.get("syscall_args", {}).get({"open": "a1"}.get(syscall, "a2")))
    accmode = flags & 3 if flags is not None else None
    writing_open = flags is not None and (accmode in (1, 2) or flags & 0o100 or flags & 0o1000)
    reading_open = accmode in (0, 2)
    writing_syscall = syscall in ("creat", "truncate", "ftruncate", "rename", "renameat", "renameat2", "link", "linkat")
    reads, writes = set(), set()
    for entry in event.get("paths", []):
        name, nametype = entry.get("name"), entry.get("nametype")
        if not name or nametype == "PARENT":
            continue
        if nametype == "CREATE":
            writes.add(name)
        elif nametype == "DELETE":
            continue
        else:  # NORMAL
            if writing_open or writing_syscall:
                writes.add(name)
            if reading_open:
                reads.add(name)
    return reads, writes


def _suid_mode(event):
    arg = _MODE_ARG.get(_syscall(event))
    mode = _int(event.get("syscall_args", {}).get(arg)) if arg else None
    return mode


def _matches(predicates, event):
    reads, writes = _accesses(event)
    executed = [event["exe"]] + [p["name"] for p in event.get("paths", []) if p.get("name") and p.get("nametype") != "PARENT"]
    for name, value in predicates.items():
        if name == "key":
            if value not in event.get("keys", []):
                return False
        elif name == "event_type":
            if event.get("event_type") != value:
                return False
        elif name == "success":
            if event.get("success") is not value:
                return False
        elif name == "exe_in":
            if event.get("exe") not in value:
                return False
        elif name == "exe_not_in":
            if event.get("exe") in value:  # missing exe is not allowlisted -> suspicious
                return False
        elif name in ("reads_any", "writes_any", "executes_any"):
            names = {"reads_any": reads, "writes_any": writes, "executes_any": executed}[name]
            if not any(fnmatch.fnmatchcase(candidate, pattern)
                       for candidate in names if candidate for pattern in value):
                return False
        elif name == "uid_ranges":
            uid = event.get("uid")
            if uid is None or not any(low <= uid <= high for low, high in value):
                return False
        elif name == "mode_bits_any":
            mode = _suid_mode(event)
            bits = int(value, 8)
            if mode is None or mode & bits != bits:
                return False
    return True


def _group(event, fields, fallback):
    def key(names):
        values = []
        for field in names:
            value = event.get(field)
            if field == "terminal" and isinstance(value, str):
                value = value[len("/dev/"):] if value.startswith("/dev/") else value
            if value is None:
                return None
            values.append((field, value))
        return tuple(values)
    return key(fields) or (key(fallback) if fallback else None)


@dataclass(frozen=True)
class DetectionResult:
    evaluated: int
    deferred: int
    alerts: int
    new_alerts: int


def load_rules(source):
    """Validate the YAML rule list and return it; reused by configuration loading."""
    if isinstance(source, (str, Path)):
        source = yaml.safe_load(Path(source).read_text(encoding="utf-8"))
    if not isinstance(source, list):
        raise ValueError("rules file must contain a YAML list (use [] until rules exist)")
    seen = set()
    for rule in source:
        if not isinstance(rule, dict):
            raise ValueError("each rule must be a mapping")
        if not isinstance(rule.get("id"), str) or not rule["id"]:
            raise ValueError("each rule needs a non-empty string id")
        if rule["id"] in seen:
            raise ValueError(f"duplicate rule id: {rule['id']}")
        seen.add(rule["id"])
        if not isinstance(rule.get("title"), str) or not rule["title"]:
            raise ValueError(f"{rule['id']}: title must be a non-empty string")
        if rule.get("severity") not in _SEVERITIES:
            raise ValueError(f"{rule['id']}: severity must be one of {sorted(_SEVERITIES)}")
        if len([kind for kind in ("match", "threshold") if kind in rule]) != 1:
            raise ValueError(f"{rule['id']}: use exactly one of match or threshold")
        if "match" in rule:
            body = rule["match"]
            if not isinstance(body, dict) or not body:
                raise ValueError(f"{rule['id']}: match must be a non-empty mapping")
            unknown = set(body) - _MATCH_PREDICATES
            if unknown:
                raise ValueError(f"{rule['id']}: unknown match predicate(s) {sorted(unknown)}")
        else:
            body = rule["threshold"]
            if not isinstance(body, dict):
                raise ValueError(f"{rule['id']}: threshold must be a mapping")
            unknown = set(body) - _THRESHOLD_KEYS
            if unknown:
                raise ValueError(f"{rule['id']}: unknown threshold key(s) {sorted(unknown)}")
            if type(body.get("count")) is not int or body["count"] < 2:
                raise ValueError(f"{rule['id']}: count must be an integer >= 2")
            if type(body.get("within_seconds")) not in (int, float) or body["within_seconds"] <= 0:
                raise ValueError(f"{rule['id']}: within_seconds must be a positive number")
            if not body.get("group_by") or set(body.get("group_by", []) + body.get("group_by_fallback", [])) - _GROUP_FIELDS:
                raise ValueError(f"{rule['id']}: group_by fields must come from {sorted(_GROUP_FIELDS)}")
    return source


def _alert(rule, events, *, window=None):
    first, last = events[0], events[-1]
    ids = [event["id"] for event in events]
    if window:
        reason = (f"{rule['title']}: {len(events)} events grouped by "
                  f"{', '.join(f'{k}={v}' for k, v in window)} between {first['ts']} and {last['ts']} "
                  f"(audit {first['audit_id']} … {last['audit_id']})")
        extra = {"window_start": first["ts"], "window_end": last["ts"]}
    else:
        who = last.get("user") or last.get("uid")
        reads, writes = _accesses(last)
        touched = ", ".join(sorted(writes | reads)) or last.get("exe") or ""
        reason = (f"{rule['title']}: {last.get('exe')} (pid {last.get('pid')}, user {who}, "
                  f"syscall {_syscall(last)}) on {touched} [audit {last['audit_id']}]")
        extra = {}
    return {"ts": last["ts"], "source": "rule", "rule_id": rule["id"],
            "severity": rule["severity"], "title": rule["title"], "reason": reason, **extra}, ids


def _threshold_alerts(rule, events):
    cfg = rule["threshold"]
    within = timedelta(seconds=cfg["within_seconds"])
    base = {key: cfg[key] for key in ("event_type", "success") if key in cfg}
    followed = cfg.get("followed_by")
    groups = {}
    for event in events:
        when = datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))
        group = _group(event, cfg["group_by"], cfg.get("group_by_fallback"))
        if group is None:
            continue
        pending = groups.setdefault(group, [])
        if _matches(base, event):
            pending.append((when, event))
        while pending and when - pending[0][0] > within:
            pending.pop(0)
        if followed is not None:
            if _matches(followed, event) and len(pending) >= cfg["count"]:
                yield _alert(rule, [e for _, e in pending] + [event], window=group)
                groups[group] = []
        elif len(pending) >= cfg["count"]:
            yield _alert(rule, [e for _, e in pending], window=group)
            groups[group] = []


def detect(store: EvidenceStore, rules, *, settle_seconds=10, settled=False) -> DetectionResult:
    """Evaluate rules over settled stored events and persist evidence-linked alerts."""
    events = store.events()
    deferred = 0
    if not settled and events:
        newest = datetime.fromisoformat(events[-1]["ts"].replace("Z", "+00:00"))
        horizon = utc_timestamp((newest - timedelta(seconds=settle_seconds)).isoformat())
        kept = [event for event in events if event["ts"] <= horizon]
        deferred = len(events) - len(kept)
        events = kept
    before = store.connection.execute("SELECT count(*) FROM alerts").fetchone()[0]
    for rule in rules:
        if "match" in rule:
            for event in events:
                if _matches(rule["match"], event):
                    alert, ids = _alert(rule, [event])
                    store.insert_alert(alert, ids)
        else:
            for alert, ids in _threshold_alerts(rule, events):
                store.insert_alert(alert, ids)
    after = store.connection.execute("SELECT count(*) FROM alerts").fetchone()[0]
    return DetectionResult(len(events), deferred, after, after - before)
