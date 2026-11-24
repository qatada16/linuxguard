import ipaddress
import math
import posixpath
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

import numpy as np

from linuxguard.detection.anomaly.windows import ActivityWindow
from linuxguard.domain.events import EventCategory, Outcome, SecurityEvent

TEMPORARY_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
SENSITIVE_PREFIXES = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/passwd",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/",
    "/etc/cron",
    "/etc/systemd/",
    "/var/spool/cron/",
    "/root/",
    "/boot/",
    "/var/log/",
)
SECURITY_CATEGORIES = frozenset(
    {
        EventCategory.ACCOUNT_MANAGEMENT,
        EventCategory.KERNEL_MODULE,
        EventCategory.AUDIT_CONFIGURATION,
        EventCategory.PERMISSION_CHANGE,
    }
)
AUTHENTICATION_CATEGORIES = frozenset({EventCategory.AUTHENTICATION, EventCategory.LOGIN})
WORKING_HOURS = (7, 20)
INTERACTIVE_UID_MINIMUM = 1000
INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    name: str
    description: str


FEATURES: tuple[FeatureSpec, ...] = (
    FeatureSpec("execution_count", "number of processes executed"),
    FeatureSpec("file_change_count", "number of file creations, renames and deletions"),
    FeatureSpec("network_count", "number of outbound network connections"),
    FeatureSpec("external_network_count", "number of connections to public IP addresses"),
    FeatureSpec("auth_failure_count", "number of failed authentications"),
    FeatureSpec("privileged_count", "number of sudo/su uses and programs run as root by a user"),
    FeatureSpec("security_change_count", "number of security-relevant changes and sensitive file accesses"),
    FeatureSpec("distinct_executables", "number of different programs executed"),
    FeatureSpec("distinct_destinations", "number of different network destinations"),
    FeatureSpec("distinct_directories", "number of different directories modified"),
    FeatureSpec("executable_rarity", "rarity of the least common program executed"),
    FeatureSpec("destination_rarity", "rarity of the least common network destination"),
    FeatureSpec("port_rarity", "rarity of the least common destination port"),
    FeatureSpec("directory_rarity", "rarity of the least common directory modified"),
    FeatureSpec("off_hours_activity", "interactive activity outside working hours"),
)

FEATURE_NAMES: tuple[str, ...] = tuple(spec.name for spec in FEATURES)
FEATURE_DESCRIPTIONS: dict[str, str] = {spec.name: spec.description for spec in FEATURES}


def is_public_address(address: str | None) -> bool:
    if not address:
        return False
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if parsed.is_multicast or parsed.is_unspecified:
        return False
    return not any(parsed.version == network.version and parsed in network for network in INTERNAL_NETWORKS)


def _executables(window: ActivityWindow) -> list[str]:
    return [
        event.executable
        for event in window.events
        if event.category == EventCategory.PROCESS_EXECUTION and event.executable
    ]


def _destinations(window: ActivityWindow) -> list[str]:
    return [event.dest_ip for event in window.events if event.dest_ip]


def _ports(window: ActivityWindow) -> list[str]:
    return [str(event.dest_port) for event in window.events if event.dest_port is not None]


def _directories(window: ActivityWindow) -> list[str]:
    return [
        posixpath.dirname(event.target_path)
        for event in window.events
        if event.category == EventCategory.FILE_MODIFICATION and event.target_path
    ]


class FrequencyTable:
    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()
        self._total = 0

    def fit(self, values: Iterable[str]) -> "FrequencyTable":
        self._counts = Counter(values)
        self._total = sum(self._counts.values())
        return self

    def rarity(self, value: str) -> float:
        vocabulary = len(self._counts) + 1
        probability = (self._counts.get(value, 0) + 1) / (self._total + vocabulary)
        return -math.log(probability)

    def max_rarity(self, values: Iterable[str]) -> float:
        return max((self.rarity(value) for value in values), default=0.0)


VOCABULARIES: dict[str, Callable[[ActivityWindow], list[str]]] = {
    "executable": _executables,
    "destination": _destinations,
    "port": _ports,
    "directory": _directories,
}


def _is_interactive(event: SecurityEvent) -> bool:
    identity = event.auid if event.auid is not None else event.uid
    return identity is not None and identity >= INTERACTIVE_UID_MINIMUM


class FeatureExtractor:
    def __init__(self) -> None:
        self._tables = {name: FrequencyTable() for name in VOCABULARIES}

    def fit(self, windows: Iterable[ActivityWindow]) -> "FeatureExtractor":
        materialized = list(windows)
        for name, extract in VOCABULARIES.items():
            self._tables[name].fit(value for window in materialized for value in extract(window))
        return self

    def raw_features(self, window: ActivityWindow) -> dict[str, float]:
        values = dict.fromkeys(FEATURE_NAMES, 0.0)
        interactive = False
        for event in window.events:
            interactive = interactive or _is_interactive(event)
            self._count_event(event, values)
        values["distinct_executables"] = float(len(set(_executables(window))))
        values["distinct_destinations"] = float(len(set(_destinations(window))))
        values["distinct_directories"] = float(len(set(_directories(window))))
        values["executable_rarity"] = self._tables["executable"].max_rarity(_executables(window))
        values["destination_rarity"] = self._tables["destination"].max_rarity(_destinations(window))
        values["port_rarity"] = self._tables["port"].max_rarity(_ports(window))
        values["directory_rarity"] = self._tables["directory"].max_rarity(_directories(window))
        hour = datetime.fromtimestamp(window.start, UTC).hour
        outside = not WORKING_HOURS[0] <= hour < WORKING_HOURS[1]
        values["off_hours_activity"] = float(len(window.events)) if interactive and outside else 0.0
        return values

    @staticmethod
    def _count_event(event: SecurityEvent, values: dict[str, float]) -> None:
        category = event.category
        if category == EventCategory.PROCESS_EXECUTION:
            values["execution_count"] += 1
            if event.effective_user == "root" and event.user not in (None, "root"):
                values["privileged_count"] += 1
            if event.executable and event.executable.startswith(TEMPORARY_PREFIXES):
                values["security_change_count"] += 1
        elif category == EventCategory.FILE_MODIFICATION:
            values["file_change_count"] += 1
        elif category == EventCategory.NETWORK_CONNECTION:
            values["network_count"] += 1
            if is_public_address(event.dest_ip):
                values["external_network_count"] += 1
        elif category == EventCategory.PRIVILEGE_ESCALATION:
            values["privileged_count"] += 1
        elif category in AUTHENTICATION_CATEGORIES and event.outcome == Outcome.FAILURE:
            values["auth_failure_count"] += 1
        if category in SECURITY_CATEGORIES:
            values["security_change_count"] += 1
        if event.target_path and event.target_path.startswith(SENSITIVE_PREFIXES):
            values["security_change_count"] += 1

    def transform_raw(self, raw: Iterable[dict[str, float]]) -> np.ndarray:
        matrix = np.array([[row[name] for name in FEATURE_NAMES] for row in raw], dtype=float)
        if matrix.size == 0:
            return np.empty((0, len(FEATURE_NAMES)))
        return matrix

    def transform(self, windows: Iterable[ActivityWindow]) -> np.ndarray:
        return self.transform_raw(self.raw_features(window) for window in windows)
