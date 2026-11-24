import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from zoneinfo import ZoneInfo

_RFC3339_PATTERN = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<program>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
)
_BSD_PATTERN = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
)
_COMPACT_OFFSET_PATTERN = re.compile(r"([+-]\d{2})(\d{2})$")


@dataclass(frozen=True, slots=True)
class SyslogRecord:
    timestamp: float
    host: str
    program: str
    pid: int | None
    message: str
    raw: str


def resolve_timezone(name: str) -> tzinfo:
    if name == "local":
        local = datetime.now().astimezone().tzinfo
        return local if local is not None else UTC
    if name.upper() == "UTC":
        return UTC
    return ZoneInfo(name)


class SyslogParser:
    def __init__(self, timezone_name: str = "local", reference_time: datetime | None = None) -> None:
        self._timezone = resolve_timezone(timezone_name)
        self._reference_time = reference_time

    def parse(self, line: str) -> SyslogRecord | None:
        stripped = line.rstrip("\r\n")
        match = _RFC3339_PATTERN.match(stripped)
        if match is not None:
            timestamp = self._parse_rfc3339(match.group("stamp"))
        else:
            match = _BSD_PATTERN.match(stripped)
            if match is None:
                return None
            timestamp = self._parse_bsd(match.group("stamp"))
        pid = match.group("pid")
        return SyslogRecord(
            timestamp=timestamp,
            host=match.group("host"),
            program=match.group("program"),
            pid=int(pid) if pid else None,
            message=match.group("message"),
            raw=stripped,
        )

    @staticmethod
    def _parse_rfc3339(stamp: str) -> float:
        normalized = stamp.replace("Z", "+00:00")
        normalized = _COMPACT_OFFSET_PATTERN.sub(r"\1:\2", normalized)
        return datetime.fromisoformat(normalized).timestamp()

    def _parse_bsd(self, stamp: str) -> float:
        reference = self._reference_time or datetime.now(self._timezone)
        parsed = datetime.strptime(f"{reference.year} {' '.join(stamp.split())}", "%Y %b %d %H:%M:%S")
        localized = parsed.replace(tzinfo=self._timezone)
        if localized - reference.astimezone(self._timezone) > timedelta(days=1):
            localized = localized.replace(year=localized.year - 1)
        return localized.timestamp()
