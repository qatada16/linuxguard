import ipaddress
import re
from dataclasses import dataclass, field

_IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6_CANDIDATE_PATTERN = re.compile(r"(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?![\w:])")
_EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_HOME_PATTERN = re.compile(r"/home/([A-Za-z0-9._-]+)")
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)
_SECRET_FLAG_PATTERN = re.compile(r"(?i)((?:--password|--token|--api-key|--secret)[= ])(\S+)")
_BEARER_PATTERN = re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)\S+")
_CREDENTIAL_URL_PATTERN = re.compile(r"(://[^/\s:@]+:)[^@\s/]+@")
_LONG_TOKEN_PATTERN = re.compile(
    r"(?<![\w/.-])(?=[A-Za-z0-9+_-]*\d)(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{32,}={0,2}(?![\w/.-])"
)
SECRET_PLACEHOLDER = "[REDACTED]"


@dataclass
class Redactor:
    known_users: set[str] = field(default_factory=set)
    known_hosts: set[str] = field(default_factory=set)
    _forward: dict[str, str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)

    def pseudonym(self, kind: str, value: str) -> str:
        key = f"{kind}:{value}"
        if key not in self._forward:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            self._forward[key] = f"{kind}-{self._counters[kind]}"
        return self._forward[key]

    @property
    def mapping(self) -> dict[str, str]:
        return {alias: key.split(":", 1)[1] for key, alias in self._forward.items()}

    def redact(self, text: str) -> str:
        if not text:
            return text
        redacted = _BEARER_PATTERN.sub(lambda match: match.group(1) + SECRET_PLACEHOLDER, text)
        redacted = _CREDENTIAL_URL_PATTERN.sub(lambda match: match.group(1) + SECRET_PLACEHOLDER + "@", redacted)
        redacted = _SECRET_ASSIGNMENT_PATTERN.sub(lambda match: match.group(1) + SECRET_PLACEHOLDER, redacted)
        redacted = _SECRET_FLAG_PATTERN.sub(lambda match: match.group(1) + SECRET_PLACEHOLDER, redacted)
        redacted = _LONG_TOKEN_PATTERN.sub(SECRET_PLACEHOLDER, redacted)
        redacted = _EMAIL_PATTERN.sub(lambda match: self.pseudonym("EMAIL", match.group(0)), redacted)
        redacted = _IPV4_PATTERN.sub(self._address_alias, redacted)
        redacted = _IPV6_CANDIDATE_PATTERN.sub(self._ipv6_alias, redacted)
        redacted = _HOME_PATTERN.sub(lambda match: "/home/" + self.pseudonym("USER", match.group(1)), redacted)
        for host in sorted(self.known_hosts, key=len, reverse=True):
            if host:
                redacted = re.sub(rf"\b{re.escape(host)}\b", self.pseudonym("HOST", host), redacted)
        for user in sorted(self.known_users, key=len, reverse=True):
            if user and user != "root":
                redacted = re.sub(rf"(?<![\w-]){re.escape(user)}(?![\w-])", self.pseudonym("USER", user), redacted)
        return redacted

    def _address_alias(self, match: re.Match[str]) -> str:
        address = match.group(0)
        if address.startswith("127.") or address == "::1":
            return address
        return self.pseudonym("IP", address)

    def _ipv6_alias(self, match: re.Match[str]) -> str:
        candidate = match.group(0)
        if "::" not in candidate and candidate.count(":") != 7:
            return candidate
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError:
            return candidate
        return self._address_alias(match)

    def restore(self, text: str) -> str:
        restored = text
        for alias, original in sorted(self.mapping.items(), key=lambda item: len(item[0]), reverse=True):
            restored = re.sub(rf"\b{re.escape(alias)}\b", original, restored)
        return restored
