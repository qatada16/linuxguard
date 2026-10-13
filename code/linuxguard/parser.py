"""Batch normalization of raw or enriched Linux Audit records, preserving evidence."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import tempfile


_HEADER = re.compile(r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>\S+)\s+msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s*(?P<body>.*)$")
_FIELD = re.compile(r'''(?<!\S)([A-Za-z_][A-Za-z_0-9]*(?:\[\d+\])?)=("[^"]*"|'[^']*'|[^\s]+)''')
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})+")


@dataclass
class ParseResult:
    events: list[dict]
    records: int
    malformed_lines: int


def _bytes(token):
    if token[:1] in ('"', "'") and token[-1:] == token[:1]:
        return token[1:-1].encode("utf-8", errors="surrogateescape")
    if _HEX.fullmatch(token):
        return bytes.fromhex(token)
    return token.encode("utf-8", errors="surrogateescape")


def _text(token):
    if token is None:
        return None
    value = _bytes(token).decode("utf-8", errors="backslashreplace")
    return None if value in ("(null)", "(none)", "?") else value


def _word(token):
    return token.strip("\"'") if token is not None else None


def _integer(token):
    try:
        return int(_word(token))
    except (ValueError, TypeError):
        return None


def _uid(token):
    value = _integer(token)
    return value if value is not None and 0 <= value < 4294967295 else None


def _fields(body):
    fields = dict(_FIELD.findall(body))
    if any(value[:1] in ('"', "'") and value[-1:] != value[:1] for value in fields.values()):
        raise ValueError("unterminated quoted field")
    message = fields.get("msg")
    if message and message.startswith("'"):
        for key, value in _FIELD.findall(message[1:-1]):
            fields.setdefault(key, value)
    return fields


def _argv(records):
    args, chunks = {}, {}
    expected = None
    for record in records:
        if record["type"] != "EXECVE":
            continue
        expected = _integer(record["fields"].get("argc")) if "argc" in record["fields"] else expected
        for key, value in record["fields"].items():
            match = re.fullmatch(r"a(\d+)(?:\[(\d+)\])?", key)
            if match:
                index, fragment = match.groups()
                if fragment is None:
                    args[int(index)] = _bytes(value)
                else:
                    chunks.setdefault(int(index), {})[int(fragment)] = _bytes(value)
    fragments_complete = True
    for index, fragments in chunks.items():
        fragments_complete &= sorted(fragments) == list(range(len(fragments)))
        args[index] = b"".join(fragments[part] for part in sorted(fragments))
    values = [args[index].decode("utf-8", errors="backslashreplace") for index in sorted(args)]
    complete = (expected is not None and len(args) == expected and
                all(index == position for position, index in enumerate(sorted(args))) and fragments_complete)
    return values, complete


def _normalize(records, host, users):
    primary = next((record for record in records if record["type"] == "SYSCALL"), records[0])
    fields = primary["fields"]

    def find(name):
        return fields.get(name, next((r["fields"][name] for r in records if name in r["fields"]), None))

    uid, auid = _uid(find("uid")), _uid(find("auid"))
    user_id = auid if auid is not None else uid
    interpreted_name = "AUID" if auid is not None else "UID"
    interpreted = _text(primary["interpreted"].get(interpreted_name))
    user = users.get(user_id, interpreted or str(user_id)) if user_id is not None else None
    argv, argv_complete = _argv(records)
    if not argv and find("proctitle"):
        argv = [part.decode("utf-8", errors="backslashreplace")
                for part in _bytes(find("proctitle")).rstrip(b"\0").split(b"\0")]
    cwd = _text(find("cwd"))
    paths = []
    for record in records:
        if record["type"] == "PATH":
            name = _text(record["fields"].get("name"))
            if name and cwd and not posixpath.isabs(name):
                name = posixpath.normpath(posixpath.join(cwd, name))
            paths.append({"name": name, "nametype": _word(record["fields"].get("nametype")),
                          "mode": _word(record["fields"].get("mode"))})
    affected = next((p["name"] for p in paths if p["name"] and p["nametype"] != "PARENT"), None)
    success_word = _word(find("success") or find("res"))
    success = {"yes": True, "success": True, "no": False, "failed": False}.get(success_word)
    key = _text(find("key"))
    keys = key.split("\x01") if key else []
    return {
        "ts": primary["ts"], "serial": primary["serial"], "audit_id": primary["epoch"] + ":" + primary["serial"],
        "host": host, "event_type": primary["type"], "record_types": list(dict.fromkeys(r["type"] for r in records)),
        "key": keys[0] if keys else None, "keys": keys, "user": user, "uid": uid, "auid": auid,
        "euid": _uid(find("euid")), "account": _text(find("acct")),
        "pid": _integer(find("pid")), "ppid": _integer(find("ppid")),
        "exe": _text(find("exe")), "comm": _text(find("comm")),
        "cmdline": shlex.join(argv) if argv else _text(find("cmd")), "argv": argv, "argv_complete": argv_complete,
        "cwd": cwd, "path": affected, "paths": paths, "success": success, "src_ip": _text(find("addr")),
        "terminal": _text(find("terminal")),
        "arch": _word(find("arch")), "syscall": _word(find("syscall")),
        "syscall_name": _word(primary["interpreted"].get("SYSCALL")),
        "syscall_args": {name: fields[name] for name in ("a0", "a1", "a2", "a3") if name in fields},
        "raw": "".join(record["raw"] for record in records),
    }


def parse_lines(lines, *, host="unknown", users=None) -> ParseResult:
    """Group by node, timestamp, and serial. Feed a file iterator, not splitlines().

    Enriched records contain ASCII GS, which str.splitlines() would incorrectly
    treat as a line boundary. This batch parser does not declare live-event completion.
    """
    grouped = {}
    malformed = records = 0
    for raw in lines:
        if not raw.strip():
            continue
        body, _, interpreted = raw.rstrip("\r\n").partition("\x1d")
        match = _HEADER.fullmatch(body)
        if not match:
            malformed += 1
            continue
        values = match.groupdict()
        try:
            ts = (datetime(1970, 1, 1, tzinfo=timezone.utc) +
                  timedelta(microseconds=int(Decimal(values["epoch"]) * 1000000))).isoformat().replace("+00:00", "Z")
            fields, decoded_fields = _fields(values["body"]), _fields(interpreted)
        except (ValueError, OverflowError):
            malformed += 1
            continue
        node = values["node"] or host
        key = (node, values["epoch"], values["serial"])
        grouped.setdefault(key, []).append({**values, "type": values["type"], "ts": ts, "raw": raw,
                                           "fields": fields, "interpreted": decoded_fields})
        records += 1
    events = [_normalize(group, node, users or {}) for (node, _, _), group in grouped.items()]
    events.sort(key=lambda event: (event["ts"], int(event["serial"]), event["host"]))
    return ParseResult(events, records, malformed)


def load_user_names(path: str | Path) -> dict[int, str]:
    """Use a captured target passwd file, never the host's UID database."""
    users = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        columns = line.split(":")
        if len(columns) == 7 and columns[2].isdigit():
            users[int(columns[2])] = columns[0]
    return users


def parse_file(source: str | Path, output: str | Path, *, host="unknown", passwd_file=None) -> ParseResult:
    """Write a repeatable JSONL view atomically; preserve the original evidence file."""
    source, output = Path(source).resolve(), Path(output).resolve()
    if output == source or (passwd_file is not None and output == Path(passwd_file).resolve()):
        raise ValueError("normalized output must differ from raw evidence and passwd input")
    users = load_user_names(passwd_file) if passwd_file is not None else {}
    with source.open(encoding="utf-8", errors="surrogateescape") as stream:
        result = parse_lines(stream, host=host, users=users)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output.parent,
                                         prefix="." + output.name, delete=False) as stream:
            temporary = Path(stream.name)
            for event in result.events:
                stream.write(json.dumps(event) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return result
