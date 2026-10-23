"""Collect cumulative evidence, batch-normalize it, and upsert into SQLite."""

from dataclasses import dataclass
import json
from pathlib import Path

from linuxguard.collector import collect, CollectionResult
from linuxguard.parser import load_user_names, parse_lines, ParseResult
from linuxguard.rules import detect, DetectionResult
from linuxguard.storage import EvidenceStore, InsertResult


@dataclass(frozen=True)
class PipelineResult:
    collection: CollectionResult
    parsed: ParseResult
    stored: InsertResult
    detection: DetectionResult | None = None


def run_pipeline(*, output, state, database, file=None, ssh_host=None,
                 log_path="/var/log/audit/audit.log", host=None, passwd_file=None,
                 rules=None, settle_seconds=10, settled=False) -> PipelineResult:
    """Replay the entire capture so records arriving later can enrich existing events.

    Database IDs remain stable. Detection and streaming completion are not implemented.
    """
    inputs = [Path(output).resolve(), Path(state).resolve(), Path(database).resolve()]
    if file is not None:
        inputs.append(Path(file).resolve())
    if passwd_file is not None:
        inputs.append(Path(passwd_file).resolve())
    if len(set(inputs)) != len(inputs):
        raise ValueError("raw source, capture, cursor, database, and passwd input must be different files")
    users = load_user_names(passwd_file) if passwd_file is not None else {}
    collection = collect(output=output, state=state, file=file, ssh_host=ssh_host, log_path=log_path)
    if host is None:
        # A local replay cannot infer its source machine from the host running the reader.
        host = json.loads(collection.state.read_text())["reader_host"] if ssh_host else "unknown"
    with collection.output.open(encoding="utf-8", errors="surrogateescape") as stream:
        parsed = parse_lines(stream, host=host, users=users)
    if parsed.malformed_lines:
        raise ValueError(f"{parsed.malformed_lines} malformed audit lines; raw capture preserved, database not changed")
    with EvidenceStore(database) as store:
        stored = store.insert_events(parsed.events)
        detection = None if rules is None else detect(
            store, rules, settle_seconds=settle_seconds, settled=settled)
    return PipelineResult(collection, parsed, stored, detection)
