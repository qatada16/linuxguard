"""Configuration checks, audit collection, batch normalization, and SQLite ingestion."""

import argparse
from pathlib import Path
import sqlite3

from linuxguard.config import load_config
from linuxguard.collector import collect, CollectionError
from linuxguard.parser import parse_file
from linuxguard.pipeline import run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check-config", help="Validate settings without connecting to services")
    check.add_argument("--config", type=Path, default=Path("config/linuxguard.yaml"))
    collector = commands.add_parser("collect", help="Append new complete audit lines from SSH or a local file")
    collector.add_argument("--config", type=Path, default=Path("config/linuxguard.yaml"))
    collector.add_argument("--file", type=Path, help="Replay a local source instead of SSH")
    collector.add_argument("--output", type=Path, required=True, help="Append-only raw capture")
    collector.add_argument("--state", type=Path, help="Cursor file; defaults to the configured state path")
    normalizer = commands.add_parser("parse", help="Rebuild a normalized JSONL view from a raw capture")
    normalizer.add_argument("--file", type=Path, required=True)
    normalizer.add_argument("--output", type=Path, required=True)
    normalizer.add_argument("--host", default="unknown", help="Source host for records without node=")
    normalizer.add_argument("--passwd-file", type=Path, help="Captured target passwd file for UID names")
    pipeline = commands.add_parser("pipeline", help="Collect, normalize, and upsert evidence into SQLite")
    pipeline.add_argument("--config", type=Path, default=Path("config/linuxguard.yaml"))
    pipeline.add_argument("--file", type=Path, help="Replay a local source instead of SSH")
    pipeline.add_argument("--output", type=Path, required=True, help="Append-only raw capture")
    pipeline.add_argument("--state", type=Path, help="Cursor file; defaults to the configured state path")
    pipeline.add_argument("--database", type=Path, help="SQLite file; defaults to the configured database")
    pipeline.add_argument("--host", help="Source host; defaults to SSH reader hostname, or unknown for local replay")
    pipeline.add_argument("--passwd-file", type=Path, help="Captured target passwd file for UID names")
    pipeline.add_argument("--detect", action="store_true", help="Run configured rules after ingestion")
    pipeline.add_argument("--settled", action="store_true",
                          help="Treat the capture as complete (requires --file --detect); skips the settle horizon")
    args = parser.parse_args()
    try:
        if args.command == "parse":
            result = parse_file(args.file, args.output, host=args.host, passwd_file=args.passwd_file)
            print(f"Parsed {result.records} records into {len(result.events)} events; malformed lines: {result.malformed_lines}")
            print(f"Normalized evidence: {args.output.resolve()}")
            print("Batch view only: recollect and reparse to complete the last live event.")
            return
        config = load_config(args.config)
        if args.command == "pipeline":
            if args.settled and not (args.file and args.detect):
                parser.error("--settled requires --file and --detect; live captures are never settled")
            result = run_pipeline(output=args.output, state=args.state or config["collector"]["state_path"],
                                  database=args.database or config["storage"]["database"], file=args.file,
                                  ssh_host=None if args.file else config["collector"]["ssh_host"],
                                  log_path=config["collector"]["log_path"], host=args.host,
                                  passwd_file=args.passwd_file,
                                  rules=config["detection"]["rules"] if args.detect else None,
                                  settle_seconds=config["detection"]["settle_seconds"], settled=args.settled)
            print(f"Collected {result.collection.bytes_written} new bytes; parsed {len(result.parsed.events)} events")
            print(f"Database: {result.stored.inserted} inserted, {result.stored.updated} updated, "
                  f"{result.stored.unchanged} unchanged")
            if result.detection is None:
                print("Batch ingestion only: later polls can enrich events; no detection was run.")
            else:
                d = result.detection
                print(f"Detection: {d.new_alerts} new alert(s), {d.alerts} total; "
                      f"evaluated {d.evaluated} events, deferred {d.deferred} unsettled.")
            return
        if args.command == "collect":
            result = collect(output=args.output, state=args.state or config["collector"]["state_path"],
                             file=args.file, ssh_host=None if args.file else config["collector"]["ssh_host"],
                             log_path=config["collector"]["log_path"])
            print(f"Collected {result.bytes_written} new bytes; rotated files read: {len(result.rotated_files)}")
            print(f"Raw evidence: {result.output}")
            print(f"Cursor: {result.state}")
            return
        print(f"Configuration valid: {args.config.resolve()}")
        print(f"SSH target: {config['collector']['ssh_host']}")
        print(f"Database: {config['storage']['database']}")
        print(f"AI mode: {config['ai']['mode']}")
        print(f"Detection rules loaded: {len(config['detection']['rules'])}")
        print("Configuration check only: no collection or detection was run.")
    except (ValueError, OSError, CollectionError, sqlite3.Error) as exc:
        label = "Configuration" if args.command == "check-config" else args.command.capitalize()
        parser.exit(2, f"{label} error: {exc}\n")


if __name__ == "__main__":
    main()
