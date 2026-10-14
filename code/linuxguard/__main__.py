"""Configuration checks, incremental audit collection, and batch normalization."""

import argparse
from pathlib import Path

from linuxguard.config import load_config
from linuxguard.collector import collect, CollectionError
from linuxguard.parser import parse_file


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
    args = parser.parse_args()
    try:
        if args.command == "parse":
            result = parse_file(args.file, args.output, host=args.host, passwd_file=args.passwd_file)
            print(f"Parsed {result.records} records into {len(result.events)} events; malformed lines: {result.malformed_lines}")
            print(f"Normalized evidence: {args.output.resolve()}")
            print("Batch view only: recollect and reparse to complete the last live event.")
            return
        config = load_config(args.config)
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
        print("Configuration check only: no collection or detection was run.")
    except (ValueError, OSError, CollectionError) as exc:
        label = "Configuration" if args.command == "check-config" else args.command.capitalize()
        parser.exit(2, f"{label} error: {exc}\n")


if __name__ == "__main__":
    main()
