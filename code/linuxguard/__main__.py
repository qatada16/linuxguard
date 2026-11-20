"""Configuration checks, audit collection, batch normalization, and SQLite ingestion."""

import argparse
from pathlib import Path
import sqlite3

from linuxguard.config import load_config
from linuxguard.collector import collect, CollectionError
from linuxguard.parser import parse_file
from linuxguard.pipeline import run_pipeline
from linuxguard.storage import EvidenceStore
from linuxguard import ml as ml_module
from linuxguard import ai as ai_module


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
    pipeline.add_argument("--model", type=Path, help="Isolation Forest model; also score windows for ML alerts")
    pipeline.add_argument("--detect", action="store_true", help="Run configured rules after ingestion")
    pipeline.add_argument("--settled", action="store_true",
                          help="Treat the capture as complete (requires --file; needs --detect or --model); skips the settle horizon")
    trainer = commands.add_parser("train", help="Train an Isolation Forest on a normal-only baseline database")
    trainer.add_argument("--config", type=Path, default=Path("config/linuxguard.yaml"))
    trainer.add_argument("--database", type=Path, required=True, help="Baseline SQLite database of normal-only events")
    trainer.add_argument("--model", type=Path, help="Output model path; defaults to the configured model")
    trainer.add_argument("--provisional", action="store_true", help="Mark the model as provisional/demo-only")
    explainer = commands.add_parser("explain", help="Explain a stored alert (standard template or local model)")
    explainer.add_argument("--config", type=Path, default=Path("config/linuxguard.yaml"))
    explainer.add_argument("--database", type=Path, required=True, help="SQLite database containing the alert")
    explainer.add_argument("--alert", type=int, required=True, help="Alert id to explain")
    explainer.add_argument("--mode", choices=["standard", "local", "cloud"], help="Override the configured AI mode")
    explainer.add_argument("--endpoint", help="Override the configured Ollama endpoint")
    args = parser.parse_args()
    try:
        if args.command == "parse":
            result = parse_file(args.file, args.output, host=args.host, passwd_file=args.passwd_file)
            print(f"Parsed {result.records} records into {len(result.events)} events; malformed lines: {result.malformed_lines}")
            print(f"Normalized evidence: {args.output.resolve()}")
            print("Batch view only: recollect and reparse to complete the last live event.")
            return
        config = load_config(args.config)
        if args.command == "train":
            with EvidenceStore(args.database) as store:
                bundle = ml_module.train(
                    store, window_seconds=config["detection"]["window_seconds"],
                    n_estimators=config["ml"]["n_estimators"], random_state=config["ml"]["random_state"],
                    threshold_percentile=config["ml"]["threshold_percentile"], provisional=args.provisional)
            model_path = args.model or config["ml"]["model_path"]
            ml_module.save(bundle, model_path)
            print(f"Trained on {bundle['n_windows']} baseline windows; threshold {bundle['threshold']:.4f}")
            print(f"Model: {Path(model_path).resolve()}" + (" (PROVISIONAL)" if bundle["provisional"] else ""))
            return
        if args.command == "explain":
            with EvidenceStore(args.database) as store:
                alert = store.get_alert(args.alert)
                if alert is None:
                    parser.exit(2, f"Explain error: no alert with id {args.alert}\n")
                text, produced_by = ai_module.explain(
                    alert, store.timeline(args.alert), mode=args.mode or config["ai"]["mode"],
                    model=config["ai"]["model"], endpoint=args.endpoint or config["ai"]["endpoint"],
                    timeout=config["ai"]["timeout_seconds"])
            print(f"Alert {args.alert}: {alert['title']} [{alert['source']}/{alert['severity']}]")
            print(f"Explanation (produced by: {produced_by}):\n{text}")
            return
        if args.command == "pipeline":
            if args.settled and not (args.file and (args.detect or args.model)):
                parser.error("--settled requires --file and --detect or --model; live captures are never settled")
            model = ml_module.load(args.model) if args.model else None
            result = run_pipeline(output=args.output, state=args.state or config["collector"]["state_path"],
                                  database=args.database or config["storage"]["database"], file=args.file,
                                  ssh_host=None if args.file else config["collector"]["ssh_host"],
                                  log_path=config["collector"]["log_path"], host=args.host,
                                  passwd_file=args.passwd_file,
                                  rules=config["detection"]["rules"] if args.detect else None, model=model,
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
            if result.ml is not None:
                m = result.ml
                print(f"ML: {m.new_alerts} new alert(s), {m.alerts} total; "
                      f"scored {m.evaluated} windows, deferred {m.deferred} unsettled.")
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
