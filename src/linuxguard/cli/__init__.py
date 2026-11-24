import argparse
import sys
from collections.abc import Sequence

from linuxguard import __version__
from linuxguard.application import LinuxGuard
from linuxguard.cli import commands
from linuxguard.config import ConfigurationError, load_settings
from linuxguard.detection.anomaly.model_store import ModelIntegrityError
from linuxguard.detection.rules.conditions import RuleDefinitionError
from linuxguard.domain.alerts import AlertStatus, DetectorType, Severity

EXIT_ERROR = 1


def _add_log_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--audit-log", action="append", default=[], help="auditd log file (repeatable)")
    parser.add_argument("--auth-log", action="append", default=[], help="auth/syslog file (repeatable)")
    parser.add_argument("--passwd", help="passwd file used to resolve user IDs")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linuxguard", description="Machine learning-assisted Linux intrusion detection and investigation"
    )
    parser.add_argument("--config", help="path to a YAML configuration file")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db", help="create the evidence database").set_defaults(
        handler=commands.command_init_database
    )

    ingest = subparsers.add_parser("ingest", help="analyse log files and store alerts")
    _add_log_arguments(ingest)
    ingest.add_argument("--mode", choices=["rules", "hybrid"])
    ingest.set_defaults(handler=commands.command_ingest)

    train = subparsers.add_parser("train", help="train the anomaly baseline from benign logs")
    _add_log_arguments(train)
    train.add_argument("--output", help="model output path")
    train.set_defaults(handler=commands.command_train)

    monitor = subparsers.add_parser("monitor", help="follow live logs and raise alerts")
    monitor.add_argument("--mode", choices=["rules", "hybrid"])
    monitor.add_argument("--from-start", action="store_true", help="process existing log content first")
    monitor.set_defaults(handler=commands.command_monitor)

    alerts = subparsers.add_parser("alerts", help="list stored alerts")
    alerts.add_argument("--severity", choices=[item.value for item in Severity])
    alerts.add_argument("--status", choices=[item.value for item in AlertStatus])
    alerts.add_argument("--detector", choices=[item.value for item in DetectorType])
    alerts.add_argument("--limit", type=int, default=50)
    alerts.set_defaults(handler=commands.command_alerts)

    show = subparsers.add_parser("show", help="show one alert with its evidence")
    show.add_argument("alert_id")
    show.set_defaults(handler=commands.command_show)

    timeline = subparsers.add_parser("timeline", help="show the investigation timeline of an alert")
    timeline.add_argument("alert_id")
    timeline.add_argument("--context", type=float, default=300.0, help="seconds of context around the alert")
    timeline.set_defaults(handler=commands.command_timeline)

    explain = subparsers.add_parser("explain", help="explain an alert in natural language")
    explain.add_argument("alert_id")
    explain.add_argument("--mode", choices=["template", "local", "cloud"])
    explain.add_argument("--yes", action="store_true", help="consent to sending redacted evidence in cloud mode")
    explain.set_defaults(handler=commands.command_explain)

    report = subparsers.add_parser("report", help="generate an incident report")
    report.add_argument("alert_id")
    report.add_argument("--format", choices=["markdown", "html", "json"], default="markdown")
    report.add_argument("--output", help="write the report to this file")
    report.add_argument("--explain", choices=["template", "local"], help="generate an explanation first")
    report.set_defaults(handler=commands.command_report)

    status = subparsers.add_parser("status", help="update the triage status of an alert")
    status.add_argument("alert_id")
    status.add_argument("status", choices=[item.value for item in AlertStatus])
    status.set_defaults(handler=commands.command_status)

    subparsers.add_parser("stats", help="show database statistics").set_defaults(handler=commands.command_stats)

    simulate = subparsers.add_parser("simulate", help="generate labelled synthetic audit and auth logs")
    simulate.add_argument("--output", required=True)
    simulate.add_argument("--seed", type=int, default=7)
    simulate.add_argument("--days", type=int, default=1)
    simulate.add_argument("--attacks", type=int, default=2, help="instances of each attack scenario per day")
    simulate.add_argument("--baseline", action="store_true", help="generate benign activity only")
    simulate.set_defaults(handler=commands.command_simulate)

    evaluate = subparsers.add_parser("evaluate", help="compare rule-only and hybrid detection")
    evaluate.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    evaluate.add_argument("--output", default="reports/evaluation")
    evaluate.add_argument("--dataset", help="evaluate a saved labelled dataset instead of synthetic seeds")
    evaluate.add_argument("--baseline", help="labelled benign dataset used to train the anomaly baseline")
    evaluate.set_defaults(handler=commands.command_evaluate)

    serve = subparsers.add_parser("serve", help="run the REST API")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.set_defaults(handler=commands.command_serve)

    dashboard = subparsers.add_parser("dashboard", help="run the Streamlit dashboard")
    dashboard.add_argument("--port", type=int, default=8501)
    dashboard.set_defaults(handler=commands.command_dashboard)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        application = LinuxGuard(load_settings(arguments.config))
        return arguments.handler(application, arguments)
    except (
        ConfigurationError,
        RuleDefinitionError,
        ModelIntegrityError,
        FileNotFoundError,
        KeyError,
    ) as error:
        message = error.args[0] if isinstance(error, KeyError) and error.args else error
        print(f"error: {message}", file=sys.stderr)
        return EXIT_ERROR
