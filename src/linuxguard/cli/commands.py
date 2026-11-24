import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from linuxguard.application import LinuxGuard
from linuxguard.cli.formatting import alert_line, render_alert_detail, render_alerts, render_timeline
from linuxguard.domain.alerts import AlertStatus
from linuxguard.evaluation.reporting import write_evaluation
from linuxguard.evaluation.runner import (
    DEFAULT_CONFIGURATIONS,
    evaluate_dataset,
    evaluate_seed,
    extract_events,
    summarize,
    train_detector,
)
from linuxguard.evaluation.synthetic.dataset import LabeledDataset, build_dataset
from linuxguard.explanation.language_models import CloudExplainer
from linuxguard.investigation.reports import content_digest, render_report
from linuxguard.investigation.timeline import TimelineBuilder

EXIT_OK = 0
EXIT_NOT_FOUND = 2
DASHBOARD_MODULE = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"


def _resolve_alert_id(app: LinuxGuard, prefix: str) -> str:
    with app.open_store() as store:
        if store.get_alert(prefix, include_evidence=False) is not None:
            return prefix
        matches = [alert.alert_id for alert in store.list_alerts(limit=100000) if alert.alert_id.startswith(prefix)]
    if len(matches) != 1:
        raise KeyError(f"No unique alert matches '{prefix}'")
    return matches[0]


def command_init_database(app: LinuxGuard, _: argparse.Namespace) -> int:
    with app.open_store():
        pass
    print(f"Database ready at {app.settings.storage.database_path}")
    return EXIT_OK


def command_ingest(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    summary = app.ingest(arguments.audit_log, arguments.auth_log, arguments.mode, arguments.passwd)
    print(f"Processed {summary.events} events ({summary.stored_events} new) in {summary.mode.value} mode.")
    print(f"Generated {len(summary.alerts)} alerts.")
    for alert in sorted(summary.alerts, key=lambda item: item.last_seen):
        print(alert_line(alert))
    return EXIT_OK


def command_train(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    summary = app.train(arguments.audit_log, arguments.auth_log, arguments.output, arguments.passwd)
    print(
        f"Trained Isolation Forest baseline on {summary.events} events ({summary.windows} windows). "
        f"Threshold {summary.threshold:.4f}. Model saved to {summary.model_path}."
    )
    return EXIT_OK


def command_monitor(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    collection = app.settings.collection
    print(f"Monitoring {collection.audit_log_path} and {', '.join(collection.auth_log_paths)}. Press Ctrl+C to stop.")
    try:
        processed = app.monitor(
            lambda alert: print(alert_line(alert), flush=True), arguments.mode, arguments.from_start
        )
    except KeyboardInterrupt:
        print("Stopped.")
        return EXIT_OK
    print(f"Processed {processed} events.")
    return EXIT_OK


def command_alerts(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    with app.open_store() as store:
        alerts = store.list_alerts(arguments.severity, arguments.status, arguments.detector, limit=arguments.limit)
    print(render_alerts(alerts))
    return EXIT_OK


def command_show(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    alert_id = _resolve_alert_id(app, arguments.alert_id)
    with app.open_store() as store:
        alert = store.get_alert(alert_id)
    print(render_alert_detail(alert))
    return EXIT_OK


def command_timeline(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    alert_id = _resolve_alert_id(app, arguments.alert_id)
    with app.open_store() as store:
        alert = store.get_alert(alert_id)
        timeline = TimelineBuilder(store, arguments.context).for_alert(alert)
    print(render_timeline(timeline))
    return EXIT_OK


def _cloud_consent(app: LinuxGuard, alert_id: str, assume_yes: bool) -> bool:
    if app.settings.explanation.cloud.consent_granted or assume_yes:
        return True
    with app.open_store() as store:
        alert = store.get_alert(alert_id)
    preview = CloudExplainer(app.settings.explanation.cloud, app.settings.explanation.max_evidence_events).preview(
        alert
    )
    print("Cloud mode sends the following redacted evidence to an external model provider:")
    print(preview)
    answer = input(f"Send this to {app.settings.explanation.cloud.endpoint}? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def command_explain(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    alert_id = _resolve_alert_id(app, arguments.alert_id)
    mode = arguments.mode or app.settings.explanation.mode
    consent = _cloud_consent(app, alert_id, arguments.yes) if mode == "cloud" else None
    with app.open_store() as store:
        explanation = app.explain(store, alert_id, mode, consent)
    print(explanation.text)
    print(f"\nSource: {explanation.provider_label}")
    return EXIT_OK


def command_report(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    alert_id = _resolve_alert_id(app, arguments.alert_id)
    with app.open_store() as store:
        if arguments.explain:
            app.explain(store, alert_id, arguments.explain)
        content = render_report(app.report(store, alert_id), arguments.format)
    if arguments.output:
        output = Path(arguments.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        digest = content_digest(content)
        output.with_name(output.name + ".sha256").write_text(f"{digest}  {output.name}\n", encoding="ascii")
        print(f"Report written to {output} (SHA-256 {digest}).")
    else:
        print(content)
    return EXIT_OK


def command_status(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    alert_id = _resolve_alert_id(app, arguments.alert_id)
    with app.open_store() as store:
        store.update_status(alert_id, AlertStatus(arguments.status))
    print(f"Alert {alert_id} marked as {arguments.status}.")
    return EXIT_OK


def command_stats(app: LinuxGuard, _: argparse.Namespace) -> int:
    with app.open_store() as store:
        print(json.dumps(store.statistics(), indent=2))
    return EXIT_OK


def command_simulate(_: LinuxGuard, arguments: argparse.Namespace) -> int:
    malicious = 0 if arguments.baseline else arguments.attacks
    dataset = build_dataset(arguments.seed, days=arguments.days, malicious_per_scenario=malicious)
    directory = dataset.save(arguments.output)
    print(
        f"Wrote {len(dataset.audit_lines)} audit lines, {len(dataset.auth_lines)} auth lines and "
        f"{len(dataset.cases)} labelled cases ({len(dataset.malicious_cases)} malicious) to {directory}."
    )
    return EXIT_OK


def command_evaluate(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    anomaly = app.settings.detection.anomaly
    if arguments.dataset:
        dataset = LabeledDataset.load(arguments.dataset, app.settings.collection.host_name)
        detector = None
        if arguments.baseline:
            baseline = LabeledDataset.load(arguments.baseline, app.settings.collection.host_name)
            detector, _, _ = train_detector(extract_events(baseline)[0], anomaly)
        runs = evaluate_dataset(dataset, app.rules, detector, DEFAULT_CONFIGURATIONS, anomaly.lateness_seconds)
        for run in runs.values():
            summary = run.metrics.summary()
            print(
                f"{run.spec.label}: precision={summary['case_precision']:.3f} recall={summary['recall']:.3f} "
                f"fpr={summary['false_positive_rate']:.3f} alerts={summary['alerts']}"
            )
        return EXIT_OK
    results = [
        evaluate_seed(seed, app.rules, anomaly, progress=lambda message: print(message, file=sys.stderr))
        for seed in arguments.seeds
    ]
    results_path, report_path = write_evaluation(summarize(results), arguments.output)
    print(f"Evaluation results written to {results_path} and {report_path}.")
    return EXIT_OK


def command_serve(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    import uvicorn

    from linuxguard.api.app import create_app

    uvicorn.run(
        create_app(app.settings),
        host=arguments.host or app.settings.api.host,
        port=arguments.port or app.settings.api.port,
    )
    return EXIT_OK


def command_dashboard(app: LinuxGuard, arguments: argparse.Namespace) -> int:
    executable = shutil.which("streamlit")
    command = [executable] if executable else [sys.executable, "-m", "streamlit"]
    command += [
        "run",
        str(DASHBOARD_MODULE),
        "--server.port",
        str(arguments.port),
        "--server.address",
        "127.0.0.1",
        "--browser.gatherUsageStats",
        "false",
    ]
    if arguments.config:
        command += ["--", "--config", arguments.config]
    return subprocess.call(command)
