import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from linuxguard.evaluation.synthetic.scenarios import SCENARIOS_BY_NAME

RESULTS_FILE = "evaluation_results.json"
REPORT_FILE = "evaluation_report.md"
PRIMARY_KEYS = ("rules", "hybrid")


def _pair(statistic: dict[str, float], digits: int = 3) -> str:
    return f"{statistic['mean']:.{digits}f} ± {statistic['std']:.{digits}f}"


def _metric_table(configurations: dict[str, Any]) -> list[str]:
    lines = [
        "| Configuration | Alerts | Alert precision | Case precision | Recall | False-positive rate | F1 | "
        "Mean detection delay (s) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for result in configurations.values():
        metrics = result["metrics"]
        lines.append(
            f"| {result['label']} | {_pair(metrics['alerts'], 1)} | {_pair(metrics['alert_precision'])} | "
            f"{_pair(metrics['case_precision'])} | {_pair(metrics['recall'])} | "
            f"{_pair(metrics['false_positive_rate'])} | {_pair(metrics['f1'])} | "
            f"{_pair(metrics['mean_delay_seconds'], 1)} |"
        )
    return lines


def _resource_table(configurations: dict[str, Any]) -> list[str]:
    lines = [
        "| Configuration | Detection time (s) | CPU time (s) | Time per event (ms) | Throughput (events/s) | "
        "Peak traced memory (MB) | Database size (KB) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for result in configurations.values():
        usage = result["resources"]
        lines.append(
            f"| {result['label']} | {_pair(usage['wall_seconds'], 2)} | {_pair(usage['cpu_seconds'], 2)} | "
            f"{_pair(usage['milliseconds_per_event'], 3)} | {_pair(usage['events_per_second'], 0)} | "
            f"{_pair(usage['peak_memory_mb'], 1)} | {_pair(usage['storage_kb'], 0)} |"
        )
    return lines


def _scenario_table(configurations: dict[str, Any]) -> list[str]:
    keys = [key for key in ("rules", "hybrid", "anomaly_only", "forest_only") if key in configurations]
    header = " | ".join(configurations[key]["label"] for key in keys)
    lines = [
        f"| Scenario | Type | Rule coverage | {header} |",
        "| --- | --- | --- | " + " | ".join("---:" for _ in keys) + " |",
    ]
    names = sorted(configurations[keys[0]]["scenarios"], key=lambda name: (not _is_malicious(name), name))
    for name in names:
        spec = SCENARIOS_BY_NAME.get(name)
        kind = "malicious" if spec and spec.malicious else "benign"
        coverage = "-" if spec is None or spec.covered_by_rules is None else ("yes" if spec.covered_by_rules else "no")
        cells = []
        for key in keys:
            counts = configurations[key]["scenarios"][name]
            cells.append(f"{counts['detected']}/{counts['total']}")
        lines.append(f"| {name} | {kind} | {coverage} | " + " | ".join(cells) + " |")
    return lines


def _is_malicious(name: str) -> bool:
    spec = SCENARIOS_BY_NAME.get(name)
    return spec is not None and spec.malicious


def render_evaluation_markdown(summary: dict[str, Any]) -> str:
    configurations = summary["configurations"]
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# LinuxGuard Evaluation Results",
        "",
        f"Generated {generated}. Seeds: {', '.join(str(seed) for seed in summary['seeds'])}. "
        f"Values are mean ± standard deviation across seeds.",
        "",
        f"- Test events per seed: {_pair(summary['test_events'], 0)}",
        f"- Labelled cases per seed: {_pair(summary['test_cases'], 1)}",
        f"- Baseline training windows per seed: {_pair(summary['training_windows'], 0)}",
        f"- Parsing throughput: {_pair(summary['parsing']['events_per_second'], 0)} events/s",
        f"- Baseline training time: {_pair(summary['training']['wall_seconds'], 2)} s",
        "",
        "## Detection Performance",
        "",
        *_metric_table(configurations),
        "",
        "Recall and false-positive rate are measured per labelled case. A benign case counts as a false "
        "positive only when an alert whose evidence contains no malicious activity touches it. Alert precision "
        "is the fraction of alerts whose evidence contains malicious activity.",
        "",
        "## Resource Consumption",
        "",
        *_resource_table(configurations),
        "",
        "## Detection by Scenario",
        "",
        "Counts are detected cases / total cases summed over all seeds. For benign scenarios the count is the "
        "number of falsely flagged cases.",
        "",
        *_scenario_table(configurations),
        "",
    ]
    return "\n".join(lines)


def write_evaluation(summary: dict[str, Any], output_directory: str | Path) -> tuple[Path, Path]:
    directory = Path(output_directory)
    directory.mkdir(parents=True, exist_ok=True)
    results_path = directory / RESULTS_FILE
    report_path = directory / REPORT_FILE
    results_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    report_path.write_text(render_evaluation_markdown(summary), encoding="utf-8")
    return results_path, report_path
