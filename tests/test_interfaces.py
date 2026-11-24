import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from linuxguard.api.app import create_app
from linuxguard.application import LinuxGuard
from linuxguard.cli import main
from linuxguard.collection.sources import FileFollower, read_lines

AUDIT_ATTACK = (
    "type=SYSCALL msg=audit({ts}:{serial}): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 a3=0 "
    "items=2 ppid=10 pid={pid} auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 "
    'fsgid=1001 tty=pts0 ses=4 comm="update" exe="/tmp/.x/update" subj=unconfined key="lg_exec"\n'
    'type=EXECVE msg=audit({ts}:{serial}): argc=1 a0="/tmp/.x/update"\n'
    "type=EOE msg=audit({ts}:{serial}): \n"
)


def write_logs(directory: Path) -> tuple[Path, Path]:
    audit = directory / "audit.log"
    auth = directory / "auth.log"
    audit.write_text(AUDIT_ATTACK.format(ts="1700000000.000", serial=1, pid=500))
    auth.write_text(
        "".join(
            f"2023-11-14T22:13:{10 + index:02d}+00:00 lab sshd[{900 + index}]: "
            f"Failed password for root from 203.0.113.7 port {40000 + index} ssh2\n"
            for index in range(6)
        )
    )
    return audit, auth


@pytest.fixture
def populated(settings, tmp_path):
    audit, auth = write_logs(tmp_path)
    application = LinuxGuard(settings)
    summary = application.ingest([audit], [auth], mode="rules")
    return application, summary


def test_ingest_stores_events_and_alerts(populated) -> None:
    application, summary = populated
    assert summary.events == 7
    assert {alert.rule_id for alert in summary.alerts} == {"LG-EXEC-001", "LG-AUTH-001"}
    with application.open_store() as store:
        assert store.statistics()["alerts"] == 2


def test_api_endpoints(populated) -> None:
    application, _ = populated
    client = TestClient(create_app(application.settings))
    assert client.get("/health").json()["status"] == "ok"
    alerts = client.get("/alerts").json()
    assert len(alerts) == 2
    alert_id = next(item["alert_id"] for item in alerts if item["rule_id"] == "LG-EXEC-001")
    detail = client.get(f"/alerts/{alert_id}").json()
    assert detail["evidence"][0]["executable"] == "/tmp/.x/update"
    assert client.get("/alerts", params={"severity": "high"}).status_code == 200
    assert client.get("/alerts", params={"severity": "bogus"}).status_code == 422
    assert client.get("/alerts/unknown").status_code == 404
    timeline = client.get(f"/alerts/{alert_id}/timeline").json()
    assert timeline[0]["evidence"] is True
    updated = client.patch(f"/alerts/{alert_id}", json={"status": "acknowledged"}).json()
    assert updated["status"] == "acknowledged"
    explanation = client.post(f"/alerts/{alert_id}/explanation", json={"mode": "template"}).json()
    assert "/tmp/.x/update" in explanation["text"]
    html = client.get(f"/alerts/{alert_id}/report", params={"format": "html"})
    assert html.headers["content-type"].startswith("text/html")
    assert json.loads(client.get(f"/alerts/{alert_id}/report").text)["alert"]["alert_id"] == alert_id
    assert client.get("/statistics").json()["alerts"] == 2


def test_api_key_is_enforced_when_configured(populated, monkeypatch) -> None:
    application, _ = populated
    monkeypatch.setenv(application.settings.api.api_key_env, "s3cret")
    client = TestClient(create_app(application.settings))
    assert client.get("/alerts").status_code == 401
    assert client.get("/alerts", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/alerts", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/health").status_code == 200


def write_config(settings, path: Path) -> Path:
    path.write_text(
        "storage:\n"
        f"  database_path: '{Path(settings.storage.database_path).as_posix()}'\n"
        "detection:\n"
        "  mode: rules\n"
        f"  model_path: '{Path(settings.detection.model_path).as_posix()}'\n"
        "collection:\n"
        "  host_name: lab\n"
        "  syslog_timezone: UTC\n"
    )
    return path


def test_cli_end_to_end(settings, tmp_path, capsys) -> None:
    config = write_config(settings, tmp_path / "config.yaml")
    audit, auth = write_logs(tmp_path)
    assert main(["--config", str(config), "init-db"]) == 0
    assert main(["--config", str(config), "ingest", "--audit-log", str(audit), "--auth-log", str(auth)]) == 0
    output = capsys.readouterr().out
    assert "Generated 2 alerts." in output
    alert_id = output.split("LG-EXEC-001")[1].split("id=")[1].split()[0]
    assert main(["--config", str(config), "alerts"]) == 0
    assert main(["--config", str(config), "show", alert_id[:10]]) == 0
    assert main(["--config", str(config), "timeline", alert_id]) == 0
    assert main(["--config", str(config), "explain", alert_id]) == 0
    assert main(["--config", str(config), "status", alert_id, "resolved"]) == 0
    report = tmp_path / "report.md"
    assert main(["--config", str(config), "report", alert_id, "--output", str(report)]) == 0
    assert report.read_text().startswith("# Incident Report")
    assert (tmp_path / "report.md.sha256").read_text().split()[1] == "report.md"
    assert main(["--config", str(config), "stats"]) == 0
    assert main(["--config", str(config), "show", "nonexistent"]) == 1


def test_cli_simulate_train_and_hybrid_ingest(settings, tmp_path, capsys) -> None:
    config = write_config(settings, tmp_path / "config.yaml")
    baseline = tmp_path / "baseline"
    test = tmp_path / "test"
    assert main(["simulate", "--output", str(baseline), "--seed", "3", "--baseline"]) == 0
    assert main(["simulate", "--output", str(test), "--seed", "4"]) == 0
    assert (
        main(
            [
                "--config",
                str(config),
                "train",
                "--audit-log",
                str(baseline / "audit.log"),
                "--auth-log",
                str(baseline / "auth.log"),
                "--passwd",
                str(baseline / "passwd"),
            ]
        )
        == 0
    )
    arguments = ["--config", str(config), "ingest", "--mode", "hybrid", "--audit-log", str(test / "audit.log")]
    assert main([*arguments, "--auth-log", str(test / "auth.log"), "--passwd", str(test / "passwd")]) == 0
    output = capsys.readouterr().out
    assert "hybrid mode" in output
    assert "anomaly:" in output


def test_cli_reports_missing_model(settings, tmp_path, capsys) -> None:
    config = write_config(settings, tmp_path / "config.yaml")
    audit, _ = write_logs(tmp_path)
    assert main(["--config", str(config), "ingest", "--mode", "hybrid", "--audit-log", str(audit)]) == 1
    assert "Model file not found" in capsys.readouterr().err


def test_monitor_follows_appended_lines(settings, tmp_path) -> None:
    audit = tmp_path / "live-audit.log"
    auth = tmp_path / "live-auth.log"
    audit.write_text("")
    auth.write_text("")
    settings.collection.audit_log_path = str(audit)
    settings.collection.auth_log_paths = [str(auth)]
    settings.collection.poll_interval_seconds = 0.01
    application = LinuxGuard(settings)
    received = []
    polls = {"count": 0}

    def should_stop() -> bool:
        polls["count"] += 1
        if polls["count"] == 3:
            with open(audit, "a") as handle:
                handle.write(AUDIT_ATTACK.format(ts="1700000000.000", serial=9, pid=700))
        return polls["count"] > 6 or bool(received)

    processed = application.monitor(received.append, mode="rules", should_stop=should_stop, sleep=lambda _: None)
    assert processed == 1
    assert received[0].rule_id == "LG-EXEC-001"


def test_file_follower_handles_partial_lines_and_rotation(tmp_path) -> None:
    path = tmp_path / "log"
    path.write_text("old line\n")
    follower = FileFollower(path)
    assert follower.poll() == []
    with open(path, "a") as handle:
        handle.write("first\nsec")
    assert follower.poll() == ["first"]
    with open(path, "a") as handle:
        handle.write("ond\n")
    assert follower.poll() == ["second"]
    path.write_text("rotated\n")
    assert follower.poll() == ["rotated"]
    assert FileFollower(tmp_path / "missing").poll() == []
    assert FileFollower(path, start_at_end=False).poll() == ["rotated"]


def test_read_lines_supports_gzip(tmp_path) -> None:
    import gzip

    with gzip.open(tmp_path / "log.gz", "wt") as handle:
        handle.write("a\nb\n")
    assert [line.strip() for line in read_lines(tmp_path / "log.gz")] == ["a", "b"]


def test_dashboard_data_helpers(populated) -> None:
    from linuxguard.dashboard.data import alerts_frame, alerts_per_hour, evaluation_frame, timeline_frame
    from linuxguard.investigation.timeline import TimelineBuilder

    application, summary = populated
    frame = alerts_frame(summary.alerts)
    assert list(frame["severity"]) and not alerts_per_hour(frame).empty
    with application.open_store() as store:
        timeline = TimelineBuilder(store).for_alert(summary.alerts[0])
    assert not timeline_frame(timeline).empty
    summary_document = {
        "configurations": {
            "rules": {
                "label": "A",
                "metrics": {
                    name: {"mean": 0.5, "std": 0.0}
                    for name in (
                        "case_precision",
                        "recall",
                        "false_positive_rate",
                        "f1",
                        "alerts",
                        "mean_delay_seconds",
                    )
                },
                "resources": {"milliseconds_per_event": {"mean": 0.1, "std": 0.0}},
            }
        }
    }
    assert evaluation_frame(summary_document).iloc[0]["recall"] == 0.5


def test_concurrent_api_requests_use_separate_connections(populated) -> None:
    application, _ = populated
    client = TestClient(create_app(application.settings))
    failures = []

    def request() -> None:
        if client.get("/alerts").status_code != 200:
            failures.append(1)

    threads = [threading.Thread(target=request) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not failures
