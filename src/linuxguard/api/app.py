import hmac
import os
from collections.abc import Iterator
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from linuxguard import __version__
from linuxguard.application import LinuxGuard
from linuxguard.config import Settings
from linuxguard.domain.alerts import Alert, AlertStatus, DetectorType, Severity
from linuxguard.domain.events import SecurityEvent
from linuxguard.investigation.reports import render_html, render_json, render_markdown
from linuxguard.investigation.timeline import TimelineBuilder, format_timestamp
from linuxguard.storage.repository import EvidenceStore


class StatusUpdate(BaseModel):
    status: AlertStatus


class ExplanationRequest(BaseModel):
    mode: Literal["template", "local", "cloud"] = "template"
    cloud_consent: bool = False


def serialize_event(event: SecurityEvent) -> dict[str, Any]:
    payload = event.to_dict()
    payload["time"] = format_timestamp(event.timestamp)
    return payload


def serialize_alert(alert: Alert, include_evidence: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "alert_id": alert.alert_id,
        "title": alert.title,
        "detector": alert.detector.value,
        "rule_id": alert.rule_id,
        "severity": alert.severity.value,
        "status": alert.status.value,
        "entity": alert.entity,
        "description": alert.description,
        "first_seen": format_timestamp(alert.first_seen),
        "last_seen": format_timestamp(alert.last_seen),
        "tactic": alert.tactic,
        "technique": alert.technique,
        "anomaly_score": alert.anomaly_score,
        "threshold": alert.threshold,
        "contributions": [
            {
                "feature": item.name,
                "description": item.description,
                "value": item.value,
                "baseline_mean": item.baseline_mean,
                "deviation": item.deviation,
            }
            for item in alert.contributions
        ],
        "explanation": alert.explanation,
        "explanation_provider": alert.explanation_provider,
    }
    if include_evidence:
        payload["evidence"] = [serialize_event(event) for event in alert.evidence]
    return payload


def get_application(request: Request) -> LinuxGuard:
    return request.app.state.linuxguard


def require_api_key(request: Request, x_api_key: Annotated[str | None, Header()] = None) -> None:
    expected = request.app.state.api_key
    if expected and not (x_api_key and hmac.compare_digest(x_api_key, expected)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")


def open_store(application: Annotated[LinuxGuard, Depends(get_application)]) -> Iterator[EvidenceStore]:
    store = application.open_store()
    try:
        yield store
    finally:
        store.close()


StoreDependency = Annotated[EvidenceStore, Depends(open_store)]
ApplicationDependency = Annotated[LinuxGuard, Depends(get_application)]
SECURED = [Depends(require_api_key)]


def load_alert(store: EvidenceStore, alert_id: str) -> Alert:
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


def create_app(settings: Settings) -> FastAPI:
    api = FastAPI(title="LinuxGuard API", version=__version__)
    api.state.linuxguard = LinuxGuard(settings)
    api.state.api_key = os.environ.get(settings.api.api_key_env)

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @api.get("/statistics", dependencies=SECURED)
    def statistics(store: StoreDependency) -> dict[str, Any]:
        return store.statistics()

    @api.get("/alerts", dependencies=SECURED)
    def list_alerts(
        store: StoreDependency,
        severity: Severity | None = None,
        alert_status: Annotated[AlertStatus | None, Query(alias="status")] = None,
        detector: DetectorType | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[dict[str, Any]]:
        alerts = store.list_alerts(
            severity.value if severity else None,
            alert_status.value if alert_status else None,
            detector.value if detector else None,
            limit=limit,
            offset=offset,
        )
        return [serialize_alert(alert) for alert in alerts]

    @api.get("/alerts/{alert_id}", dependencies=SECURED)
    def get_alert(alert_id: str, store: StoreDependency) -> dict[str, Any]:
        return serialize_alert(load_alert(store, alert_id), include_evidence=True)

    @api.patch("/alerts/{alert_id}", dependencies=SECURED)
    def update_alert(alert_id: str, update: StatusUpdate, store: StoreDependency) -> dict[str, Any]:
        load_alert(store, alert_id)
        store.update_status(alert_id, update.status)
        return serialize_alert(load_alert(store, alert_id))

    @api.get("/alerts/{alert_id}/timeline", dependencies=SECURED)
    def alert_timeline(
        alert_id: str, store: StoreDependency, context: Annotated[float, Query(ge=0, le=86400)] = 300
    ) -> list[dict[str, Any]]:
        timeline = TimelineBuilder(store, context).for_alert(load_alert(store, alert_id))
        return [
            {
                "time": entry.time_text,
                "evidence": entry.is_evidence,
                "summary": entry.summary,
                "related_alerts": list(entry.related_alert_ids),
                "event": serialize_event(entry.event),
            }
            for entry in timeline.entries
        ]

    @api.post("/alerts/{alert_id}/explanation", dependencies=SECURED)
    def explain_alert(
        alert_id: str, payload: ExplanationRequest, store: StoreDependency, application: ApplicationDependency
    ) -> dict[str, Any]:
        load_alert(store, alert_id)
        consent = payload.cloud_consent if payload.mode == "cloud" else None
        explanation = application.explain(store, alert_id, payload.mode, consent)
        return {"text": explanation.text, "provider": explanation.provider_label}

    @api.get("/alerts/{alert_id}/report", dependencies=SECURED)
    def alert_report(
        alert_id: str,
        store: StoreDependency,
        application: ApplicationDependency,
        report_format: Annotated[Literal["markdown", "html", "json"], Query(alias="format")] = "json",
    ) -> Any:
        load_alert(store, alert_id)
        report = application.report(store, alert_id)
        if report_format == "html":
            return HTMLResponse(render_html(report))
        if report_format == "markdown":
            return PlainTextResponse(render_markdown(report), media_type="text/markdown")
        return PlainTextResponse(render_json(report), media_type="application/json")

    return api
