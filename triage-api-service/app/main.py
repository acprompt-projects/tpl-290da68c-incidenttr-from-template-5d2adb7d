from __future__ import annotations
import os
import uuid
import httpx
import hashlib
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from .models import (
    Severity, IncidentStatus, IncidentCreate, TriageUpdate,
    Incident, NotificationResult, ErrorResponse,
)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
PAGERDUTY_EVENTS_URL = os.getenv("PAGERDUTY_EVENTS_URL", "https://events.pagerduty.com/v2/enqueue")
PAGERDUTY_ROUTING_KEY = os.getenv("PAGERDUTY_ROUTING_KEY", "")

incidents_db: dict[str, Incident] = {}
dedup_index: dict[str, str] = {}

SEVERITY_KEYWORDS: dict[Severity, list[str]] = {
    Severity.critical: ["outage", "down", "data_loss", "breach"],
    Severity.high: ["degraded", "partial_outage", "error_spike"],
    Severity.medium: ["warning", "anomaly", "slow"],
    Severity.low: ["info_alert", "flap"],
}


def classify_severity(incident: IncidentCreate) -> Severity:
    if incident.severity:
        return incident.severity
    text = (incident.title + " " + incident.description).lower()
    for sev in (Severity.critical, Severity.high, Severity.medium, Severity.low):
        if any(kw in text for kw in SEVERITY_KEYWORDS[sev]):
            return sev
    return Severity.info


async def notify_slack(incident: Incident) -> bool:
    if not SLACK_WEBHOOK_URL:
        return False
    payload = {
        "text": f"🚨 [{incident.severity.value.upper()}] {incident.title}\n"
                f"ID: {incident.id} | Status: {incident.status.value}\n"
                f"Services: {', '.join(incident.affected_services) or 'N/A'}"
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(SLACK_WEBHOOK_URL, json=payload)
            return resp.status_code == 200
    except Exception:
        return False


async def notify_pagerduty(incident: Incident) -> bool:
    if not PAGERDUTY_ROUTING_KEY:
        return False
    payload = {
        "routing_key": PAGERDUTY_ROUTING_KEY,
        "event_action": "trigger",
        "payload": {
            "summary": incident.title,
            "severity": incident.severity.value,
            "source": incident.source.value,
            "component": ", ".join(incident.affected_services) or "unknown",
        },
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(PAGERDUTY_EVENTS_URL, json=payload)
            return resp.status_code == 202
    except Exception:
        return False


async def dispatch_notifications(incident: Incident) -> NotificationResult:
    errors: list[str] = []
    slack_ok = await notify_slack(incident)
    if not slack_ok and SLACK_WEBHOOK_URL:
        errors.append("slack_notification_failed")
    pd_ok = await notify_pagerduty(incident)
    if not pd_ok and PAGERDUTY_ROUTING_KEY:
        errors.append("pagerduty_notification_failed")
    return NotificationResult(slack=slack_ok, pagerduty=pd_ok, errors=errors)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(title="Incident Triage Service", version="1.0.0", lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def custom_validation_handler(request, exc):
    body = {"detail": str(exc)}
    return JSONResponse(status_code=422, content=body)


@app.post("/incidents", response_model=Incident, status_code=status.HTTP_201_CREATED,
           responses={409: {"model": ErrorResponse}})
async def create_incident(payload: IncidentCreate):
    severity = classify_severity(payload)
    if payload.dedup_key:
        dedup_hash = hashlib.sha256(payload.dedup_key.encode()).hexdigest()
        existing_id = dedup_index.get(dedup_hash)
        if existing_id and existing_id in incidents_db:
            inc = incidents_db[existing_id]
            inc.correlation_count += 1
            inc.updated_at = datetime.utcnow()
            return inc
    incident_id = str(uuid.uuid4())
    incident = Incident(
        id=incident_id, title=payload.title, description=payload.description,
        severity=severity, source=payload.source, tags=payload.tags,
        dedup_key=payload.dedup_key, affected_services=payload.affected_services,
    )
    if payload.dedup_key:
        dedup_index[hashlib.sha256(payload.dedup_key.encode()).hexdigest()] = incident_id
    notifications = await dispatch_notifications(incident)
    incident.notifications = notifications
    incidents_db[incident_id] = incident
    return incident


@app.get("/incidents/{incident_id}", response_model=Incident,
          responses={404: {"model": ErrorResponse}})
async def get_incident(incident_id: str):
    inc = incidents_db.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.patch("/incidents/{incident_id}/triage", response_model=Incident,
            responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}})
async def update_triage(incident_id: str, update: TriageUpdate):
    inc = incidents_db.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if inc.status == IncidentStatus.resolved:
        raise HTTPException(status_code=409, detail="Cannot triage a resolved incident")
    if update.severity:
        inc.severity = update.severity
    if update.status:
        inc.status = update.status
    if update.assignee:
        inc.assignee = update.assignee
    if update.notes:
        inc.notes = (inc.notes or "") + "\n" + update.notes if inc.notes else update.notes
    if update.escalate:
        inc.status = IncidentStatus.escalated
        notifications = await dispatch_notifications(inc)
        inc.notifications = notifications
    inc.updated_at = datetime.utcnow()
    return inc