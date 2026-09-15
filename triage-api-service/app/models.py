from __future__ import annotations
from enum import Enum
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class IncidentStatus(str, Enum):
    open = "open"
    triaging = "triaging"
    escalated = "escalated"
    resolved = "resolved"
    dismissed = "dismissed"


class AlertSource(str, Enum):
    rules_engine = "rules_engine"
    manual = "manual"
    monitoring = "monitoring"


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field(..., min_length=1)
    severity: Optional[Severity] = None
    source: AlertSource = AlertSource.rules_engine
    tags: dict[str, str] = Field(default_factory=dict)
    dedup_key: Optional[str] = None
    affected_services: list[str] = Field(default_factory=list)


class TriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None
    escalate: bool = False


class NotificationResult(BaseModel):
    slack: bool = False
    pagerduty: bool = False
    errors: list[str] = Field(default_factory=list)


class Incident(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.open
    source: AlertSource = AlertSource.rules_engine
    tags: dict[str, str] = Field(default_factory=dict)
    dedup_key: Optional[str] = None
    affected_services: list[str] = Field(default_factory=list)
    assignee: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    correlation_count: int = 1
    notifications: NotificationResult = Field(default_factory=NotificationResult)


class ErrorResponse(BaseModel):
    detail: str
    incident_id: Optional[str] = None