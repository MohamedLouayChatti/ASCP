from enum import StrEnum

from pydantic import BaseModel,Field
from datetime import UTC, datetime
import uuid
from typing import Any

class EventType(StrEnum):
    RETRIEVAL = "retrieval_event"
    EVAL_VECTOR = "eval_vector"
    TOOL_CALL_ATTEMPT = "tool_call_attempt"
    TOOL_CALL_RESULT = "tool_call_result"
    POLICY_BLOCK = "policy_block"
    DLP_HIT = "dlp_hit"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    INCIDENT_CREATED = "incident_created"
    '''
    SANITIZATION = "sanitization_event"
    REQUEST_START = "request_start"
    REQUEST_END = "request_end" '''

class SeverityLevel(StrEnum):
    INFO = "info"
    WARN = "warn"
    ERROR = "error" 
    CRITICAL = "critical"

class TelemetryEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str  # links all events in a single request/session
    session_id: str | None = None 
    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    severity: SeverityLevel = SeverityLevel.INFO
    tool_name: str | None = None
    reason_code: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    invariant_violated: str | None = None  # e.g. "I1", "I2"
    risk_score: float | None = None

class IncidentReport(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str
    session_id: str | None = None 
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    trigger: str  # what caused the incident
    blocked_action: str | None = None
    redacted_fields: list[str] = Field(default_factory=list)
    invariant_at_risk: str | None = None
    evidence_references: list[str] = Field(default_factory=list)
    policy_rule_ids: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""
