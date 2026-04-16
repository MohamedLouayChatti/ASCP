"""
Layer D — Telemetry, Risk Scoring, and Incident Reporting.

Public API surface for the entire Layer D package.
Consumers only need to import from here — never from submodules directly.

Usage:
    from layerd import (
        TelemetryEvent, IncidentReport, EventType, SeverityLevel,
        RiskInput, RiskResult, ScoringConfig, compute_risk_score,
        TelemetrySink, emit_jsonl,
    )
"""

from layerd.telemetry.events import (
    EventType,
    IncidentReport,
    SeverityLevel,
    TelemetryEvent,
)
from layerd.telemetry.sink_jsonl import emit_jsonl
from layerd.risk import (
    RiskInput,
    RiskResult,
    ScoringConfig,
    Severity,
    compute_risk_score,
)

__all__ = [
    # Telemetry
    "EventType",
    "IncidentReport",
    "SeverityLevel",
    "TelemetryEvent",
    "TelemetrySink",
    "emit_jsonl",
    # Risk scoring
    "RiskInput",
    "RiskResult",
    "ScoringConfig",
    "Severity",
    "compute_risk_score",
]