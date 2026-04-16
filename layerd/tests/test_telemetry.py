from __future__ import annotations

import asyncio
import json

import pytest

from layerd.risk.config import DEFAULT_CONFIG
from layerd.risk.enums import (
    ContextSufficiency,
    ContractDecision,
    DLPAction,
    RiskLevel,
    Severity,
)
from layerd.risk.models import RiskInput
from layerd.risk.scorer import compute_risk_score

from layerd.telemetry.events import (
    EventType,
    IncidentReport,
    SeverityLevel,
    TelemetryEvent,
)
from layerd.telemetry.sink_jsonl import emit_jsonl

# ===========================================================================
# SECTION 10 — Telemetry: Event Models
# ===========================================================================
 
class TestTelemetryEventModels:
 
    def test_event_has_auto_id(self):
        e = TelemetryEvent(correlation_id="c1", event_type=EventType.POLICY_BLOCK)
        assert e.event_id  # non-empty UUID
 
    def test_two_events_have_distinct_ids(self):
        e1 = TelemetryEvent(correlation_id="c1", event_type=EventType.POLICY_BLOCK)
        e2 = TelemetryEvent(correlation_id="c1", event_type=EventType.POLICY_BLOCK)
        assert e1.event_id != e2.event_id
 
    def test_event_timestamp_is_utc(self):
        from datetime import timezone
        e = TelemetryEvent(correlation_id="c1", event_type=EventType.DLP_HIT)
        assert e.timestamp.tzinfo == timezone.utc
 
    def test_event_default_severity_is_info(self):
        e = TelemetryEvent(correlation_id="c1", event_type=EventType.TOOL_CALL_ATTEMPT)
        assert e.severity == SeverityLevel.INFO
 
    def test_event_serializes_to_json(self):
        e = TelemetryEvent(
            correlation_id="c1",
            event_type=EventType.INCIDENT_CREATED,
            severity=SeverityLevel.CRITICAL,
            reason_code="CANARY_LEAK",
            risk_score=1.0,
        )
        data = json.loads(e.model_dump_json())
        assert data["event_type"] == "incident_created"
        assert data["risk_score"] == 1.0
 
    def test_incident_report_has_auto_id(self):
        r = IncidentReport(correlation_id="c1", trigger="canary_leak")
        assert r.incident_id
 
    def test_incident_default_risk_score_is_zero(self):
        r = IncidentReport(correlation_id="c1", trigger="test")
        assert r.risk_score == 0.0
 
    @pytest.mark.parametrize("event_type", list(EventType))
    def test_all_event_types_instantiate(self, event_type):
        e = TelemetryEvent(correlation_id="c1", event_type=event_type)
        assert e.event_type == event_type
 
    @pytest.mark.parametrize("severity", list(SeverityLevel))
    def test_all_severity_levels_instantiate(self, severity):
        e = TelemetryEvent(
            correlation_id="c1",
            event_type=EventType.TOOL_CALL_RESULT,
            severity=severity,
        )
        assert e.severity == severity
 
 
# ===========================================================================
# SECTION 11 — Telemetry: JSONL Sink
# ===========================================================================
 
class TestJsonlSink:
 
    def test_emit_creates_file(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        e = TelemetryEvent(correlation_id="c1", event_type=EventType.POLICY_BLOCK)
        asyncio.run(emit_jsonl(e, path))
        assert path.exists()
 
    def test_emit_writes_valid_json(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        e = TelemetryEvent(correlation_id="c1", event_type=EventType.DLP_HIT)
        asyncio.run(emit_jsonl(e, path))
        data = json.loads(path.read_text().strip())
        assert data["event_type"] == "dlp_hit"
        assert data["correlation_id"] == "c1"
 
    def test_emit_appends_multiple_events(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        for i in range(5):
            e = TelemetryEvent(
                correlation_id=f"c{i}",
                event_type=EventType.TOOL_CALL_ATTEMPT,
            )
            asyncio.run(emit_jsonl(e, path))
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 5
 
    def test_each_line_is_independent_json(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        for i in range(3):
            e = TelemetryEvent(
                correlation_id=f"corr-{i}",
                event_type=EventType.APPROVAL_REQUIRED,
            )
            asyncio.run(emit_jsonl(e, path))
        for line in path.read_text().strip().splitlines():
            json.loads(line)  # each line must parse independently
 
    def test_emit_creates_parent_directories(self, tmp_path):
        deep_path = tmp_path / "a" / "b" / "c" / "tel.jsonl"
        e = TelemetryEvent(correlation_id="c1", event_type=EventType.INCIDENT_CREATED)
        asyncio.run(emit_jsonl(e, deep_path))
        assert deep_path.exists()
 
    def test_concurrent_writes_no_data_loss(self, tmp_path):
        """Multiple concurrent emits must not lose or corrupt any event."""
        path = tmp_path / "concurrent.jsonl"
        N = 20
 
        async def run_all():
            events = [
                TelemetryEvent(
                    correlation_id=f"c{i}",
                    event_type=EventType.TOOL_CALL_RESULT,
                )
                for i in range(N)
            ]
            await asyncio.gather(*[emit_jsonl(e, path) for e in events])
 
        asyncio.run(run_all())
        lines = path.read_text().strip().splitlines()
        assert len(lines) == N
        for line in lines:
            json.loads(line)  # every line must be valid JSON
 
    def test_emitted_event_preserves_risk_score(self, tmp_path):
        path = tmp_path / "tel.jsonl"
        e = TelemetryEvent(
            correlation_id="c1",
            event_type=EventType.INCIDENT_CREATED,
            risk_score=0.95,
            invariant_violated="I3",
        )
        asyncio.run(emit_jsonl(e, path))
        data = json.loads(path.read_text().strip())
        assert data["risk_score"] == pytest.approx(0.95)
        assert data["invariant_violated"] == "I3"
 
 
# ===========================================================================
# SECTION 12 — Integration: Scorer → Telemetry Pipeline
# ===========================================================================
 
class TestIntegration:
    """
    End-to-end tests simulating realistic agent scenarios.
    Each test represents an actual attack or legitimate use case.
    """
 
    def test_normal_rag_query(self, tmp_path):
        """Happy path: well-grounded RAG response, no violations."""
        inp = RiskInput(
            grounding_score=0.95,
            hallucination_risk=0.05,
            retrieval_relevance=0.90,
            context_sufficiency=ContextSufficiency.SUFFICIENT,
            decision=ContractDecision.ALLOW,
            tool_risk_level=RiskLevel.LOW,
        )
        result = compute_risk_score(inp)
        assert result.severity in (Severity.LOW, Severity.MEDIUM)
        assert result.violated_invariants == []
 
        # NOTE: Severity (risk) and SeverityLevel (telemetry) use different scales.
        # risk.Severity = LOW|MEDIUM|HIGH|CRITICAL  (risk score bands)
        # SeverityLevel = INFO|WARN|ERROR|CRITICAL  (log/alert severity)
        # They must be mapped explicitly — no automatic conversion exists.
        _sev_map = {
            Severity.LOW: SeverityLevel.INFO,
            Severity.MEDIUM: SeverityLevel.WARN,
            Severity.HIGH: SeverityLevel.ERROR,
            Severity.CRITICAL: SeverityLevel.CRITICAL,
        }
        event = TelemetryEvent(
            correlation_id="req-001",
            event_type=EventType.TOOL_CALL_RESULT,
            risk_score=result.score,
            severity=_sev_map[result.severity],
        )
        path = tmp_path / "tel.jsonl"
        asyncio.run(emit_jsonl(event, path))
        data = json.loads(path.read_text().strip())
        assert data["event_type"] == "tool_call_result"
 
    def test_canary_leak_triggers_incident_pipeline(self, tmp_path):
        """Simulates a prompt injection that exfiltrates a canary token."""
        inp = RiskInput(canary_hits=True)
        result = compute_risk_score(inp)
 
        assert result.score == 1.0
        assert result.severity == Severity.CRITICAL
        assert "I3" in result.violated_invariants
 
        # Build incident report
        report = IncidentReport(
            correlation_id="req-002",
            trigger="canary_token_exfiltrated",
            blocked_action="send_email",
            invariant_at_risk="I3",
            risk_score=result.score,
            summary="Agent attempted to send canary token via email tool.",
        )
        assert report.risk_score == 1.0
        assert report.invariant_at_risk == "I3"
 
        # Emit two events: DLP hit + incident
        path = tmp_path / "tel.jsonl"
        dlp_event = TelemetryEvent(
            correlation_id="req-002",
            event_type=EventType.DLP_HIT,
            severity=SeverityLevel.CRITICAL,
            reason_code="CANARY_LEAK",
            risk_score=result.score,
            invariant_violated="I3",
        )
        incident_event = TelemetryEvent(
            correlation_id="req-002",
            event_type=EventType.INCIDENT_CREATED,
            severity=SeverityLevel.CRITICAL,
            risk_score=result.score,
        )
        async def _emit_both():
            await asyncio.gather(
                emit_jsonl(dlp_event, path),
                emit_jsonl(incident_event, path),
            )
        asyncio.run(_emit_both())
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2
 
    def test_forbidden_tool_attempt(self, tmp_path):
        """Agent tries to call a tool outside its permission scope (I1)."""
        inp = RiskInput(
            decision=ContractDecision.BLOCK,
            violations=["I1"],
            tool_risk_level=RiskLevel.CRITICAL,
        )
        result = compute_risk_score(inp)
 
        assert result.score >= DEFAULT_CONFIG.layer_b.violation_i1_floor
        assert result.severity in (Severity.HIGH, Severity.CRITICAL)
        assert "I1" in result.violated_invariants
 
        event = TelemetryEvent(
            correlation_id="req-003",
            event_type=EventType.POLICY_BLOCK,
            severity=SeverityLevel.ERROR,
            tool_name="delete_database",
            reason_code="TOOL_FORBIDDEN",
            invariant_violated="I1",
            risk_score=result.score,
        )
        path = tmp_path / "tel.jsonl"
        asyncio.run(emit_jsonl(event, path))
        data = json.loads(path.read_text().strip())
        assert data["reason_code"] == "TOOL_FORBIDDEN"
        assert data["tool_name"] == "delete_database"
 
    def test_human_approval_workflow(self, tmp_path):
        """High-risk tool triggers approval, then gets granted."""
        inp = RiskInput(
            decision=ContractDecision.REQUIRE_APPROVAL,
            tool_risk_level=RiskLevel.HIGH,
        )
        result = compute_risk_score(inp)
        assert result.score >= DEFAULT_CONFIG.layer_b.decision_approval_floor
 
        path = tmp_path / "tel.jsonl"
        for event_type in (EventType.APPROVAL_REQUIRED, EventType.APPROVAL_GRANTED):
            e = TelemetryEvent(
                correlation_id="req-004",
                event_type=event_type,
                tool_name="send_email",
                risk_score=result.score,
            )
            asyncio.run(emit_jsonl(e, path))
 
        lines = path.read_text().strip().splitlines()
        types = [json.loads(l)["event_type"] for l in lines]
        assert "approval_required" in types
        assert "approval_granted" in types
 
    def test_hallucinating_agent_with_pii(self, tmp_path):
        """Agent with high hallucination risk also leaks PII."""
        inp = RiskInput(
            hallucination_risk=0.85,
            grounding_score=0.10,
            pii_matches=True,
            action=DLPAction.REDACT,
        )
        result = compute_risk_score(inp)
        assert result.score >= DEFAULT_CONFIG.layer_c.pii_matches_floor
        assert result.severity in (Severity.HIGH, Severity.CRITICAL)
 