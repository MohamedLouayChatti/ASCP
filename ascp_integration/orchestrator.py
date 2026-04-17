from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncGenerator

import dlp
from dlp.config import DLPConfig
from dlp.models import DLPAction as DLPModelAction
from layerb.engine import LayerBEngine
from layerd.risk import (
    DLPAction as RiskDLPAction,
    RiskInput,
    RiskLevel,
    Severity,
    compute_risk_score,
)
from layerd.telemetry.events import EventType, SeverityLevel, TelemetryEvent
from layerd.telemetry.sink_jsonl import emit_jsonl

logger = logging.getLogger(__name__)


@dataclass
class ASCPDecision:
    """Transport-friendly decision object returned by all integration hooks."""

    status: str = "ALLOW"
    approval_token: str = ""
    reason_code: str = "ALLOWED"
    violations: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    severity: str = "low"
    trace: str = ""


class ASCPOrchestrator:
    """Coordinates ASCP Layers A, B, C, and D for SDK adapters."""

    def __init__(
        self,
        session_id: str,
        log_path: str = "ascp_logs.jsonl",
        *,
        layer_b_engine: LayerBEngine | None = None,
        dlp_config: Path | Any | None = None,
    ) -> None:
        self.session_id = session_id
        self.log_path = log_path

        logger.info("Initializing Layer C (DLP)...")
        dlp.init(dlp_config if dlp_config is not None else _sdk_default_dlp_config())

        logger.info("Initializing Layer B (Engine)...")
        self.layer_b_engine = layer_b_engine or LayerBEngine()

    def load_layer_b_policy(self, policy_path: str) -> None:
        logger.info("Loading custom Layer B policy from: %s", policy_path)
        self.layer_b_engine = LayerBEngine(policy_path=policy_path)

    async def begin_invocation(
        self,
        correlation_id: str,
        context: dict[str, Any] | None = None,
    ) -> tuple[str, ASCPDecision]:
        session_id = str(uuid.uuid4())
        await self._emit(
            correlation_id,
            EventType.EVAL_VECTOR,
            f"Started invocation session {session_id}",
            details={"context": _safe_context(context)},
        )
        return session_id, ASCPDecision(trace="Invocation started.")

    async def end_invocation(self, correlation_id: str, session_id: str) -> ASCPDecision:
        await self._emit(
            correlation_id,
            EventType.EVAL_VECTOR,
            f"Ended invocation session {session_id}",
        )
        return ASCPDecision(trace="Invocation ended.")

    async def hook_system_prompt(
        self,
        correlation_id: str,
        prompt_text: str,
        context: dict[str, Any] | None = None,
    ) -> tuple[str, ASCPDecision]:
        """Inspect and instrument the system prompt before it reaches the model."""

        injected_prompt, _token, label = dlp.inject_canary_into_system_prompt(prompt_text)
        await self._emit(
            correlation_id,
            EventType.EVAL_VECTOR,
            "System prompt inspected and instrumented.",
            details={"framework": _context_value(context, "framework"), "canary_label": label},
        )
        return injected_prompt, ASCPDecision(
            status="ALLOW",
            reason_code="SYSTEM_PROMPT_INSTRUMENTED",
            trace="Layer C inserted a prompt canary for leak detection.",
        )

    async def hook_user_input(
        self,
        correlation_id: str,
        input_text: str,
        context: dict[str, Any] | None = None,
    ) -> tuple[str, ASCPDecision]:
        """Inspect user input before it is added to the agent state."""

        decision = dlp.scan_output(input_text)
        ascp_decision = self._decision_from_dlp(decision, default_reason="USER_INPUT_SCANNED")
        if decision.should_block:
            await self._log_risk(
                correlation_id,
                "I3",
                1.0,
                decision.safe_message or "User input blocked by DLP.",
            )
            return decision.safe_message or "[Input Blocked by ASCP]", ascp_decision

        await self._emit(
            correlation_id,
            EventType.EVAL_VECTOR,
            "User input inspected.",
            details={"framework": _context_value(context, "framework")},
        )
        return decision.clean_text, ascp_decision

    async def hook_prompt_get(
        self,
        correlation_id: str,
        prompt_name: str,
        context: dict[str, Any] | None = None,
        args: dict[str, Any] | None = None,
        approval_token: str | None = None,
    ) -> tuple[str, ASCPDecision]:
        """Validate access to a named prompt template.

        The SDK validates access; the framework/app remains responsible for loading
        the actual prompt body from its prompt registry.
        """

        result = self.layer_b_engine.validator.validate_prompt_get(
            prompt_name,
            args or {},
            approval_token=approval_token,
            agent_id=_context_value(context, "agent_id", "unknown"),
            framework=_context_value(context, "framework", "custom"),
        )
        decision = self._decision_from_contract(result)
        await self._emit(
            correlation_id,
            EventType.TOOL_CALL_ATTEMPT,
            f"Prompt '{prompt_name}' validation: {decision.status}",
            risk_score=decision.risk_score,
        )
        return "", decision

    async def hook_resource_read(
        self,
        correlation_id: str,
        resource_uri: str,
        context: dict[str, Any] | None = None,
        approval_token: str | None = None,
    ) -> tuple[str, ASCPDecision]:
        """Validate a resource/document read before the framework fetches it."""

        result = self.layer_b_engine.validator.validate_resource_read(
            resource_uri,
            approval_token=approval_token,
            agent_id=_context_value(context, "agent_id", "unknown"),
            framework=_context_value(context, "framework", "custom"),
        )
        decision = self._decision_from_contract(result)
        event_type = EventType.POLICY_BLOCK if decision.status == "BLOCK" else EventType.RETRIEVAL
        await self._emit(
            correlation_id,
            event_type,
            f"Resource '{resource_uri}' validation: {decision.status}",
            risk_score=decision.risk_score,
        )
        return "", decision

    async def hook_rag_retrieval(
        self,
        correlation_id: str,
        retrieved_docs: list[dict[str, str]],
        context: dict[str, Any] | None = None,
    ) -> tuple[list[dict[str, str]], str | None, ASCPDecision]:
        injected_docs, token, label = dlp.inject_canaries_into_context(retrieved_docs)
        await self._emit(
            correlation_id,
            EventType.RETRIEVAL,
            "RAG context retrieved and instrumented.",
            details={
                "doc_count": len(retrieved_docs),
                "framework": _context_value(context, "framework"),
                "canary_label": label,
            },
        )
        return injected_docs, token, ASCPDecision(
            status="ALLOW",
            reason_code="RAG_CONTEXT_INSTRUMENTED",
            trace="Layer C inserted a context canary for leak detection.",
        )

    async def hook_tool_call(
        self,
        correlation_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        approval_token: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> tuple[ASCPDecision, dict[str, Any]]:
        dlp_decision = dlp.scan_tool_args(tool_name, tool_args)
        if dlp_decision.should_block:
            await self._log_risk(
                correlation_id,
                "I3",
                1.0,
                dlp_decision.safe_message or "Tool blocked by DLP.",
            )
            return self._decision_from_dlp(dlp_decision, default_reason="TOOL_ARGS_DLP_BLOCK"), tool_args

        invocation_context = _layer_b_invocation_context(context)
        lb_decision = self.layer_b_engine.explain_decision(
            tool_name,
            tool_args,
            approval_token=approval_token,
            evidence_ids=_context_list(context, "evidence_ids"),
            trust_vector=_context_value(context, "trust_vector"),
            invocation_context=invocation_context,
            agent_id=_context_value(context, "agent_id", "unknown"),
            framework=_context_value(context, "framework", "custom"),
        )
        decision = self._decision_from_layer_b_dict(lb_decision)
        sanitized_args = lb_decision.get("sanitized_args") or tool_args

        if decision.status == "BLOCK":
            await self._log_risk(
                correlation_id,
                "I1",
                decision.risk_score or 1.0,
                f"Tool '{tool_name}' blocked by Layer B: {decision.reason_code}",
            )
        elif decision.status == "REQUIRE_APPROVAL":
            await self._emit(
                correlation_id,
                EventType.APPROVAL_REQUIRED,
                f"Tool '{tool_name}' requires approval: {decision.reason_code}",
                risk_score=decision.risk_score,
            )
        else:
            await self._emit(
                correlation_id,
                EventType.TOOL_CALL_ATTEMPT,
                f"Tool '{tool_name}' allowed.",
                risk_score=decision.risk_score,
            )

        return decision, sanitized_args

    async def hook_tool_result(
        self,
        correlation_id: str,
        tool_name: str,
        result: Any,
        context: dict[str, Any] | None = None,
    ) -> tuple[str, ASCPDecision]:
        decision = dlp.scan_tool_result(tool_name, result)
        ascp_decision = self._decision_from_dlp(decision, default_reason="TOOL_RESULT_SCANNED")
        if decision.should_block:
            await self._log_risk(
                correlation_id,
                "I3",
                1.0,
                decision.safe_message or "Tool result blocked by DLP.",
            )
            return decision.safe_message or "[Tool Result Blocked by ASCP]", ascp_decision

        await self._emit(
            correlation_id,
            EventType.TOOL_CALL_RESULT,
            f"Tool '{tool_name}' result scanned.",
            details={"framework": _context_value(context, "framework")},
        )
        return decision.clean_text, ascp_decision

    async def hook_agent_output(
        self,
        correlation_id: str,
        generated_text: str,
        context_docs: list[str],
        context: dict[str, Any] | None = None,
    ) -> tuple[str, ASCPDecision]:
        grounding_score = 1.0
        grounding_trace = ""
        if context_docs:
            from grounding.support_checker import compute_grounding_score

            grounding = compute_grounding_score(generated_text, context_docs)
            grounding_score = grounding.get("grounding_score", 1.0)
            grounding_trace = json.dumps(
                {
                    "grounding_score": grounding_score,
                    "total_claims": grounding.get("total_claims", 0),
                    "contradicted_claims": grounding.get("contradicted_claims", 0),
                },
                sort_keys=True,
            )

        dlp_decision = dlp.scan_output(generated_text)
        risk_input = RiskInput(
            grounding_score=grounding_score,
            tool_risk_level=RiskLevel.UNKNOWN,
            should_block=dlp_decision.should_block,
            action=_risk_dlp_action(dlp_decision.action),
            canary_hits=bool(dlp_decision.dlp_result and dlp_decision.dlp_result.canary_hits),
            secret_matches=bool(dlp_decision.dlp_result and dlp_decision.dlp_result.secret_matches),
            pii_matches=bool(dlp_decision.dlp_result and dlp_decision.dlp_result.pii_matches),
            hallucination_risk=max(0.0, min(1.0, 1.0 - grounding_score)),
        )
        risk = compute_risk_score(risk_input)

        decision = self._decision_from_dlp(dlp_decision, default_reason="OUTPUT_SCANNED")
        decision.risk_score = risk.score
        decision.severity = risk.severity.value
        decision.trace = "\n".join(risk.reasoning_trace)
        if grounding_trace:
            decision.trace = f"{decision.trace}\n[GROUNDING] {grounding_trace}"

        if risk.severity == Severity.CRITICAL or dlp_decision.should_block:
            decision.status = "BLOCK"
            decision.reason_code = decision.reason_code or "OUTPUT_RISK_BLOCK"
            await self._emit(
                correlation_id,
                EventType.POLICY_BLOCK,
                f"Blocked output. Risk: {risk.score}",
                risk_score=risk.score,
            )
            return dlp_decision.safe_message or "[Output Blocked by ASCP]", decision

        if decision.status == "REDACT":
            await self._emit(
                correlation_id,
                EventType.DLP_HIT,
                f"Output redacted. Risk: {risk.score}",
                risk_score=risk.score,
            )
        else:
            await self._emit(
                correlation_id,
                EventType.TOOL_CALL_RESULT,
                f"Output allowed. Risk: {risk.score}",
                risk_score=risk.score,
            )
        return dlp_decision.clean_text, decision

    async def hook_streaming_agent_output(
        self,
        correlation_id: str,
        chunk_stream: AsyncGenerator[str, None],
        context: dict[str, Any] | None = None,
    ) -> AsyncGenerator[tuple[str, ASCPDecision], None]:
        async for chunk in chunk_stream:
            # Chunks are forwarded as they arrive. Call hook_agent_output on the
            # final accumulated answer when the framework can provide one.
            yield chunk, ASCPDecision(reason_code="STREAM_CHUNK_FORWARDED")

    def _decision_from_layer_b_dict(self, payload: dict[str, Any]) -> ASCPDecision:
        status_map = {
            "allow": "ALLOW",
            "block": "BLOCK",
            "require_approval": "REQUIRE_APPROVAL",
        }
        raw_status = str(payload.get("decision", "allow")).lower()
        status = status_map.get(raw_status, "ALLOW")
        risk_score = 0.0
        severity = "low"
        if status == "BLOCK":
            risk_score = 1.0
            severity = "critical"
        elif status == "REQUIRE_APPROVAL":
            risk_score = 0.7
            severity = "medium"

        return ASCPDecision(
            status=status,
            approval_token=payload.get("approval_token") or "",
            reason_code=payload.get("reason_code") or "ALLOWED",
            violations=list(payload.get("violations") or []),
            risk_score=risk_score,
            severity=severity,
            trace=json.dumps(payload.get("details") or {}, default=str)
            if isinstance(payload.get("details"), dict)
            else str(payload.get("details") or ""),
        )

    def _decision_from_contract(self, result: Any) -> ASCPDecision:
        return self._decision_from_layer_b_dict(
            {
                "decision": _enum_value(getattr(result, "decision", "allow")),
                "approval_token": getattr(result, "approval_token", "") or "",
                "reason_code": getattr(result, "reason_code", "") or "ALLOWED",
                "violations": getattr(result, "violations", []) or [],
                "details": getattr(result, "details", "") or "",
            }
        )

    def _decision_from_dlp(
        self,
        decision: Any,
        *,
        default_reason: str,
    ) -> ASCPDecision:
        action = getattr(decision, "action", DLPModelAction.ALLOW)
        dlp_result = getattr(decision, "dlp_result", None)
        original_text = getattr(dlp_result, "original_text", None)
        was_modified = original_text is not None and decision.clean_text != original_text
        status = "ALLOW"
        if getattr(decision, "should_block", False):
            status = "BLOCK"
        elif getattr(decision, "should_escalate", False):
            status = "ESCALATE"
        elif action == DLPModelAction.REDACT or was_modified:
            status = "REDACT"

        violations = list(getattr(decision, "violations", []) or [])
        return ASCPDecision(
            status=status,
            reason_code=getattr(decision, "decision_reason", "") or default_reason,
            violations=violations,
            risk_score=1.0 if status == "BLOCK" else (0.4 if status == "REDACT" else 0.0),
            severity="critical" if status == "BLOCK" else ("medium" if status == "ESCALATE" else "low"),
            trace=getattr(dlp_result, "decision_reason", "") or getattr(decision, "decision_layer", ""),
        )

    async def _emit(
        self,
        correlation_id: str,
        event_type: EventType,
        message: str,
        risk_score: float = 0.0,
        details: dict[str, Any] | None = None,
    ) -> None:
        event = TelemetryEvent(
            event_id=str(uuid.uuid4()),
            correlation_id=correlation_id,
            session_id=self.session_id,
            event_type=event_type,
            severity=SeverityLevel.INFO,
            reason_code=message,
            risk_score=risk_score,
            details=details or {},
        )
        await emit_jsonl(event, Path(self.log_path))

    async def _log_risk(self, correlation_id: str, invariant: str, risk: float, message: str) -> None:
        event = TelemetryEvent(
            event_id=str(uuid.uuid4()),
            correlation_id=correlation_id,
            session_id=self.session_id,
            event_type=EventType.POLICY_BLOCK,
            severity=SeverityLevel.CRITICAL,
            reason_code=message,
            invariant_violated=invariant,
            risk_score=risk,
        )
        await emit_jsonl(event, Path(self.log_path))


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value))


def _risk_dlp_action(action: DLPModelAction) -> RiskDLPAction:
    name = getattr(action, "name", "ALLOW").lower()
    if name == "block":
        return RiskDLPAction.BLOCK
    if name == "redact":
        return RiskDLPAction.REDACT
    if name == "escalate":
        return RiskDLPAction.ESCALATE
    return RiskDLPAction.ALLOW


def _sdk_default_dlp_config() -> DLPConfig:
    """Default SDK policy that never downloads an ML model implicitly."""

    config = DLPConfig.defaults()
    config.unmatched_action = DLPModelAction.ALLOW
    for pattern in config.secret_patterns:
        if pattern.action == DLPModelAction.PASS_TO_ML:
            pattern.action = DLPModelAction.BLOCK
    for pattern in config.pii_patterns:
        if pattern.action == DLPModelAction.PASS_TO_ML:
            pattern.action = DLPModelAction.REDACT
    return config


def _context_value(context: dict[str, Any] | None, key: str, default: Any = "") -> Any:
    if not isinstance(context, dict):
        return default
    value = context.get(key, default)
    return default if value is None else value


def _context_list(context: dict[str, Any] | None, key: str) -> list[str]:
    value = _context_value(context, key, [])
    return list(value) if isinstance(value, (list, tuple)) else []


def _layer_b_invocation_context(context: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    return {
        "workflow": context.get("workflow"),
        "history": list(context.get("history") or []),
        "state": context.get("state") or {},
        "intent": context.get("intent"),
        "argument_schema": context.get("argument_schema"),
        "input_schema": context.get("input_schema"),
        "metadata": context.get("metadata") or {},
    }


def _safe_context(context: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    return {
        key: value
        for key, value in context.items()
        if key in {"agent_id", "framework", "workflow", "history", "evidence_ids"}
    }
