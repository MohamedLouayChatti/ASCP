"""
ASCP FastAPI Gateway — main entry point.

All agent traffic flows through this gateway via two paths:

  1. Legacy /agent/query (Tier 3: framework-specific hooks)
     - Single hardcoded agent execution path
     - Kept for backward compatibility

  2. /mcp (Tier 1 + 2: official MCP SDK transport)
     - Mounted FastMCP server
     - Works with native MCP clients or MCP-adapted frameworks
     - Validates all tool calls, resource reads, and prompts through ASCP

Enforcement order per request:
  1. Rate limiting
  2. PEP Input    — sanitize + injection check
  3. Tool/Resource validation (C1 contracts) — I1, I2
  4. PEP Output   — DLP scan + grounding check — I3, I4
  5. Risk scoring + approval workflow
  6. Telemetry    — emit events + incidents
  7. Response     — allowed / blocked / escalated
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import AsyncExitStack
from contextlib import asynccontextmanager
from html import escape
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from apps.config import settings
from apps.adapters.runtime_registry import resolve_tool_path
from apps.gateway.middleware.pep_input import inspect_input
from apps.gateway.middleware.pep_output import inspect_output
from apps.gateway.middleware.pep_tool import ContractValidator
from apps.gateway.policies.editor import PolicyEditor
from apps.gateway.policies.loader import PolicyLoader
from apps.mcp.proxy import MCPProxy
from apps.risk.scorer import RiskInput, compute_risk_score
from apps.telemetry import emit
from apps.telemetry.langwatch import setup_langwatch
from apps.telemetry.observed import get_observed_registry
from apps.telemetry.query import get_recent_events
from apps.telemetry.events import (
    EventType,
    IncidentReport,
    SeverityLevel,
    TelemetryEvent,
)
from security.dlp.canaries import CanarySeeder

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
)
logger = structlog.get_logger(__name__)

# --------------------------------------------------------------------------- #
# App-wide singletons (initialised in lifespan)
# --------------------------------------------------------------------------- #
_policy_loader: PolicyLoader | None = None
_contract_validator: ContractValidator | None = None
_canary_seeder: CanarySeeder | None = None
_mcp_proxy: MCPProxy | None = None
_policy_editor: PolicyEditor | None = None

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit])


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown logic."""
    global _policy_loader, _contract_validator, _canary_seeder, _mcp_proxy, _policy_editor

    async with AsyncExitStack() as stack:
        logger.info("ASCP gateway starting", env=settings.env)
        setup_langwatch()

        _policy_loader = PolicyLoader(settings.policy_path)
        _contract_validator = ContractValidator(
            settings.tool_permissions_path,
            settings.schemas_dir,
          langwatch_enabled=settings.langwatch_enabled,
          langwatch_api_key=settings.langwatch_api_key,
          langwatch_endpoint=settings.langwatch_endpoint,
          langwatch_project=settings.langwatch_project,
          langwatch_debug=settings.langwatch_debug,
        )
        _policy_editor = PolicyEditor(settings.tool_permissions_path)
        _canary_seeder = CanarySeeder()
        _canary_seeder.seed_workspace(settings.workspace_path)
        _mcp_proxy = MCPProxy(
            policy_loader=_policy_loader,
            contract_validator=_contract_validator,
            canary_seeder=_canary_seeder,
        )

        mcp_app = _mcp_proxy.streamable_http_app()
        await stack.enter_async_context(_mcp_proxy.session_manager.run())

        existing_mount = next(
            (route for route in app.router.routes if getattr(route, "name", "") == "mcp-sdk"),
            None,
        )
        if existing_mount is None:
            app.mount("/mcp", mcp_app, name="mcp-sdk")
        else:
            existing_mount.app = mcp_app

        logger.info(
            "ASCP ready",
            tools=_contract_validator.list_tools(),
            enforcement=_policy_loader.enforcement_mode,
        )
        yield
        logger.info("ASCP gateway shutting down")


app = FastAPI(
    title="ASCP — Agent Security Control Plane",
    version="0.1.0",
    description="Security-first control plane for RAG and tool-using LLM agents.",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.env != "production" else [],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Request / Response models
# --------------------------------------------------------------------------- #


class AgentRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=32768)
    session_id: str | None = None
    retrieval_context: list[dict[str, Any]] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TrustVectorResponse(BaseModel):
    grounding_score: float
    hallucination_risk: float
    context_sufficiency: float
    retrieval_relevance: float
    abstain_recommended: bool
    leakage_flag: bool
    action_safety_flag: bool


class AgentResponse(BaseModel):
    session_id: str
    correlation_id: str
    answer: str
    blocked: bool
    block_reason: str | None
    risk_score: float
    severity: str
    trust_vector: TrustVectorResponse
    latency_ms: float


class ToolCallRequest(BaseModel):
    tool_name: str
    args: dict[str, Any]
    correlation_id: str
    approval_token: str | None = None


class ToolCallResponse(BaseModel):
    decision: str
    tool_name: str
    reason_code: str
    details: str
    approval_token: str | None = None


class PermissionMutationRequest(BaseModel):
    kind: str
    name: str
    contract: dict[str, Any] | None = None


class ToolRunRequest(BaseModel):
    tool_name: str
    args: dict[str, Any] = Field(default_factory=dict)
    query: str | None = None
    prompt_text: str | None = None
    agent_id: str = "developer_ui"
    framework: str = "ui"
    approval_token: str | None = None


class ApprovalRunRequest(BaseModel):
    approval_token: str
    query: str | None = None
    prompt_text: str | None = None
    agent_id: str = "developer_ui"
    framework: str = "ui"


class ChatRunRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=32768)
    session_id: str | None = None


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #


@app.get("/health", tags=["ops"])
async def health():
    return {
        "status": "ok",
        "env": settings.env,
        "enforcement": _policy_loader.enforcement_mode if _policy_loader else "loading",
    }


@app.get("/readiness", tags=["ops"])
async def readiness():
    if _contract_validator is None or _policy_loader is None:
        raise HTTPException(status_code=503, detail="Not ready")
    return {"status": "ready"}


def _record_agent_run_observations(
    *,
    session_id: str,
    query: str,
    messages: list[dict[str, str]],
    steps: list[Any],
    documents: list[dict[str, Any]],
) -> None:
    assert _contract_validator is not None

    observed = get_observed_registry()
    system_prompt = next(
        (message.get("content", "") for message in messages if message.get("role") == "system"),
        "",
    )
    user_prompts = [
        message.get("content", "")
        for message in messages
        if message.get("role") == "user"
        and not message.get("content", "").startswith("Tool result for ")
    ]
    latest_user_prompt = user_prompts[-1] if user_prompts else query
    prompt_context = {
        "query": query,
        "user_prompt": latest_user_prompt,
    }
    if system_prompt:
        prompt_context["system_prompt"] = system_prompt
        observed.observe(
            "prompt",
            "agent_system_prompt",
            source="agent_chat",
            framework="agent_chat",
            agent_id=session_id,
            description="System prompt used by the ASCP agent chat surface.",
            prompt_role="system",
            prompt_text=system_prompt,
            context=prompt_context,
        )

    if latest_user_prompt:
        observed.observe(
            "prompt",
            "agent_user_prompt",
            source="agent_chat",
            framework="agent_chat",
            agent_id=session_id,
            description="User prompt observed by the ASCP agent chat surface.",
            prompt_role="user",
            prompt_text=latest_user_prompt,
            prompt_messages=user_prompts,
            context=prompt_context,
        )

    if documents:
        for index, document in enumerate(documents[:20], start=1):
            uri = str(
                document.get("uri")
                or document.get("source")
                or f"doc://{document.get('id', index)}"
            )
            observed.observe(
                "resource",
                uri,
                source="agent_chat",
                framework="agent_chat",
                agent_id=session_id,
                description=str(document.get("title") or document.get("source") or "Agent context"),
                uri=uri,
                context=prompt_context,
                registered=False,
            )

    from apps.agent_app.tools import TOOL_REGISTRY

    for step in steps:
        tool_name = getattr(step, "tool_name", None)
        if not isinstance(tool_name, str) or not tool_name:
            continue
        tool_fn = TOOL_REGISTRY.get(tool_name)
        observed.observe(
            "tool",
            tool_name,
            source="agent_chat",
            framework="agent_chat",
            agent_id=session_id,
            description=_contract_validator.get_tool_contract(tool_name).get("description", ""),
            args=getattr(step, "tool_args", {}) or {},
            context=prompt_context,
            tool_path=resolve_tool_path(tool_fn),
            registered=tool_name in _contract_validator.list_tools(),
            outcome=getattr(step, "outcome", None),
        )


async def _run_agent_pipeline(body: AgentRequest) -> dict[str, Any]:
    t_start = time.perf_counter()
    correlation_id = str(uuid.uuid4())
    session_id = body.session_id or str(uuid.uuid4())

    await emit(
        TelemetryEvent(
            correlation_id=correlation_id,
            event_type=EventType.REQUEST_START,
            details={"session_id": session_id, "query_len": len(body.query)},
        )
    )

    assert _policy_loader is not None
    assert _contract_validator is not None

    pol = _policy_loader

    sanitized_query, ops, injection_detected = inspect_input(
        body.query,
        max_length=pol.sanitization.get("max_input_length", 32768),
        strip_html=pol.sanitization.get("html_strip", True),
        unicode_norm=pol.sanitization.get("unicode_normalize", True),
    )

    if ops:
        await emit(
            TelemetryEvent(
                correlation_id=correlation_id,
                event_type=EventType.SANITIZATION,
                details={"ops": ops, "injection_detected": injection_detected},
            )
        )

    if injection_detected and pol.enforcement_mode == "strict":
        await emit(
            TelemetryEvent(
                correlation_id=correlation_id,
                event_type=EventType.POLICY_BLOCK,
                severity=SeverityLevel.WARN,
                reason_code="INJECTION_DETECTED",
                invariant_violated="I4",
                details={"query_prefix": sanitized_query[:100]},
            )
        )
        response = AgentResponse(
            session_id=session_id,
            correlation_id=correlation_id,
            answer=pol.safe_failure.get("fallback_message", "Request blocked."),
            blocked=True,
            block_reason="injection_detected",
            risk_score=0.75,
            severity="high",
            trust_vector=TrustVectorResponse(
                grounding_score=0.0,
                hallucination_risk=1.0,
                context_sufficiency=0.0,
                retrieval_relevance=0.0,
                abstain_recommended=True,
                leakage_flag=False,
                action_safety_flag=True,
            ),
            latency_ms=round((time.perf_counter() - t_start) * 1000, 2),
        )
        return {
            "response": response,
            "correlation_id": correlation_id,
            "session_id": session_id,
            "messages": [],
            "steps": [],
            "documents": [],
        }

    documents: list[dict[str, Any]] = []
    hierarchy_violation = False

    if body.retrieval_context:
        from apps.gateway.middleware.pep_retrieval import inspect_retrieval

        documents, hierarchy_violation = inspect_retrieval(body.retrieval_context)
        await emit(
            TelemetryEvent(
                correlation_id=correlation_id,
                event_type=EventType.RETRIEVAL,
                details={
                    "doc_count": len(documents),
                    "hierarchy_violation": hierarchy_violation,
                },
            )
        )

    agent_messages: list[dict[str, str]] = []
    agent_steps: list[Any] = []
    try:
        from apps.agent_app.agent import run_agent

        agent_run = await run_agent(
            query=sanitized_query,
            documents=documents,
            correlation_id=correlation_id,
            contract_validator=_contract_validator,
        )
        agent_answer = agent_run.answer
        tool_events = agent_run.events
        output_result = agent_run.output_result
        agent_messages = agent_run.messages
        agent_steps = agent_run.steps
        _record_agent_run_observations(
            session_id=session_id,
            query=sanitized_query,
            messages=agent_messages,
            steps=agent_steps,
            documents=documents,
        )
    except Exception as exc:
        logger.error("Agent execution failed", error=str(exc), correlation_id=correlation_id)
        if pol.safe_failure.get("block_on_validator_error", True):
            agent_answer = pol.safe_failure.get("fallback_message", "Request blocked.")
        else:
            agent_answer = f"An error occurred: {exc}"
        tool_events = []
        grounding_cfg = pol.grounding
        output_result = inspect_output(
            answer=agent_answer,
            query=sanitized_query,
            documents=documents,
            min_grounding_score=grounding_cfg.get(
                "min_grounding_score", settings.min_grounding_score
            ),
            max_hallucination_risk=grounding_cfg.get(
                "max_hallucination_risk", settings.max_hallucination_risk
            ),
        )

    for te in tool_events:
        await emit(te)

    tv = output_result.trust_vector
    tv.action_safety_flag = hierarchy_violation

    await emit(
        TelemetryEvent(
            correlation_id=correlation_id,
            event_type=EventType.EVAL_VECTOR,
            details={
                "grounding_score": tv.grounding_score,
                "hallucination_risk": tv.hallucination_risk,
                "abstain_recommended": tv.abstain_recommended,
                "leakage_flag": tv.leakage_flag,
            },
        )
    )

    if output_result.dlp_result.has_violations:
        await emit(
            TelemetryEvent(
                correlation_id=correlation_id,
                event_type=EventType.DLP_HIT,
                severity=SeverityLevel.CRITICAL
                if output_result.dlp_result.canary_hits
                else SeverityLevel.WARN,
                reason_code="DLP_VIOLATION",
                invariant_violated="I3",
                details={"violations": output_result.dlp_result.violations},
            )
        )

    risk_inp = RiskInput(
        grounding_score=tv.grounding_score,
        hallucination_risk=tv.hallucination_risk,
        context_sufficiency=tv.context_sufficiency,
        canary_leaked=bool(output_result.dlp_result.canary_hits),
        secret_leaked=bool(output_result.dlp_result.secret_matches),
        pii_detected=bool(output_result.dlp_result.pii_matches),
        injection_detected=injection_detected,
        hierarchy_violation=hierarchy_violation,
    )
    risk_score, severity = compute_risk_score(risk_inp)

    if risk_score >= 0.6 or output_result.blocked:
        incident = IncidentReport(
            correlation_id=correlation_id,
            trigger=output_result.block_reason or f"risk_score={risk_score}",
            blocked_action="output_blocked" if output_result.blocked else None,
            redacted_fields=output_result.dlp_result.violations,
            invariant_at_risk=output_result.dlp_result.invariant_violated,
            evidence_references=[e.get("doc_id", "") for e in tv.evidence_references],
            risk_score=risk_score,
            summary=f"ASCP incident: {output_result.block_reason or 'elevated risk detected'}",
        )
        await emit(
            TelemetryEvent(
                correlation_id=correlation_id,
                event_type=EventType.INCIDENT_CREATED,
                severity=SeverityLevel.CRITICAL,
                risk_score=risk_score,
                details=incident.model_dump(mode="json"),
            )
        )

    latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    await emit(
        TelemetryEvent(
            correlation_id=correlation_id,
            event_type=EventType.REQUEST_END,
            risk_score=risk_score,
            details={"latency_ms": latency_ms, "blocked": output_result.blocked},
        )
    )

    response = AgentResponse(
        session_id=session_id,
        correlation_id=correlation_id,
        answer=output_result.final_text,
        blocked=output_result.blocked,
        block_reason=output_result.block_reason,
        risk_score=risk_score,
        severity=severity.value,
        trust_vector=TrustVectorResponse(
            grounding_score=tv.grounding_score,
            hallucination_risk=tv.hallucination_risk,
            context_sufficiency=tv.context_sufficiency,
            retrieval_relevance=tv.retrieval_relevance,
            abstain_recommended=tv.abstain_recommended,
            leakage_flag=tv.leakage_flag,
            action_safety_flag=tv.action_safety_flag,
        ),
        latency_ms=latency_ms,
    )

    return {
        "response": response,
        "correlation_id": correlation_id,
        "session_id": session_id,
        "messages": agent_messages,
        "steps": agent_steps,
        "documents": documents,
    }


# --------------------------------------------------------------------------- #
# Main agent endpoint
# --------------------------------------------------------------------------- #


@app.post("/agent/query", response_model=AgentResponse, tags=["agent"])
@limiter.limit(settings.rate_limit)
async def agent_query(request: Request, body: AgentRequest) -> AgentResponse:
    """
    Main endpoint.  Runs the full ASCP enforcement pipeline around agent execution.
    """
    del request
    result = await _run_agent_pipeline(body)
    return result["response"]

    t_start = time.perf_counter()
    correlation_id = str(uuid.uuid4())
    session_id = body.session_id or str(uuid.uuid4())

    await emit(
        TelemetryEvent(
            correlation_id=correlation_id,
            event_type=EventType.REQUEST_START,
            details={"session_id": session_id, "query_len": len(body.query)},
        )
    )

    assert _policy_loader is not None
    assert _contract_validator is not None

    pol = _policy_loader

    # ------------------------------------------------------------------ #
    # 1. PEP Input — sanitize + injection check
    # ------------------------------------------------------------------ #
    sanitized_query, ops, injection_detected = inspect_input(
        body.query,
        max_length=pol.sanitization.get("max_input_length", 32768),
        strip_html=pol.sanitization.get("html_strip", True),
        unicode_norm=pol.sanitization.get("unicode_normalize", True),
    )

    if ops:
        await emit(
            TelemetryEvent(
                correlation_id=correlation_id,
                event_type=EventType.SANITIZATION,
                details={"ops": ops, "injection_detected": injection_detected},
            )
        )

    # Block on injection in strict mode
    if injection_detected and pol.enforcement_mode == "strict":
        await emit(
            TelemetryEvent(
                correlation_id=correlation_id,
                event_type=EventType.POLICY_BLOCK,
                severity=SeverityLevel.WARN,
                reason_code="INJECTION_DETECTED",
                invariant_violated="I4",
                details={"query_prefix": sanitized_query[:100]},
            )
        )
        return AgentResponse(
            session_id=session_id,
            correlation_id=correlation_id,
            answer=pol.safe_failure.get("fallback_message", "Request blocked."),
            blocked=True,
            block_reason="injection_detected",
            risk_score=0.75,
            severity="high",
            trust_vector=TrustVectorResponse(
                grounding_score=0.0,
                hallucination_risk=1.0,
                context_sufficiency=0.0,
                retrieval_relevance=0.0,
                abstain_recommended=True,
                leakage_flag=False,
                action_safety_flag=True,
            ),
            latency_ms=round((time.perf_counter() - t_start) * 1000, 2),
        )

    # ------------------------------------------------------------------ #
    # 2. Retrieval context inspection (PEP Retrieval)
    # ------------------------------------------------------------------ #
    documents: list[dict[str, Any]] = []
    hierarchy_violation = False

    if body.retrieval_context:
        from apps.gateway.middleware.pep_retrieval import inspect_retrieval

        documents, hierarchy_violation = inspect_retrieval(body.retrieval_context)
        await emit(
            TelemetryEvent(
                correlation_id=correlation_id,
                event_type=EventType.RETRIEVAL,
                details={
                    "doc_count": len(documents),
                    "hierarchy_violation": hierarchy_violation,
                },
            )
        )

    # ------------------------------------------------------------------ #
    # 3. Agent execution (lazy import to avoid circular deps)
    # ------------------------------------------------------------------ #
    try:
        from apps.agent_app.agent import run_agent

        agent_run = await run_agent(
            query=sanitized_query,
            documents=documents,
            correlation_id=correlation_id,
            contract_validator=_contract_validator,
        )
        agent_answer = agent_run.answer
        tool_events = agent_run.events
        output_result = agent_run.output_result
    except Exception as exc:
        logger.error("Agent execution failed", error=str(exc), correlation_id=correlation_id)
        if pol.safe_failure.get("block_on_validator_error", True):
            agent_answer = pol.safe_failure.get("fallback_message", "Request blocked.")
        else:
            agent_answer = f"An error occurred: {exc}"
        tool_events = []
        grounding_cfg = pol.grounding
        output_result = inspect_output(
            answer=agent_answer,
            query=sanitized_query,
            documents=documents,
            min_grounding_score=grounding_cfg.get(
                "min_grounding_score", settings.min_grounding_score
            ),
            max_hallucination_risk=grounding_cfg.get(
                "max_hallucination_risk", settings.max_hallucination_risk
            ),
        )

    # Emit tool events
    for te in tool_events:
        await emit(te)

    # ------------------------------------------------------------------ #
    # 4. PEP Output — DLP + Grounding
    # ------------------------------------------------------------------ #
    tv = output_result.trust_vector
    tv.action_safety_flag = hierarchy_violation

    # Emit eval vector event
    await emit(
        TelemetryEvent(
            correlation_id=correlation_id,
            event_type=EventType.EVAL_VECTOR,
            details={
                "grounding_score": tv.grounding_score,
                "hallucination_risk": tv.hallucination_risk,
                "abstain_recommended": tv.abstain_recommended,
                "leakage_flag": tv.leakage_flag,
            },
        )
    )

    # Emit DLP events
    if output_result.dlp_result.has_violations:
        await emit(
            TelemetryEvent(
                correlation_id=correlation_id,
                event_type=EventType.DLP_HIT,
                severity=SeverityLevel.CRITICAL
                if output_result.dlp_result.canary_hits
                else SeverityLevel.WARN,
                reason_code="DLP_VIOLATION",
                invariant_violated="I3",
                details={"violations": output_result.dlp_result.violations},
            )
        )

    # ------------------------------------------------------------------ #
    # 5. Risk scoring
    # ------------------------------------------------------------------ #
    risk_inp = RiskInput(
        grounding_score=tv.grounding_score,
        hallucination_risk=tv.hallucination_risk,
        context_sufficiency=tv.context_sufficiency,
        canary_leaked=bool(output_result.dlp_result.canary_hits),
        secret_leaked=bool(output_result.dlp_result.secret_matches),
        pii_detected=bool(output_result.dlp_result.pii_matches),
        injection_detected=injection_detected,
        hierarchy_violation=hierarchy_violation,
    )
    risk_score, severity = compute_risk_score(risk_inp)

    # ------------------------------------------------------------------ #
    # 6. Incident report for high-risk events
    # ------------------------------------------------------------------ #
    if risk_score >= 0.6 or output_result.blocked:
        incident = IncidentReport(
            correlation_id=correlation_id,
            trigger=output_result.block_reason or f"risk_score={risk_score}",
            blocked_action="output_blocked" if output_result.blocked else None,
            redacted_fields=output_result.dlp_result.violations,
            invariant_at_risk=output_result.dlp_result.invariant_violated,
            evidence_references=[e.get("doc_id", "") for e in tv.evidence_references],
            risk_score=risk_score,
            summary=f"ASCP incident: {output_result.block_reason or 'elevated risk detected'}",
        )
        await emit(
            TelemetryEvent(
                correlation_id=correlation_id,
                event_type=EventType.INCIDENT_CREATED,
                severity=SeverityLevel.CRITICAL,
                risk_score=risk_score,
                details=incident.model_dump(mode="json"),
            )
        )

    latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    await emit(
        TelemetryEvent(
            correlation_id=correlation_id,
            event_type=EventType.REQUEST_END,
            risk_score=risk_score,
            details={"latency_ms": latency_ms, "blocked": output_result.blocked},
        )
    )

    return AgentResponse(
        session_id=session_id,
        correlation_id=correlation_id,
        answer=output_result.final_text,
        blocked=output_result.blocked,
        block_reason=output_result.block_reason,
        risk_score=risk_score,
        severity=severity.value,
        trust_vector=TrustVectorResponse(
            grounding_score=tv.grounding_score,
            hallucination_risk=tv.hallucination_risk,
            context_sufficiency=tv.context_sufficiency,
            retrieval_relevance=tv.retrieval_relevance,
            abstain_recommended=tv.abstain_recommended,
            leakage_flag=tv.leakage_flag,
            action_safety_flag=tv.action_safety_flag,
        ),
        latency_ms=latency_ms,
    )


# --------------------------------------------------------------------------- #
# Tool validation endpoint (standalone, for CI testing)
# --------------------------------------------------------------------------- #


@app.post("/tools/validate", response_model=ToolCallResponse, tags=["tools"])
async def validate_tool_call(body: ToolCallRequest) -> ToolCallResponse:
    """Validate a proposed tool call against C1 contracts (no execution)."""
    assert _contract_validator is not None
    result = _contract_validator.validate_call(
        tool_name=body.tool_name,
        args=body.args,
        approval_token=body.approval_token,
    )
    await emit(
        TelemetryEvent(
            correlation_id=body.correlation_id,
            event_type=EventType.TOOL_CALL_ATTEMPT,
            tool_name=body.tool_name,
            reason_code=result.reason_code,
            details={
                "decision": result.decision.value,
                "violations": result.violations,
            },
            invariant_violated=result.violations[0] if result.violations else None,
        )
    )
    return ToolCallResponse(
        decision=result.decision.value,
        tool_name=result.tool_name,
        reason_code=result.reason_code,
        details=result.details,
        approval_token=result.approval_token,
    )


# --------------------------------------------------------------------------- #
# DLP scan endpoint (standalone)
# --------------------------------------------------------------------------- #


class DLPScanRequest(BaseModel):
    text: str


class DLPScanResponse(BaseModel):
    action: str
    violations: list[str]
    clean_text: str
    has_violations: bool


@app.post("/dlp/scan", response_model=DLPScanResponse, tags=["dlp"])
async def dlp_scan(body: DLPScanRequest) -> DLPScanResponse:
    """Scan text for DLP violations (canaries, secrets, PII)."""
    from security.dlp import scan as dlp_scan_fn

    result = dlp_scan_fn(body.text)
    return DLPScanResponse(
        action=result.action.value,
        violations=result.violations,
        clean_text=result.clean_text,
        has_violations=result.has_violations,
    )


@app.get("/")
async def root():
    return {"message": "ASCP Gateway is running. Use /docs for API documentation."}


def _prompt_trace_from_context(context: dict[str, Any]) -> dict[str, Any]:
    prompt_trace: dict[str, Any] = {}
    for key in ("system_prompt", "user_prompt", "prompt_text", "query", "messages", "prompt_messages"):
        value = context.get(key)
        if value not in (None, "", [], {}):
            prompt_trace[key] = value
    return prompt_trace


def _is_agent_observed_component(item: dict[str, Any]) -> bool:
    sources = set(item.get("sources", []))
    return bool(
        sources.intersection({"wrap", "agent_chat"})
    )


def _is_test_observed_tool(item: dict[str, Any]) -> bool:
    tool_path = str(item.get("last_metadata", {}).get("tool_path") or "")
    normalized = tool_path.replace("/", "\\").lower()
    return "\\tests\\" in normalized


def _summarize_dashboard() -> dict[str, Any]:
    assert _contract_validator is not None
    assert _policy_editor is not None

    observed = get_observed_registry().snapshot()
    policy = _policy_editor.snapshot()
    observed_tools = observed.get("tools", {})
    observed_resources = observed.get("resources", {})
    observed_prompts = observed.get("prompts", {})
    agent_tools: list[dict[str, Any]] = []
    for name, item in observed_tools.items():
        if not _is_agent_observed_component(item):
            continue
        if _is_test_observed_tool(item):
            continue
        contract = (policy.get("capabilities", {}) or policy.get("tools", {})).get(name)
        schema = (
            item.get("last_metadata", {}).get("args_schema")
            or _contract_validator.get_schema("tool", name)
            or {"type": "object", "properties": {}, "additionalProperties": True}
        )
        last_metadata = item.get("last_metadata", {})
        last_context = last_metadata.get("context") if isinstance(last_metadata.get("context"), dict) else {}
        prompt_trace = _prompt_trace_from_context(last_context)
        agent_tools.append(
            {
                "name": name,
                "description": (item.get("descriptions") or [""])[0],
                "frameworks": item.get("frameworks", []),
                "agents": item.get("agents", []),
                "sources": item.get("sources", []),
                "observation_count": item.get("observation_count", 0),
                "last_seen_at": item.get("last_seen_at"),
                "args_schema": schema,
                "permitted": contract is not None,
                "approval_required": bool(contract.get("approval_required", False)) if contract else False,
                "contract": contract,
                "tool_path": last_metadata.get("tool_path"),
                "last_args": last_metadata.get("args", {}),
                "last_context": last_context,
                "prompt_trace": prompt_trace,
                "last_prompt_text": (
                    prompt_trace.get("prompt_text")
                    or prompt_trace.get("user_prompt")
                    or prompt_trace.get("query")
                    or ""
                ),
            }
        )
    agent_tools.sort(key=lambda item: (item.get("last_seen_at") or "", item["name"]), reverse=True)

    resources = [
        {
            "name": name,
            "description": (item.get("descriptions") or [""])[0],
            "frameworks": item.get("frameworks", []),
            "sources": item.get("sources", []),
            "observation_count": item.get("observation_count", 0),
            "last_seen_at": item.get("last_seen_at"),
            "uri": item.get("last_metadata", {}).get("uri", name),
            "last_context": item.get("last_metadata", {}).get("context", {}),
        }
        for name, item in observed_resources.items()
        if _is_agent_observed_component(item)
    ]
    resources.sort(key=lambda item: (item.get("last_seen_at") or "", item["name"]), reverse=True)

    prompts = []
    for name, item in observed_prompts.items():
        if not _is_agent_observed_component(item):
            continue
        last_metadata = item.get("last_metadata", {})
        prompts.append(
            {
                "name": name,
                "description": (item.get("descriptions") or [""])[0],
                "frameworks": item.get("frameworks", []),
                "sources": item.get("sources", []),
                "observation_count": item.get("observation_count", 0),
                "last_seen_at": item.get("last_seen_at"),
                "prompt_role": last_metadata.get("prompt_role"),
                "prompt_text": last_metadata.get("prompt_text"),
                "prompt_messages": last_metadata.get("prompt_messages", []),
                "last_args": last_metadata.get("args", {}),
                "last_context": last_metadata.get("context", {}),
            }
        )
    prompts.sort(key=lambda item: (item.get("last_seen_at") or "", item["name"]), reverse=True)

    agent_tool_names = {item["name"] for item in agent_tools}
    events = [
        event
        for event in list(reversed(get_recent_events(limit=300)))
        if event.get("tool_name") in agent_tool_names
        or event.get("event_type") in {EventType.REQUEST_START.value, EventType.REQUEST_END.value}
    ]
    pending_approvals = {
        token: approval
        for token, approval in _contract_validator.pending_approvals_snapshot().items()
        if approval.get("component_name") in agent_tool_names
    }

    stats = {
        "allowed": 0,
        "blocked": 0,
        "approval_required": 0,
        "agent_tools": len(agent_tools),
        "resources": len(resources),
        "prompts": len(prompts),
    }
    for event in events:
        event_type = event.get("event_type")
        if event_type == EventType.APPROVAL_REQUIRED.value:
            stats["approval_required"] += 1
        elif event_type == EventType.POLICY_BLOCK.value:
            stats["blocked"] += 1
        elif event_type == EventType.TOOL_CALL_RESULT.value:
            stats["allowed"] += 1

    return {
        "stats": stats,
        "agent_tools": agent_tools,
        "resources": resources,
        "prompts": prompts,
        "events": events,
        "pending_approvals": pending_approvals,
        "policy": policy,
    }


@app.get("/ui/api/dashboard", tags=["ui"])
async def dashboard_data() -> dict[str, Any]:
    return _summarize_dashboard()


@app.post("/ui/api/chat", tags=["ui"])
async def run_chat_prompt(body: ChatRunRequest) -> dict[str, Any]:
    result = await _run_agent_pipeline(
        AgentRequest(
            query=body.prompt,
            session_id=body.session_id,
            metadata={"surface": "developer_ui_chat"},
        )
    )
    response: AgentResponse = result["response"]
    return {
        "session_id": response.session_id,
        "correlation_id": response.correlation_id,
        "answer": response.answer,
        "blocked": response.blocked,
        "block_reason": response.block_reason,
        "risk_score": response.risk_score,
        "severity": response.severity,
        "latency_ms": response.latency_ms,
        "messages": result["messages"],
        "steps": [
            {
                "step_index": getattr(step, "step_index", None),
                "outcome": getattr(step, "outcome", None),
                "tool_name": getattr(step, "tool_name", None),
                "tool_args": getattr(step, "tool_args", {}),
                "tool_result": getattr(step, "tool_result", None),
                "final_answer": getattr(step, "final_answer", None),
                "block_reason": getattr(step, "block_reason", None),
            }
            for step in result["steps"]
        ],
    }


@app.post("/ui/api/permissions/default", tags=["ui"])
async def create_default_permission(body: PermissionMutationRequest) -> dict[str, Any]:
    assert _policy_editor is not None
    assert _contract_validator is not None

    observed = get_observed_registry().snapshot().get(f"{body.kind}s", {}).get(body.name, {})
    contract = _policy_editor.build_default_contract(body.kind, body.name, observed)
    saved = _policy_editor.upsert_permission(body.kind, body.name, contract)
    _contract_validator.reload()
    return {"saved": True, "contract": saved}


@app.post("/ui/api/permissions/upsert", tags=["ui"])
async def upsert_permission(body: PermissionMutationRequest) -> dict[str, Any]:
    assert _policy_editor is not None
    assert _contract_validator is not None

    if body.contract is None:
        raise HTTPException(status_code=400, detail="contract is required")
    saved = _policy_editor.upsert_permission(body.kind, body.name, body.contract)
    _contract_validator.reload()
    return {"saved": True, "contract": saved}


@app.post("/ui/api/permissions/remove", tags=["ui"])
async def remove_permission(body: PermissionMutationRequest) -> dict[str, Any]:
    assert _policy_editor is not None
    assert _contract_validator is not None

    removed = _policy_editor.remove_permission(body.kind, body.name)
    _contract_validator.reload()
    return {"removed": removed}


async def _run_tool_from_ui(body: ToolRunRequest) -> dict[str, Any]:
    assert _mcp_proxy is not None

    prompt_text = body.prompt_text or body.query or f"Run tool {body.tool_name} from ASCP dashboard"
    meta: dict[str, Any] = {
        "agent_id": body.agent_id,
        "framework": body.framework,
        "context": {
            "query": body.query or prompt_text,
            "prompt_text": prompt_text,
            "user_prompt": prompt_text,
            "route": "/ui/ascp",
            "surface": "developer_ui",
        },
    }
    if body.approval_token:
        meta["approval_token"] = body.approval_token

    content, payload = await _mcp_proxy.call_tool(
        body.tool_name,
        {
            **body.args,
            "__ascp_meta": meta,
        },
    )
    observed_tool = get_observed_registry().snapshot().get("tools", {}).get(body.tool_name, {})
    last_metadata = observed_tool.get("last_metadata", {})
    return {
        "tool_name": body.tool_name,
        "content": [getattr(block, "text", str(block)) for block in content],
        "execution_details": {
            "tool_path": last_metadata.get("tool_path"),
            "args": last_metadata.get("args", body.args),
            "prompt_context": last_metadata.get("context", meta["context"]),
        },
        **payload,
    }


@app.post("/ui/api/tools/run", tags=["ui"])
async def run_tool_from_ui(body: ToolRunRequest) -> dict[str, Any]:
    return await _run_tool_from_ui(body)


@app.post("/ui/api/tools/approve-run", tags=["ui"])
async def approve_tool_from_ui(body: ApprovalRunRequest) -> dict[str, Any]:
    assert _contract_validator is not None

    pending = _contract_validator.pending_approvals_snapshot().get(body.approval_token)
    if pending is None:
        raise HTTPException(status_code=404, detail="Approval token not found")
    if pending.get("component_type") != "tool":
        raise HTTPException(status_code=400, detail="Only tool approvals can be run from the dashboard")

    return await _run_tool_from_ui(
        ToolRunRequest(
            tool_name=str(pending.get("component_name")),
            args=dict(pending.get("args", {})),
            query=body.query,
            prompt_text=body.prompt_text,
            agent_id=body.agent_id,
            framework=body.framework,
            approval_token=body.approval_token,
        )
    )


@app.get("/ui/ascp", response_class=HTMLResponse, tags=["ui"])
async def ascp_dashboard() -> HTMLResponse:
    title = escape("ASCP Control Room")
    html = """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>__TITLE__</title>
      <style>
        :root {{
          --bg: #f4efe6;
          --panel: rgba(255,255,255,0.82);
          --ink: #1d1f1f;
          --muted: #5b645f;
          --line: rgba(29,31,31,0.12);
          --good: #1d7d4d;
          --warn: #a56a00;
          --bad: #b23232;
          --accent: #0e6e82;
        }}
        body {{
          margin: 0;
          font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
          color: var(--ink);
          background:
            radial-gradient(circle at top left, rgba(14,110,130,0.18), transparent 30%),
            radial-gradient(circle at top right, rgba(165,106,0,0.16), transparent 28%),
            linear-gradient(180deg, #f8f3ea 0%, var(--bg) 100%);
        }}
        .shell {{
          max-width: 1400px;
          margin: 0 auto;
          padding: 32px 20px 48px;
        }}
        .hero {{
          display: grid;
          gap: 12px;
          margin-bottom: 24px;
        }}
        .hero h1 {{
          margin: 0;
          font-size: clamp(2rem, 4vw, 3.4rem);
          letter-spacing: -0.04em;
        }}
        .hero p {{
          margin: 0;
          color: var(--muted);
          max-width: 75ch;
        }}
        .stats, .grid {{
          display: grid;
          gap: 16px;
        }}
        .stats {{
          grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
          margin-bottom: 24px;
        }}
        .grid {{
          grid-template-columns: 1.1fr 0.9fr;
        }}
        .panel {{
          background: var(--panel);
          border: 1px solid var(--line);
          border-radius: 22px;
          box-shadow: 0 18px 50px rgba(32, 31, 26, 0.08);
          backdrop-filter: blur(16px);
          padding: 18px;
        }}
        .stat-value {{
          font-size: 2rem;
          font-weight: 700;
        }}
        .kicker {{
          text-transform: uppercase;
          font-size: 0.75rem;
          letter-spacing: 0.08em;
          color: var(--muted);
        }}
        .panel h2 {{
          margin: 0 0 14px;
          font-size: 1rem;
        }}
        .toolbar {{
          display: flex;
          gap: 10px;
          flex-wrap: wrap;
          margin-bottom: 12px;
        }}
        button {{
          border: 0;
          border-radius: 999px;
          padding: 10px 14px;
          background: var(--accent);
          color: white;
          cursor: pointer;
          font-weight: 600;
        }}
        button.secondary {{
          background: rgba(29,31,31,0.08);
          color: var(--ink);
        }}
        .pill {{
          display: inline-flex;
          align-items: center;
          gap: 6px;
          border-radius: 999px;
          padding: 4px 10px;
          font-size: 0.78rem;
          font-weight: 700;
        }}
        .allow {{ background: rgba(29,125,77,0.12); color: var(--good); }}
        .block {{ background: rgba(178,50,50,0.12); color: var(--bad); }}
        .approval {{ background: rgba(165,106,0,0.12); color: var(--warn); }}
        .list {{
          display: grid;
          gap: 10px;
          max-height: 520px;
          overflow: auto;
        }}
        .card {{
          border: 1px solid var(--line);
          border-radius: 16px;
          padding: 12px;
          background: rgba(255,255,255,0.66);
        }}
        .card strong {{
          display: block;
          margin-bottom: 4px;
        }}
        .card small {{
          display: block;
          color: var(--muted);
          margin-bottom: 8px;
          word-break: break-word;
        }}
        textarea {{
          width: 100%;
          min-height: 260px;
          border-radius: 18px;
          border: 1px solid var(--line);
          padding: 14px;
          font: 0.9rem/1.5 "IBM Plex Mono", Consolas, monospace;
          resize: vertical;
          background: rgba(255,255,255,0.78);
        }}
        pre {{
          margin: 0;
          white-space: pre-wrap;
          word-break: break-word;
          font: 0.82rem/1.5 "IBM Plex Mono", Consolas, monospace;
        }}
        .event {{
          display: grid;
          gap: 6px;
          padding: 12px 0;
          border-bottom: 1px solid var(--line);
        }}
        .event:last-child {{ border-bottom: 0; }}
        .split {{
          display: grid;
          grid-template-columns: 1fr 1fr 1fr;
          gap: 12px;
        }}
        .chat-log {{
          display: grid;
          gap: 10px;
          max-height: 280px;
          overflow: auto;
          margin-bottom: 12px;
        }}
        .bubble {{
          border-radius: 18px;
          padding: 12px 14px;
          background: rgba(255,255,255,0.7);
          border: 1px solid var(--line);
        }}
        .bubble.user {{
          background: rgba(14,110,130,0.12);
          border-color: rgba(14,110,130,0.2);
        }}
        .bubble.assistant {{
          background: rgba(29,125,77,0.1);
          border-color: rgba(29,125,77,0.18);
        }}
        @media (max-width: 980px) {{
          .grid, .split {{ grid-template-columns: 1fr; }}
        }}
      </style>
    </head>
    <body>
      <div class="shell">
        <section class="hero">
          <span class="kicker">Developer Dashboard</span>
          <h1>__TITLE__</h1>
          <p>Chat with the agent from prompts only, inspect the tools it chose, review the resources and prompts it touched, and route sensitive actions through human approval.</p>
        </section>
        <section class="stats" id="stats"></section>
        <section class="grid">
          <div class="panel">
            <h2>Observed Agent Tools</h2>
            <div class="toolbar">
              <button class="secondary" onclick="loadDashboard()">Refresh</button>
            </div>
            <div class="list" id="tools"></div>
          </div>
          <div class="panel">
            <h2>Agent Chat</h2>
            <div class="toolbar">
              <button onclick="sendPrompt()">Send Prompt</button>
              <button class="secondary" onclick="saveContract()">Save Policy</button>
              <button class="secondary" onclick="createDefaultContract()">Allow Default</button>
              <button class="secondary" onclick="requireApproval()">Require Approval</button>
              <button class="secondary" onclick="removeContract()">Remove</button>
            </div>
            <div class="chat-log" id="chatLog">
              <div class="bubble assistant">Start with a prompt here and ASCP will show which tools, prompts, and resources the agent touched.</div>
            </div>
            <div class="kicker">Chat Prompt</div>
            <textarea id="chatPrompt"></textarea>
            <p id="selection" class="kicker">Select an observed agent tool to inspect it and edit its policy while you chat.</p>
            <div class="split">
              <div>
                <div class="kicker">Tool Path</div>
                <pre id="toolPath">Select a tool to inspect its path.</pre>
              </div>
              <div>
                <div class="kicker">Last Observed Arguments</div>
                <pre id="lastArgs">No tool execution observed yet.</pre>
              </div>
              <div>
                <div class="kicker">Prompt Context Received</div>
                <pre id="promptTrace">No prompt context observed yet.</pre>
              </div>
            </div>
            <div class="kicker" style="margin-top: 12px;">Policy Contract</div>
            <textarea id="editor"></textarea>
            <div class="kicker" style="margin-top: 12px;">Last Chat Trace</div>
            <pre id="runOutput">Send a prompt to begin.</pre>
          </div>
        </section>
        <section class="split" style="margin-top: 20px;">
          <div class="panel">
            <h2>Observed Resources</h2>
            <div class="list" id="resources"></div>
          </div>
          <div class="panel">
            <h2>Agent Prompts</h2>
            <div class="list" id="prompts"></div>
          </div>
          <div class="panel">
            <h2>Pending Human Approval</h2>
            <div class="list" id="approvals"></div>
          </div>
        </section>
        <section class="grid" style="margin-top: 20px;">
          <div class="panel">
            <h2>Tool Telemetry</h2>
            <div id="events"></div>
          </div>
          <div class="panel">
            <h2>Active Chat Session</h2>
            <pre id="chatMeta">No chat session yet.</pre>
          </div>
        </section>
      </div>
      <script>
        let dashboard = {{}};
        let selected = null;
        let currentRunResult = null;
        let activeSessionId = null;
        let chatTurns = [];

        function stringify(value, fallback = '') {{
          if (value === null || value === undefined) return fallback;
          if (typeof value === 'string') return value;
          return JSON.stringify(value, null, 2);
        }}

        function badgeForEvent(event) {{
          if (event.event_type === 'approval_required') return '<span class="pill approval">Approval</span>';
          if (event.event_type === 'policy_block') return '<span class="pill block">Blocked</span>';
          if (event.event_type === 'tool_call_result') return '<span class="pill allow">Allowed</span>';
          return '<span class="pill">Observed</span>';
        }}

        function renderStats(stats) {{
          const root = document.getElementById('stats');
          root.innerHTML = [
            ['Allowed Actions', stats.allowed],
            ['Blocked Actions', stats.blocked],
            ['Human Approval', stats.approval_required],
            ['Observed Agent Tools', stats.agent_tools],
            ['Observed Resources', stats.resources],
            ['Observed Prompts', stats.prompts],
          ].map(([label, value]) => `
            <div class="panel">
              <div class="kicker">${{label}}</div>
              <div class="stat-value">${{value}}</div>
            </div>
          `).join('');
        }}

        function renderSelectedTool(tool, runResult = null) {{
          const execution = runResult?.execution_details || {{}};
          const promptContext = execution.prompt_context || tool?.prompt_trace || tool?.last_context || {{}};
          document.getElementById('toolPath').textContent =
            execution.tool_path || tool?.tool_path || 'Tool path has not been observed yet.';
          document.getElementById('lastArgs').textContent = stringify(
            execution.args || tool?.last_args || {{}},
            'No arguments observed yet.'
          );
          document.getElementById('promptTrace').textContent = stringify(
            promptContext,
            'No prompt context observed yet.'
          );
        }}

        function renderChatLog() {{
          const root = document.getElementById('chatLog');
          root.innerHTML = chatTurns.length ? chatTurns.map((turn) => `
            <div class="bubble ${{turn.role}}">
              <strong>${{turn.role === 'user' ? 'You' : 'Agent'}}</strong>
              <div>${{turn.content}}</div>
            </div>
          `).join('') : '<div class="bubble assistant">Start with a prompt here and ASCP will show which tools, prompts, and resources the agent touched.</div>';
        }}

        function renderTools(items) {{
          document.getElementById('tools').innerHTML = items.length ? items.map((item) => {{
            const permitted = Boolean(item.permitted);
            const approval = item.approval_required ? '<span class="pill approval">Approval Required</span>' : '';
            return `
              <div class="card" onclick='selectTool(${JSON.stringify(item.name)})'>
                <strong>${{item.name}}</strong>
                <small>${{item.description || 'No description yet'}}</small>
                <div class="pill ${{permitted ? 'allow' : 'block'}}">${{permitted ? 'Permission present' : 'Not yet permitted'}}</div>
                ${{approval}}
                <small>Seen ${{item.observation_count}} times · frameworks: ${{(item.frameworks || []).join(', ') || 'n/a'}}</small>
              </div>
            `;
          }}).join('') : '<div class="card"><small>No observed agent tools yet. Send a chat prompt first.</small></div>';
        }}

        function renderResources(items) {{
          document.getElementById('resources').innerHTML = items.length ? items.map((item) => `
            <div class="card">
              <strong>${{item.name}}</strong>
              <small>${{item.description || item.uri || 'Observed resource'}}</small>
              <small>Seen ${{item.observation_count}} times Â· sources: ${{(item.sources || []).join(', ') || 'n/a'}}</small>
            </div>
          `).join('') : '<div class="card"><small>No agent resources have been observed yet.</small></div>';
        }}

        function renderPrompts(items) {{
          document.getElementById('prompts').innerHTML = items.length ? items.map((item) => `
            <div class="card">
              <strong>${{item.name}}</strong>
              <small>${{item.prompt_role || 'prompt'}} Â· seen ${{item.observation_count}} times</small>
              <pre>${{stringify(item.prompt_text || item.last_args || item.prompt_messages || item.last_context, 'No prompt text observed yet.')}}</pre>
            </div>
          `).join('') : '<div class="card"><small>No agent prompts have been observed yet.</small></div>';
        }}

        function renderEvents(events) {{
          const root = document.getElementById('events');
          root.innerHTML = events.length ? events.slice(-60).reverse().map((event) => `
            <div class="event">
              <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;">
                <strong>${{event.tool_name || event.event_type}}</strong>
                ${{badgeForEvent(event)}}
              </div>
              <small>${{event.timestamp}} · ${{event.reason_code || 'NO_REASON'}}</small>
              <pre>${{JSON.stringify(event.details || {{}}, null, 2)}}</pre>
            </div>
          `).join('') : '<div class="card"><small>No events yet.</small></div>';
        }}

        function renderApprovals(approvals) {{
          const entries = Object.entries(approvals || {{}});
          document.getElementById('approvals').innerHTML = entries.length ? entries.map(([token, item]) => `
            <div class="card">
              <strong>${{item.component_name}}</strong>
              <small>${{item.component_type}} · token: ${{token}}</small>
              <pre>${{JSON.stringify(item.args || {{}}, null, 2)}}</pre>
              <button onclick='approveAndRun(${JSON.stringify(token)})'>Approve And Run</button>
            </div>
          `).join('') : '<div class="card"><small>No approvals are waiting right now.</small></div>';
        }}

        function findTool(name) {{
          return (dashboard.agent_tools || []).find((tool) => tool.name === name) || null;
        }}

        function selectTool(name) {{
          selected = {{ kind: 'tool', name }};
          const tool = findTool(name);
          const runResult = currentRunResult && currentRunResult.tool_name === name ? currentRunResult : null;
          document.getElementById('selection').textContent = `tool · ${{name}}`;
          document.getElementById('editor').value = JSON.stringify(tool?.contract || {{
            risk: 'medium',
            scopes: ['custom'],
            approval_required: false,
            description: tool?.description || '',
            constraints: {{}}
          }}, null, 2);
          document.getElementById('runOutput').textContent = runResult
            ? JSON.stringify(runResult, null, 2)
            : 'Send a chat prompt to see the latest agent trace.';
          renderSelectedTool(tool, runResult);
        }}

        async function loadDashboard() {{
          const response = await fetch('/ui/api/dashboard');
          dashboard = await response.json();
          renderStats(dashboard.stats || {{}});
          renderTools(dashboard.agent_tools || []);
          renderResources(dashboard.resources || []);
          renderPrompts(dashboard.prompts || []);
          renderEvents(dashboard.events || []);
          renderApprovals(dashboard.pending_approvals || {{}});
          if (selected) {{
            selectTool(selected.name);
          }} else if ((dashboard.agent_tools || []).length) {{
            selectTool(dashboard.agent_tools[0].name);
          }}
        }}

        async function saveContract() {{
          if (!selected) return;
          const contract = JSON.parse(document.getElementById('editor').value || '{}');
          await fetch('/ui/api/permissions/upsert', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ ...selected, contract }}),
          }});
          await loadDashboard();
        }}

        async function requireApproval() {{
          if (!selected) return;
          const contract = JSON.parse(document.getElementById('editor').value || '{}');
          contract.approval_required = true;
          document.getElementById('editor').value = JSON.stringify(contract, null, 2);
          await saveContract();
        }}

        async function createDefaultContract() {{
          if (!selected) return;
          await fetch('/ui/api/permissions/default', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify(selected),
          }});
          await loadDashboard();
        }}

        async function sendPrompt() {{
          const prompt = (document.getElementById('chatPrompt').value || '').trim();
          if (!prompt) return;
          const response = await fetch('/ui/api/chat', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
              prompt,
              session_id: activeSessionId
            }}),
          }});
          currentRunResult = await response.json();
          activeSessionId = currentRunResult.session_id || activeSessionId;
          chatTurns.push({{ role: 'user', content: prompt }});
          chatTurns.push({{ role: 'assistant', content: currentRunResult.answer || '[No answer returned]' }});
          renderChatLog();
          document.getElementById('chatMeta').textContent = JSON.stringify(currentRunResult, null, 2);
          document.getElementById('runOutput').textContent = JSON.stringify(currentRunResult, null, 2);
          document.getElementById('chatPrompt').value = '';
          await loadDashboard();
        }}

        async function approveAndRun(token) {{
          const prompt = (document.getElementById('chatPrompt').value || '').trim() || 'Approve the pending tool action from the ASCP dashboard.';
          const response = await fetch('/ui/api/tools/approve-run', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
              approval_token: token,
              query: prompt,
              prompt_text: prompt,
              framework: 'ui',
              agent_id: 'developer_ui'
            }}),
          }});
          currentRunResult = await response.json();
          document.getElementById('runOutput').textContent = JSON.stringify(currentRunResult, null, 2);
          await loadDashboard();
        }}

        async function removeContract() {{
          if (!selected) return;
          await fetch('/ui/api/permissions/remove', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify(selected),
          }});
          await loadDashboard();
        }}

        renderChatLog();
        loadDashboard();
      </script>
    </body>
    </html>
    """.replace("__TITLE__", title).replace("{{", "{").replace("}}", "}")
    return HTMLResponse(html)


@app.post("/mcp/scan-output", tags=["mcp"])
async def scan_mcp_output(body: dict[str, Any]) -> dict[str, Any]:
    """
    Post-execution DLP and grounding scan on agent output.

    Called by adapters after agent produces a response to check for:
      - Secret/canary leaks (I3)
      - Instruction hierarchy violations (I4)
      - Hallucination risk
    """
    assert _mcp_proxy is not None

    content = body.get("content", "")
    correlation_id = body.get("correlation_id", str(uuid.uuid4()))

    return await _mcp_proxy.scan_output(content, correlation_id)
