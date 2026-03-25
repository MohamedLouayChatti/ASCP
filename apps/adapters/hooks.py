"""
ASCP reasoning-loop hooks and supervisors.

This module wraps the full agent turn lifecycle instead of only validating
individual tool calls. It can be used with local validators/executors or with
the MCP proxy client for framework-agnostic supervision.
"""

from __future__ import annotations

import inspect
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from apps.mcp.client import ApprovalRequiredError, MCPProxyClient, ToolBlockedError
from apps.telemetry.events import EventType, SeverityLevel, TelemetryEvent

_SAFE_OUTPUT_FALLBACK = (
    "I cannot provide a response to this query due to a policy constraint. "
    "Please rephrase your question or contact support if you believe this is an error."
)

_CLARIFICATION_PROMPT = (
    "Please either call a tool using TOOL_CALL: {...} or provide FINAL_ANSWER: ..."
)

ToolValidator = Callable[[str, dict[str, Any], str], Awaitable["ToolValidationResult"]]
ToolExecutor = Callable[[str, dict[str, Any], str], Awaitable[Any]]
OutputGuard = Callable[[str, str], Awaitable["LoopOutputGuardResult"]]


class ToolDecisionType(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class ToolValidationResult:
    decision: ToolDecisionType
    reason_code: str
    details: str = ""
    approval_token: str | None = None
    violations: list[str] = field(default_factory=list)


@dataclass
class LoopOutputGuardResult:
    final_text: str
    blocked: bool
    block_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_result: Any | None = None


@dataclass
class LoopStep:
    step_index: int
    llm_output: str
    outcome: str
    tool_name: str | None = None
    tool_args: dict[str, Any] = field(default_factory=dict)
    tool_result: str | None = None
    final_answer: str | None = None
    block_reason: str | None = None


@dataclass
class LoopRunResult:
    answer: str
    events: list[TelemetryEvent]
    messages: list[dict[str, str]]
    steps: list[LoopStep]
    output_guard_result: LoopOutputGuardResult | None = None


class ASCPMemoryHook:
    """Captures message snapshots before each model turn."""

    def __init__(self) -> None:
        self.snapshots: list[dict[str, Any]] = []

    async def on_before_llm(
        self,
        *,
        step_index: int,
        messages: list[dict[str, str]],
        correlation_id: str,
    ) -> None:
        self.snapshots.append(
            {
                "step_index": step_index,
                "correlation_id": correlation_id,
                "messages": [dict(message) for message in messages],
            }
        )


class ASCPPlannerHook:
    """Captures model outputs and tool decisions for planner observability."""

    def __init__(self) -> None:
        self.decisions: list[dict[str, Any]] = []

    async def on_after_llm(
        self,
        *,
        step_index: int,
        llm_output: str,
        correlation_id: str,
        **_: Any,
    ) -> None:
        self.decisions.append(
            {
                "step_index": step_index,
                "correlation_id": correlation_id,
                "llm_output": llm_output,
            }
        )

    async def on_tool_validation(
        self,
        *,
        step_index: int,
        tool_name: str,
        tool_args: dict[str, Any],
        validation: ToolValidationResult,
        **_: Any,
    ) -> None:
        self.decisions.append(
            {
                "step_index": step_index,
                "tool_name": tool_name,
                "tool_args": dict(tool_args),
                "decision": validation.decision.value,
                "reason_code": validation.reason_code,
            }
        )


class ASCPReasoningLoop:
    """
    Supervises the full agent reasoning loop.

    Each turn is wrapped at five boundaries:
      1. Before the model call
      2. After the model call
      3. Before tool execution (validation)
      4. After tool execution
      5. Before the final answer is released
    """

    def __init__(
        self,
        *,
        tool_validator: ToolValidator,
        tool_executor: ToolExecutor,
        output_guard: OutputGuard | None = None,
        hooks: list[Any] | None = None,
    ) -> None:
        self.tool_validator = tool_validator
        self.tool_executor = tool_executor
        self.output_guard = output_guard
        self.hooks = hooks or []

    @classmethod
    def with_mcp_proxy(
        cls,
        proxy_client: MCPProxyClient,
        *,
        tool_executor: ToolExecutor | None = None,
        agent_id: str = "unknown",
        framework: str = "custom",
        hooks: list[Any] | None = None,
    ) -> ASCPReasoningLoop:
        cached_results: dict[str, Any] = {}

        def _cache_key(
            tool_name: str,
            arguments: dict[str, Any],
            correlation_id: str,
        ) -> str:
            return json.dumps(
                {
                    "correlation_id": correlation_id,
                    "tool_name": tool_name,
                    "arguments": arguments,
                },
                sort_keys=True,
                default=str,
            )

        async def validate_with_proxy(
            tool_name: str,
            arguments: dict[str, Any],
            correlation_id: str,
        ) -> ToolValidationResult:
            try:
                result = await proxy_client.call_tool(
                    tool_name=tool_name,
                    arguments=arguments,
                    agent_id=agent_id,
                    framework=framework,
                )
                cached_results[_cache_key(tool_name, arguments, correlation_id)] = result
            except ApprovalRequiredError as exc:
                return ToolValidationResult(
                    decision=ToolDecisionType.REQUIRE_APPROVAL,
                    reason_code="APPROVAL_REQUIRED",
                    details=exc.details,
                    approval_token=exc.approval_token,
                )
            except ToolBlockedError as exc:
                return ToolValidationResult(
                    decision=ToolDecisionType.BLOCK,
                    reason_code=exc.reason,
                    details=exc.details,
                    violations=["I1" if exc.reason == "TOOL_NOT_REGISTERED" else "I2"],
                )

            return ToolValidationResult(
                decision=ToolDecisionType.ALLOW,
                reason_code="ALLOWED",
            )

        async def execute_with_proxy(
            tool_name: str,
            arguments: dict[str, Any],
            correlation_id: str,
        ) -> Any:
            key = _cache_key(tool_name, arguments, correlation_id)
            if key in cached_results:
                return cached_results.pop(key)
            return await proxy_client.call_tool(
                tool_name=tool_name,
                arguments=arguments,
                agent_id=agent_id,
                framework=framework,
            )

        async def guard_with_proxy(answer: str, correlation_id: str) -> LoopOutputGuardResult:
            result = await proxy_client.scan_output(answer, correlation_id)
            if result.get("blocked"):
                return LoopOutputGuardResult(
                    final_text=_SAFE_OUTPUT_FALLBACK,
                    blocked=True,
                    block_reason=result.get("reason", "OUTPUT_BLOCKED"),
                    metadata=result,
                    raw_result=result,
                )
            return LoopOutputGuardResult(
                final_text=result.get("clean_text", answer),
                blocked=False,
                metadata=result,
                raw_result=result,
            )

        return cls(
            tool_validator=validate_with_proxy,
            tool_executor=execute_with_proxy,
            output_guard=guard_with_proxy,
            hooks=hooks,
        )

    async def run(
        self,
        *,
        initial_messages: list[dict[str, str]],
        llm_callable: Callable[[list[dict[str, str]]], Awaitable[str]],
        correlation_id: str,
        max_steps: int = 5,
    ) -> LoopRunResult:
        messages = [dict(message) for message in initial_messages]
        events: list[TelemetryEvent] = []
        steps: list[LoopStep] = []

        for step_index in range(1, max_steps + 1):
            await self._call_hooks(
                "on_before_llm",
                step_index=step_index,
                messages=messages,
                correlation_id=correlation_id,
            )
            llm_output = await llm_callable(messages)
            messages.append({"role": "assistant", "content": llm_output})

            await self._call_hooks(
                "on_after_llm",
                step_index=step_index,
                messages=messages,
                llm_output=llm_output,
                correlation_id=correlation_id,
            )

            final_answer = _parse_final_answer(llm_output)
            if final_answer is not None:
                output_guard_result = await self._guard_output(final_answer, correlation_id)
                await self._call_hooks(
                    "on_final_answer",
                    step_index=step_index,
                    answer=output_guard_result.final_text,
                    blocked=output_guard_result.blocked,
                    block_reason=output_guard_result.block_reason,
                    correlation_id=correlation_id,
                )
                steps.append(
                    LoopStep(
                        step_index=step_index,
                        llm_output=llm_output,
                        outcome="final_answer",
                        final_answer=output_guard_result.final_text,
                        block_reason=output_guard_result.block_reason,
                    )
                )
                return LoopRunResult(
                    answer=output_guard_result.final_text,
                    events=events,
                    messages=messages,
                    steps=steps,
                    output_guard_result=output_guard_result,
                )

            parsed = _parse_tool_call(llm_output)
            if not parsed:
                messages.append({"role": "user", "content": _CLARIFICATION_PROMPT})
                steps.append(
                    LoopStep(
                        step_index=step_index,
                        llm_output=llm_output,
                        outcome="clarification_requested",
                    )
                )
                continue

            tool_name, tool_args = parsed
            validation = await self.tool_validator(tool_name, tool_args, correlation_id)
            await self._call_hooks(
                "on_tool_validation",
                step_index=step_index,
                tool_name=tool_name,
                tool_args=tool_args,
                validation=validation,
                correlation_id=correlation_id,
            )

            events.append(
                TelemetryEvent(
                    correlation_id=correlation_id,
                    event_type=EventType.TOOL_CALL_ATTEMPT,
                    tool_name=tool_name,
                    reason_code=validation.reason_code,
                    details={
                        "decision": validation.decision.value,
                        "args_keys": list(tool_args.keys()),
                        "violations": validation.violations,
                    },
                    invariant_violated=validation.violations[0]
                    if validation.violations
                    else None,
                    severity=SeverityLevel.CRITICAL
                    if validation.violations
                    else SeverityLevel.INFO,
                )
            )

            if validation.decision == ToolDecisionType.BLOCK:
                tool_result_text = (
                    f"[BLOCKED] Tool '{tool_name}' was blocked: {validation.reason_code}. "
                    f"{validation.details}"
                )
                events.append(
                    TelemetryEvent(
                        correlation_id=correlation_id,
                        event_type=EventType.POLICY_BLOCK,
                        tool_name=tool_name,
                        reason_code=validation.reason_code,
                        severity=SeverityLevel.CRITICAL,
                        invariant_violated=validation.violations[0]
                        if validation.violations
                        else "I1",
                        details={"details": validation.details},
                    )
                )
                outcome = "tool_blocked"
            elif validation.decision == ToolDecisionType.REQUIRE_APPROVAL:
                tool_result_text = (
                    f"[APPROVAL REQUIRED] Tool '{tool_name}' requires human approval. "
                    f"Approval token: {validation.approval_token}. The tool was not executed."
                )
                events.append(
                    TelemetryEvent(
                        correlation_id=correlation_id,
                        event_type=EventType.APPROVAL_REQUIRED,
                        tool_name=tool_name,
                        reason_code="APPROVAL_REQUIRED",
                        details={"approval_token": validation.approval_token},
                    )
                )
                outcome = "tool_requires_approval"
            else:
                try:
                    raw_tool_result = await self.tool_executor(tool_name, tool_args, correlation_id)
                    tool_result_text = _stringify_result(raw_tool_result)
                    events.append(
                        TelemetryEvent(
                            correlation_id=correlation_id,
                            event_type=EventType.TOOL_CALL_RESULT,
                            tool_name=tool_name,
                            reason_code="SUCCESS",
                            details={"result_len": len(tool_result_text)},
                        )
                    )
                    outcome = "tool_executed"
                except Exception as exc:
                    tool_result_text = f"[ERROR] Tool '{tool_name}' raised an error: {exc}"
                    events.append(
                        TelemetryEvent(
                            correlation_id=correlation_id,
                            event_type=EventType.TOOL_CALL_RESULT,
                            tool_name=tool_name,
                            reason_code="EXECUTION_ERROR",
                            severity=SeverityLevel.WARN,
                            details={"error": str(exc)},
                        )
                    )
                    outcome = "tool_execution_error"

            await self._call_hooks(
                "on_tool_result",
                step_index=step_index,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_result=tool_result_text,
                correlation_id=correlation_id,
            )

            messages.append(
                {
                    "role": "user",
                    "content": f"Tool result for {tool_name}:\n{tool_result_text}",
                }
            )
            steps.append(
                LoopStep(
                    step_index=step_index,
                    llm_output=llm_output,
                    outcome=outcome,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    tool_result=tool_result_text,
                )
            )

        answer = "I was unable to complete the task within the allowed number of steps."
        output_guard_result = await self._guard_output(answer, correlation_id)
        steps.append(
            LoopStep(
                step_index=max_steps,
                llm_output="",
                outcome="max_steps",
                final_answer=output_guard_result.final_text,
                block_reason=output_guard_result.block_reason,
            )
        )
        return LoopRunResult(
            answer=output_guard_result.final_text,
            events=events,
            messages=messages,
            steps=steps,
            output_guard_result=output_guard_result,
        )

    async def _guard_output(self, answer: str, correlation_id: str) -> LoopOutputGuardResult:
        if self.output_guard is None:
            return LoopOutputGuardResult(final_text=answer, blocked=False)
        return await self.output_guard(answer, correlation_id)

    async def _call_hooks(self, hook_name: str, **payload: Any) -> None:
        for hook in self.hooks:
            callback = getattr(hook, hook_name, None)
            if callback is None:
                continue
            result = callback(**payload)
            if inspect.isawaitable(result):
                await result


def _stringify_result(result: Any) -> str:
    if isinstance(result, str):
        return result
    return json.dumps(result)


def _parse_tool_call(text: str) -> tuple[str, dict[str, Any]] | None:
    match = re.search(r"TOOL_CALL:\s*(\{.*\})", text, re.DOTALL)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    tool_name = parsed.get("tool")
    tool_args = parsed.get("args", {})
    if not isinstance(tool_name, str) or not isinstance(tool_args, dict):
        return None
    return tool_name, tool_args


def _parse_final_answer(text: str) -> str | None:
    match = re.search(r"FINAL_ANSWER:\s*(.+)", text, re.DOTALL)
    return match.group(1).strip() if match else None
