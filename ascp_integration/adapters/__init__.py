from __future__ import annotations

import json
import uuid
from typing import Any

from ascp_integration.orchestrator import ASCPDecision, ASCPOrchestrator


class ASCPAgentAdapter:
    """Base SDK adapter for agent-framework integrations.

    Framework adapters should translate their native callbacks/events into this
    lifecycle:

    system prompt -> user input -> RAG docs/resources -> tool call/result -> output
    """

    framework: str = "custom"

    def __init__(
        self,
        orchestrator: ASCPOrchestrator,
        *,
        agent_id: str | None = None,
        workflow: str = "",
        correlation_id: str | None = None,
    ) -> None:
        self.orchestrator = orchestrator
        self.agent_id = agent_id or f"{self.framework}-agent"
        self.workflow = workflow
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.current_sys_prompt = ""
        self.current_user_input = ""
        self.current_rag_contexts: list[str] = []
        self.last_decision = ASCPDecision()

    def invocation_context(self, **extra: Any) -> dict[str, Any]:
        context = {
            "agent_id": self.agent_id,
            "framework": self.framework,
            "workflow": self.workflow,
        }
        context.update({key: value for key, value in extra.items() if value is not None})
        return context

    async def begin_invocation(self, **extra: Any) -> str:
        session_id, decision = await self.orchestrator.begin_invocation(
            self.correlation_id,
            self.invocation_context(**extra),
        )
        self.last_decision = decision
        return session_id

    async def end_invocation(self, session_id: str) -> ASCPDecision:
        decision = await self.orchestrator.end_invocation(self.correlation_id, session_id)
        self.last_decision = decision
        return decision

    async def handle_system_prompt(self, raw_prompt: str, **extra: Any) -> str:
        prompt, decision = await self.orchestrator.hook_system_prompt(
            self.correlation_id,
            raw_prompt,
            self.invocation_context(**extra),
        )
        self.current_sys_prompt = prompt
        self.last_decision = decision
        return prompt

    async def handle_user_input(self, user_input: str, **extra: Any) -> str:
        text, decision = await self.orchestrator.hook_user_input(
            self.correlation_id,
            user_input,
            self.invocation_context(**extra),
        )
        self.current_user_input = text
        self.last_decision = decision
        return text

    async def handle_rag_documents(
        self,
        documents: list[dict[str, str]],
        **extra: Any,
    ) -> list[dict[str, str]]:
        docs, _token, decision = await self.orchestrator.hook_rag_retrieval(
            self.correlation_id,
            documents,
            self.invocation_context(**extra),
        )
        self.current_rag_contexts = [doc.get("text", "") for doc in docs]
        self.last_decision = decision
        return docs

    async def validate_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        approval_token: str | None = None,
        **extra: Any,
    ) -> tuple[ASCPDecision, dict[str, Any]]:
        decision, sanitized_args = await self.orchestrator.hook_tool_call(
            self.correlation_id,
            tool_name,
            arguments,
            approval_token=approval_token,
            context=self.invocation_context(**extra),
        )
        self.last_decision = decision
        return decision, sanitized_args

    async def handle_tool_result(self, tool_name: str, result: Any, **extra: Any) -> str:
        result_payload = json.dumps(result, default=str) if isinstance(result, (dict, list)) else str(result)
        sanitized, decision = await self.orchestrator.hook_tool_result(
            self.correlation_id,
            tool_name,
            result_payload,
            self.invocation_context(**extra),
        )
        self.last_decision = decision
        return sanitized

    async def handle_agent_output(self, generated_text: str, **extra: Any) -> str:
        clean_text, decision = await self.orchestrator.hook_agent_output(
            self.correlation_id,
            generated_text,
            self.current_rag_contexts,
            self.invocation_context(**extra),
        )
        self.last_decision = decision
        return clean_text

    # Compatibility aliases used by the first adapter version.
    async def inject_system_prompt_hook(self, raw_prompt: str) -> str:
        return await self.handle_system_prompt(raw_prompt)

    async def on_user_input(self, user_input: str) -> str:
        return await self.handle_user_input(user_input)

    async def on_rag_retrieve(self, documents: list[dict[str, str]]) -> list[dict[str, str]]:
        return await self.handle_rag_documents(documents)

    async def on_tool_start(self, tool_name: str, arguments: dict[str, Any]) -> None:
        decision, _sanitized_args = await self.validate_tool_call(tool_name, arguments)
        if decision.status == "BLOCK":
            raise PermissionError(decision.reason_code)

    async def on_tool_result(self, tool_name: str, result: Any) -> str:
        return await self.handle_tool_result(tool_name, result)

    async def on_llm_end(self, generated_text: str) -> str:
        return await self.handle_agent_output(generated_text)


__all__ = ["ASCPAgentAdapter"]
