from __future__ import annotations

from typing import Any

from ascp_integration.adapters import ASCPAgentAdapter
from ascp_integration.orchestrator import ASCPOrchestrator


class ASCPSmolagentsAdapter(ASCPAgentAdapter):
    """smolagents adapter for prompts, tools, memory documents, and outputs."""

    framework = "smolagents"

    def __init__(
        self,
        orchestrator: ASCPOrchestrator,
        *,
        agent_id: str | None = None,
        workflow: str = "",
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(
            orchestrator,
            agent_id=agent_id,
            workflow=workflow,
            correlation_id=correlation_id,
        )

    async def prepare_run(
        self,
        task: str,
        *,
        system_prompt: str | None = None,
        documents: list[Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"task": await self.handle_user_input(task)}
        if system_prompt is not None:
            payload["system_prompt"] = await self.handle_system_prompt(system_prompt)
        if documents is not None:
            payload["documents"] = await self.handle_rag_documents(_documents_to_dicts(documents))
        return payload

    async def before_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        decision, sanitized_args = await self.validate_tool_call(tool_name, arguments)
        if decision.status == "BLOCK":
            raise PermissionError(decision.reason_code)
        return sanitized_args

    async def after_tool_call(self, tool_name: str, result: Any) -> str:
        return await self.handle_tool_result(tool_name, result)

    async def finalize_answer(self, answer: str) -> str:
        return await self.handle_agent_output(answer)


def _documents_to_dicts(documents: list[Any]) -> list[dict[str, str]]:
    converted: list[dict[str, str]] = []
    for index, doc in enumerate(documents):
        if isinstance(doc, dict):
            converted.append(
                {
                    "text": str(doc.get("text") or doc.get("content") or ""),
                    "source": str(doc.get("source") or f"smolagents_doc_{index}"),
                }
            )
        else:
            converted.append(
                {
                    "text": str(getattr(doc, "text", None) or getattr(doc, "content", None) or doc),
                    "source": str(getattr(doc, "source", None) or f"smolagents_doc_{index}"),
                }
            )
    return converted


__all__ = ["ASCPSmolagentsAdapter"]
