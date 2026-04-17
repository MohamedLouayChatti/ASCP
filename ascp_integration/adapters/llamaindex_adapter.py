from __future__ import annotations

from typing import Any

from ascp_integration.adapters import ASCPAgentAdapter
from ascp_integration.orchestrator import ASCPOrchestrator


class ASCPLlamaIndexAdapter(ASCPAgentAdapter):
    """LlamaIndex adapter for query engines, retrievers, and agent workflows."""

    framework = "llamaindex"

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

    async def prepare_query(
        self,
        query: str,
        *,
        system_prompt: str | None = None,
    ) -> dict[str, str]:
        payload = {"query": await self.handle_user_input(query)}
        if system_prompt is not None:
            payload["system_prompt"] = await self.handle_system_prompt(system_prompt)
        return payload

    async def on_retrieval(self, nodes: list[Any]) -> list[Any]:
        docs = [_node_to_doc(node, index) for index, node in enumerate(nodes)]
        injected_docs = await self.handle_rag_documents(docs)
        for index, injected in enumerate(injected_docs):
            if index < len(nodes):
                _set_node_text(nodes[index], injected.get("text", ""))
        return nodes

    async def before_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        decision, sanitized_args = await self.validate_tool_call(tool_name, arguments)
        if decision.status == "BLOCK":
            raise PermissionError(decision.reason_code)
        return sanitized_args

    async def after_tool_call(self, tool_name: str, result: Any) -> str:
        return await self.handle_tool_result(tool_name, result)

    async def finalize_response(self, response: Any) -> Any:
        text = getattr(response, "response", None) or str(response)
        clean_text = await self.handle_agent_output(str(text))
        if hasattr(response, "response"):
            response.response = clean_text
            return response
        return clean_text


def _node_to_doc(node: Any, index: int) -> dict[str, str]:
    actual_node = getattr(node, "node", node)
    metadata = getattr(actual_node, "metadata", {}) or {}
    if not isinstance(metadata, dict):
        metadata = {}
    text = ""
    if hasattr(actual_node, "get_content"):
        text = actual_node.get_content()
    else:
        text = getattr(actual_node, "text", None) or getattr(actual_node, "content", None) or str(actual_node)
    return {
        "text": str(text),
        "source": str(metadata.get("source") or getattr(actual_node, "id_", None) or f"llamaindex_node_{index}"),
    }


def _set_node_text(node: Any, text: str) -> None:
    actual_node = getattr(node, "node", node)
    if hasattr(actual_node, "text"):
        actual_node.text = text
    elif hasattr(actual_node, "set_content"):
        actual_node.set_content(text)


__all__ = ["ASCPLlamaIndexAdapter"]
