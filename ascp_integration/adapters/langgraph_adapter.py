from __future__ import annotations

import json
import uuid
from typing import Any

try:
    from langchain_core.callbacks import AsyncCallbackHandler
except ImportError:  # pragma: no cover - optional SDK dependency
    class AsyncCallbackHandler:  # type: ignore[no-redef]
        pass

from ascp_integration.adapters import ASCPAgentAdapter
from ascp_integration.orchestrator import ASCPOrchestrator


class ASCPLangGraphAdapter(ASCPAgentAdapter, AsyncCallbackHandler):
    """LangChain/LangGraph callback adapter.

    Use this as a callback handler for LangChain/LangGraph runs and call the
    explicit `handle_*` methods when your graph owns a lifecycle event directly.
    """

    framework = "langgraph"

    def __init__(
        self,
        orchestrator: ASCPOrchestrator,
        *,
        agent_id: str | None = None,
        workflow: str = "",
        correlation_id: str | None = None,
    ) -> None:
        ASCPAgentAdapter.__init__(
            self,
            orchestrator,
            agent_id=agent_id,
            workflow=workflow,
            correlation_id=correlation_id,
        )
        AsyncCallbackHandler.__init__(self)

    async def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Inspect system prompts and human inputs when LangChain exposes messages."""

        for message_batch in messages:
            for message in message_batch:
                content = getattr(message, "content", "")
                message_type = getattr(message, "type", "")
                if message_type == "system" and content:
                    message.content = await self.handle_system_prompt(str(content), run_id=str(run_id))
                elif message_type == "human" and content:
                    message.content = await self.handle_user_input(str(content), run_id=str(run_id))

    async def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Fallback for non-chat LLM prompt strings."""

        for index, prompt in enumerate(prompts):
            prompts[index] = await self.handle_system_prompt(prompt, run_id=str(run_id))

    async def on_retriever_end(
        self,
        documents: list[Any],
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        doc_dicts = [
            {
                "text": getattr(doc, "page_content", str(doc)),
                "source": getattr(doc, "metadata", {}).get("source", "unknown")
                if isinstance(getattr(doc, "metadata", {}), dict)
                else "unknown",
            }
            for doc in documents
        ]
        injected_docs = await self.handle_rag_documents(doc_dicts, run_id=str(run_id))
        for index, injected in enumerate(injected_docs):
            if index < len(documents) and hasattr(documents[index], "page_content"):
                documents[index].page_content = injected.get("text", "")

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name") or serialized.get("id") or "unknown"
        arguments = _tool_inputs(input_str, kwargs.get("inputs"))
        decision, _sanitized_args = await self.validate_tool_call(
            tool_name,
            arguments,
            run_id=str(run_id),
            argument_schema=serialized.get("args_schema") or serialized.get("schema"),
        )
        if decision.status == "BLOCK":
            raise PermissionError(decision.reason_code)

    async def on_tool_end(
        self,
        output: Any,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = kwargs.get("name") or kwargs.get("tool_name") or "unknown"
        await self.handle_tool_result(tool_name, output, run_id=str(run_id))

    async def on_llm_end(
        self,
        response: Any,
        *,
        run_id: uuid.UUID,
        parent_run_id: uuid.UUID | None = None,
        **kwargs: Any,
    ) -> None:
        generation = _first_generation(response)
        if generation is None:
            return
        text = getattr(generation, "text", "") or getattr(generation, "message", None)
        if not isinstance(text, str) and hasattr(text, "content"):
            text = text.content
        if not text:
            return

        clean_text = await self.handle_agent_output(str(text), run_id=str(run_id))
        if hasattr(generation, "text"):
            generation.text = clean_text
        elif hasattr(generation, "message") and hasattr(generation.message, "content"):
            generation.message.content = clean_text


class ASCPLangChainAdapter(ASCPLangGraphAdapter):
    """LangChain alias with a distinct framework label for telemetry/policy."""

    framework = "langchain"


def _tool_inputs(input_str: str, inputs: Any) -> dict[str, Any]:
    if isinstance(inputs, dict):
        return inputs
    if input_str:
        try:
            parsed = json.loads(input_str)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {"input": input_str}
    return {}


def _first_generation(response: Any) -> Any | None:
    try:
        return response.generations[0][0]
    except (AttributeError, IndexError, TypeError):
        return None


__all__ = ["ASCPLangGraphAdapter", "ASCPLangChainAdapter"]
