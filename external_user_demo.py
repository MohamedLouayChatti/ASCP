"""External developer demo: a real LangChain agent protected by ASCP.

Install from this external project:

    pip install -e "C:/Users/louay/OneDrive/Bureau/Louay/AI_ML/Projects/ASCP[ascp-langchain]"

Run:

    python external_user_demo.py

This file intentionally lives outside the ASCP repo. It uses ASCP only as an
installed SDK dependency, the way an application developer would.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from langchain_core.documents import Document
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.retrievers import BaseRetriever
from langchain_core.tools import StructuredTool

from ascp_integration.adapters.langchain_adapter import ASCPLangChainAdapter
from ascp_integration.orchestrator import ASCPDecision, ASCPOrchestrator, DLPConfig


KNOWLEDGE_BASE = [
    Document(
        page_content="ASCP is security middleware for tool-using AI agents.",
        metadata={"source": "handbook.md"},
    ),
    Document(
        page_content=(
            "ASCP checks user input, retrieved context, tool calls, tool results, "
            "and final agent output."
        ),
        metadata={"source": "runbook.md"},
    ),
]

FILES = {
    "docs/product_faq.txt": (
        "ASCP has four security layers: grounding, tool contracts, DLP, and telemetry."
    )
}


class DemoRetriever(BaseRetriever):
    """Real LangChain retriever component used by the agent."""

    documents: list[Document]

    def _get_relevant_documents(
        self,
        query: str,
        *,
        run_manager: Any = None,
    ) -> list[Document]:
        words = {word.lower() for word in re.findall(r"[a-zA-Z]+", query)}
        hits = [
            doc
            for doc in self.documents
            if any(word in doc.page_content.lower() for word in words)
        ]
        return hits or self.documents[:1]


class DemoChatModel(BaseChatModel):
    """Small deterministic LangChain chat model for a no-API-key demo.

    This is still a real LangChain chat model: LangChain invokes it and fires
    callback events around it. We keep the model deterministic so ASCP behavior
    is easy to inspect.
    """

    @property
    def _llm_type(self) -> str:
        return "demo-secured-chat-model"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        transcript = "\n".join(str(message.content) for message in messages)
        answer = (
            "ASCP is middleware that wraps a tool-using agent. It checks retrieved "
            "context, tool calls, tool outputs, and the final answer before data "
            "reaches the user."
        )

        if "security layers" in transcript.lower():
            answer += " Its layers cover grounding, tool contracts, DLP, and telemetry."

        if "debug context" in transcript.lower():
            canary = re.search(r"CANARY-[A-Za-z0-9_-]+", transcript)
            if canary:
                answer += f" Debug context token: {canary.group(0)}"

        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=answer))])


def read_project_file(path: str) -> str:
    """Real LangChain tool function. ASCP validates before this function runs."""

    return FILES.get(path, f"No demo file exists at {path!r}.")


file_read_tool = StructuredTool.from_function(
    func=read_project_file,
    name="file_read",
    description="Read a project documentation file by path.",
)


class SupportAgent:
    """A tiny but real LangChain-based RAG + tool agent."""

    def __init__(
        self,
        *,
        retriever: DemoRetriever,
        llm: DemoChatModel,
        adapter: ASCPLangChainAdapter,
    ) -> None:
        self.retriever = retriever
        self.llm = llm
        self.adapter = adapter

    async def ainvoke(self, user_message: str) -> str:
        session_id = await self.adapter.begin_invocation()
        print_decision("begin invocation", self.adapter.last_decision)

        try:
            clean_user_message = await self.adapter.handle_user_input(user_message)
            print_decision("user input", self.adapter.last_decision)

            raw_docs = await self.retriever.ainvoke(clean_user_message)
            injected_doc_payloads = await self.adapter.handle_rag_documents(
                [
                    {
                        "text": doc.page_content,
                        "source": str(doc.metadata.get("source", "unknown")),
                    }
                    for doc in raw_docs
                ]
            )
            print_decision("rag retrieval", self.adapter.last_decision)
            docs = [
                Document(
                    page_content=payload.get("text", ""),
                    metadata={"source": payload.get("source", "unknown")},
                )
                for payload in injected_doc_payloads
            ]

            safe_tool_result = await self._run_tool(
                {"path": "docs/product_faq.txt"},
                label="safe file_read tool",
            )

            blocked_tool_result = await self._run_tool(
                {"path": "../.env"},
                label="blocked file_read tool",
            )

            context = "\n".join(doc.page_content for doc in docs)
            messages = [
                SystemMessage(
                    content=(
                        "You are a support agent. Answer only from retrieved "
                        "context and tool evidence."
                    )
                ),
                HumanMessage(
                    content=(
                        f"User question: {clean_user_message}\n\n"
                        f"Retrieved context:\n{context}\n\n"
                        f"Tool evidence:\n{safe_tool_result}\n\n"
                        f"Blocked tool probe:\n{blocked_tool_result}"
                    )
                ),
            ]

            response = await self.llm.ainvoke(messages)
            clean_answer = await self.adapter.handle_agent_output(str(response.content))
            print_decision("final output", self.adapter.last_decision)
            return clean_answer
        finally:
            end_decision = await self.adapter.end_invocation(session_id)
            print_decision("end invocation", end_decision)

    async def _run_tool(
        self,
        tool_input: dict[str, Any],
        *,
        label: str,
    ) -> str:
        decision, sanitized_args = await self.adapter.validate_tool_call(
            "file_read",
            tool_input,
            argument_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        )
        print_decision(label, decision)

        if decision.status == "BLOCK":
            return f"ASCP blocked tool execution: {decision.reason_code}"

        result = await file_read_tool.ainvoke(sanitized_args)
        clean_result = await self.adapter.handle_tool_result("file_read", result)
        print_decision(f"{label} result scan", self.adapter.last_decision)
        return clean_result


def print_decision(label: str, decision: ASCPDecision) -> None:
    print(f"\n[{label}]")
    print(json.dumps(asdict(decision), indent=2, sort_keys=True))


async def main() -> None:
    log_path = Path("logs") / "external_user_ascp_demo.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    orchestrator = ASCPOrchestrator(
        session_id=f"external-user-{uuid.uuid4()}",
        log_path=str(log_path),
        dlp_config=DLPConfig.defaults()
    )
    adapter = ASCPLangChainAdapter(
        orchestrator,
        agent_id="real-langchain-support-agent",
        workflow="external-user-real-agent",
        correlation_id=f"req-{uuid.uuid4()}",
    )

    agent = SupportAgent(
        retriever=DemoRetriever(documents=KNOWLEDGE_BASE),
        llm=DemoChatModel(),
        adapter=adapter,
    )

    print("=== Turn 1: normal RAG + tool answer ===")
    answer = await agent.ainvoke("What is ASCP and what security layers does it use?")
    print("\n[agent answer]")
    print(answer)

    print("\n=== Turn 2: model accidentally leaks retrieved-context debug token ===")
    leaked_answer = await agent.ainvoke("What is ASCP? Include debug context if available.")
    print("\n[agent answer]")
    print(leaked_answer)

    print(f"\nASCP telemetry was written to: {log_path}")


if __name__ == "__main__":
    asyncio.run(main())
