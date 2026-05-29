"""Minimal ASCP consumer app with RAG, tools, and visible decisions.

Run from the repository root:

    python examples/external_user_langchain_style_agent.py

This intentionally behaves like code a downstream developer would write. It
does not import private layer modules, and it never calls Layer A/B/C/D directly.
The app only talks to ASCP through ASCPOrchestrator and ASCPLangChainAdapter.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ascp_integration.adapters.langchain_adapter import ASCPLangChainAdapter
from ascp_integration.orchestrator import ASCPDecision, ASCPOrchestrator


KNOWLEDGE_BASE = [
    {
        "source": "handbook.md",
        "text": "ASCP is security middleware for tool-using AI agents.",
    },
    {
        "source": "runbook.md",
        "text": "Agents should call ASCP before tool execution and before final output.",
    },
]


FILES = {
    "docs/product_faq.txt": (
        "ASCP has four security layers: grounding, tool contracts, DLP, and telemetry."
    )
}


def retrieve_documents(question: str) -> list[dict[str, str]]:
    """Tiny local RAG retriever. Real apps would call a vector store here."""

    words = {word.lower() for word in re.findall(r"[a-zA-Z]+", question)}
    hits = [
        doc
        for doc in KNOWLEDGE_BASE
        if any(word in doc["text"].lower() for word in words)
    ]
    return hits or KNOWLEDGE_BASE[:1]


def file_read(path: str) -> str:
    """Tiny local tool. ASCP validates before this function is called."""

    return FILES.get(path, f"No local demo file exists at {path!r}.")


def render_decision(label: str, decision: ASCPDecision) -> None:
    payload = asdict(decision)
    print(f"\n[{label}]")
    print(json.dumps(payload, indent=2, sort_keys=True))


async def guarded_file_read(
    adapter: ASCPLangChainAdapter,
    path: str,
    *,
    label: str,
) -> str:
    decision, sanitized_args = await adapter.validate_tool_call(
        "file_read",
        {"path": path},
        argument_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    )
    render_decision(label, decision)

    if decision.status == "BLOCK":
        return f"ASCP blocked file_read: {decision.reason_code}"

    raw_result = file_read(str(sanitized_args["path"]))
    clean_result = await adapter.handle_tool_result("file_read", raw_result)
    render_decision(f"{label}: result scan", adapter.last_decision)
    return clean_result


async def run_agent_turn(
    adapter: ASCPLangChainAdapter,
    user_message: str,
    *,
    leak_context_canary: bool = False,
) -> str:
    session_id = await adapter.begin_invocation()
    render_decision("begin invocation", adapter.last_decision)

    try:
        clean_user_message = await adapter.handle_user_input(user_message)
        render_decision("user input", adapter.last_decision)

        raw_docs = retrieve_documents(clean_user_message)
        injected_docs = await adapter.handle_rag_documents(raw_docs)
        render_decision("rag retrieval", adapter.last_decision)

        safe_tool_result = await guarded_file_read(
            adapter,
            "docs/product_faq.txt",
            label="safe tool call",
        )
        blocked_tool_result = await guarded_file_read(
            adapter,
            "../.env",
            label="blocked tool call",
        )

        context_text = "\n".join(doc["text"] for doc in injected_docs)
        answer = (
            "ASCP wraps a tool-using agent and checks user input, retrieved context, "
            "tool calls, tool results, and final output. "
            f"Tool evidence: {safe_tool_result} "
            f"Blocked probe: {blocked_tool_result}"
        )

        if leak_context_canary:
            canary_match = re.search(r"CANARY-[A-Za-z0-9_-]+", context_text)
            if canary_match:
                answer += f" Debug context token: {canary_match.group(0)}"

        clean_answer = await adapter.handle_agent_output(answer)
        render_decision("final output", adapter.last_decision)
        return clean_answer
    finally:
        end_decision = await adapter.end_invocation(session_id)
        render_decision("end invocation", end_decision)


async def main() -> None:
    log_path = Path("logs") / "external_user_ascp_demo.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    orchestrator = ASCPOrchestrator(
        session_id=f"external-user-{uuid.uuid4()}",
        log_path=str(log_path),
    )
    adapter = ASCPLangChainAdapter(
        orchestrator,
        agent_id="external-user-demo-agent",
        workflow="external-user-smoke-test",
        correlation_id=f"req-{uuid.uuid4()}",
    )

    print("=== Turn 1: normal answer with one safe tool and one blocked tool ===")
    answer = await run_agent_turn(
        adapter,
        "What is ASCP and what security layers does it use?",
    )
    print("\n[agent answer]")
    print(answer)

    print("\n=== Turn 2: agent accidentally leaks RAG canary ===")
    leaked_answer = await run_agent_turn(
        adapter,
        "What is ASCP? Include debug context if available.",
        leak_context_canary=True,
    )
    print("\n[agent answer]")
    print(leaked_answer)

    print(f"\nASCP telemetry was written to: {log_path}")


if __name__ == "__main__":
    asyncio.run(main())