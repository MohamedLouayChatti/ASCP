from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from apps.adapters.runtime_registry import register_runtime_tool
from layer_b import LayerBEngine

load_dotenv()


FILE_READ_SCHEMA = {
    "type": "object",
    "required": ["path"],
    "additionalProperties": False,
    "properties": {
        "path": {"type": "string"},
    },
}

PROJECT_LOOKUP_SCHEMA = {
    "type": "object",
    "required": ["topic"],
    "additionalProperties": False,
    "properties": {
        "topic": {"type": "string"},
    },
}


def file_read(path: str) -> dict[str, Any]:
    root = Path.cwd()
    target = (root / path).resolve(strict=False)
    content = target.read_text(encoding="utf-8")
    return {
        "path": str(target.relative_to(root)) if target.is_relative_to(root) else str(target),
        "content_preview": content[:800],
    }


def project_lookup(topic: str) -> dict[str, Any]:
    knowledge = {
        "layer b": [
            "Layer B validates capability, resource, and prompt access before execution.",
            "Unknown tools are guarded by baseline checks and approval modes.",
            "Recent work added audit logging and feedback suggestion generation.",
        ],
        "production": [
            "Production usage should keep local audit logging enabled.",
            "LangWatch is optional and should remain an observability sink, not the policy source of truth.",
        ],
    }
    normalized = topic.strip().lower()
    for key, bullets in knowledge.items():
        if key in normalized:
            return {"topic": topic, "results": bullets}
    return {
        "topic": topic,
        "results": [
            "No exact canned result matched the query.",
            "The demo intentionally keeps this tool unregistered to exercise Layer B approval flow.",
        ],
    }


TOOL_DEFS = [
    {
        "type": "function",
        "function": {
            "name": "file_read",
            "description": "Read a local project file and return a preview.",
            "parameters": FILE_READ_SCHEMA,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "project_lookup",
            "description": "Look up Layer B project notes from a small in-memory knowledge base.",
            "parameters": PROJECT_LOOKUP_SCHEMA,
        },
    },
]

TOOL_IMPLS = {
    "file_read": file_read,
    "project_lookup": project_lookup,
}

TOOL_SCHEMAS = {
    "file_read": FILE_READ_SCHEMA,
    "project_lookup": PROJECT_LOOKUP_SCHEMA,
}


def _register_tools() -> None:
    register_runtime_tool(
        "file_read",
        file_read,
        description="Read a local project file and return a preview.",
        framework="ollama",
        args_schema=FILE_READ_SCHEMA,
    )
    register_runtime_tool(
        "project_lookup",
        project_lookup,
        description="Look up Layer B project notes from a small in-memory knowledge base.",
        framework="ollama",
        args_schema=PROJECT_LOOKUP_SCHEMA,
    )


def _ollama_chat(
    *,
    base_url: str,
    api_key: str | None,
    model: str,
    messages: list[dict[str, Any]],
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    response = requests.post(
        f"{base_url.rstrip('/')}/api/chat",
        headers=headers,
        json={
            "model": model,
            "messages": messages,
            "tools": TOOL_DEFS,
            "stream": False,
        },
        timeout=120,
    )
    response.raise_for_status()
    return response.json()


def _execute_tool_call(
    engine: LayerBEngine,
    *,
    tool_name: str,
    tool_args: dict[str, Any],
    user_prompt: str,
    history: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    invocation_context = {
        "args_schema": TOOL_SCHEMAS.get(tool_name),
        "workflow": "demo_agent",
        "history": history,
        "user_intent": user_prompt,
    }
    decision = engine.explain_decision(
        tool_name,
        tool_args,
        invocation_context=invocation_context,
        framework="ollama",
        agent_id="layer-b-ollama-demo",
    )
    if str(decision["decision"]) == "require_approval":
        print(f"[approval] {tool_name} requires approval: {decision['details']}")
        decision = engine.explain_decision(
            tool_name,
            tool_args,
            approval_token=decision["approval_token"],
            invocation_context=invocation_context,
            framework="ollama",
            agent_id="layer-b-ollama-demo",
        )
        print(f"[approval] auto-approved demo run for {tool_name}")

    print(
        json.dumps(
            {
                "tool": tool_name,
                "args": tool_args,
                "layer_b": {
                    "decision": decision["decision"],
                    "reason_code": decision["reason_code"],
                    "details": decision["details"],
                },
            },
            indent=2,
            default=str,
        )
    )

    if str(decision["decision"]) != "allow":
        return {"blocked": True, "decision": decision}, decision

    raw_output = TOOL_IMPLS[tool_name](**tool_args)
    sanitized_output = engine.validator.sanitize_output(tool_name, raw_output)
    return sanitized_output, decision


def _run_agent_scenario(
    engine: LayerBEngine,
    *,
    base_url: str,
    api_key: str | None,
    model: str,
    user_prompt: str,
) -> dict[str, Any]:
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "You are a small demo agent. Always use one of the provided tools when the user asks "
                "about repository content or project knowledge. After tool use, answer concisely."
            ),
        },
        {"role": "user", "content": user_prompt},
    ]
    history: list[str] = []

    first_response = _ollama_chat(base_url=base_url, api_key=api_key, model=model, messages=messages)
    assistant_message = first_response.get("message", {})
    messages.append(assistant_message)

    tool_calls = assistant_message.get("tool_calls") or []
    if not tool_calls:
        return {
            "user_prompt": user_prompt,
            "assistant_reply": assistant_message.get("content", ""),
            "tool_results": [],
        }

    tool_results: list[dict[str, Any]] = []
    for tool_call in tool_calls:
        function_call = tool_call.get("function", {})
        tool_name = str(function_call.get("name", "")).strip()
        arguments = function_call.get("arguments", {})
        if not tool_name:
            continue
        tool_output, decision = _execute_tool_call(
            engine,
            tool_name=tool_name,
            tool_args=arguments if isinstance(arguments, dict) else {},
            user_prompt=user_prompt,
            history=history,
        )
        history.append(tool_name)
        tool_results.append(
            {
                "tool_name": tool_name,
                "decision": decision,
                "output": tool_output,
            }
        )
        messages.append(
            {
                "role": "tool",
                "name": tool_name,
                "content": json.dumps(tool_output, ensure_ascii=True),
            }
        )

    final_response = _ollama_chat(base_url=base_url, api_key=api_key, model=model, messages=messages)
    final_message = final_response.get("message", {})
    return {
        "user_prompt": user_prompt,
        "assistant_reply": final_message.get("content", ""),
        "tool_results": tool_results,
    }


def main() -> int:
    _register_tools()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    event_log_path = Path(os.getenv("ASCP_LAYER_B_EVENT_LOG") or f"data/layer_b_demo_events_{timestamp}.jsonl")
    os.environ["ASCP_LAYER_B_EVENT_LOG"] = str(event_log_path)
    os.environ.setdefault("LANGWATCH_PROJECT", "layer-b-sdk-demo")

    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    api_key = os.getenv("OLLAMA_API_KEY")
    model = os.getenv("OLLAMA_MODEL", "gpt-oss")

    engine = LayerBEngine(agent_id="layer-b-ollama-demo", framework="ollama")

    scenarios = [
        "Use the file_read tool to inspect README.md and summarize Layer B in one sentence.",
        "Use the project_lookup tool to tell me what still matters for productionizing Layer B.",
    ]

    print(f"Using Ollama model: {model}")
    print(f"Layer B event log: {event_log_path}")
    print("LangWatch enabled:" f" {bool(os.getenv('LANGWATCH_KEY') or os.getenv('LANGWATCH_API_KEY'))}")

    for prompt in scenarios:
        print("\n=== Scenario ===")
        print(prompt)
        try:
            result = _run_agent_scenario(
                engine,
                base_url=base_url,
                api_key=api_key,
                model=model,
                user_prompt=prompt,
            )
        except requests.RequestException as exc:
            print(f"Ollama request failed: {exc}")
            return 1

        print(json.dumps(result, indent=2, default=str))

    print("\n=== Recent Layer B Events ===")
    print(json.dumps(engine.recent_security_events(event_log_path=event_log_path), indent=2, default=str))

    print("\n=== Contract Candidates ===")
    print(json.dumps(engine.generate_contract_candidates(), indent=2, default=str))

    print("\n=== Feedback Suggestions ===")
    print(
        json.dumps(
            engine.generate_feedback_suggestions(
                event_log_path=event_log_path,
                min_occurrences=1,
            ),
            indent=2,
            default=str,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
