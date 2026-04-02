from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from layerb import LayerBEngine, register_runtime_tool


CUSTOM_POLICY_PATH = Path("examples") / "layer_b_custom_policy.yaml"

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
        "content_preview": content[:160],
    }


def project_lookup(topic: str) -> dict[str, Any]:
    knowledge = {
        "production": [
            "Keep local Layer B event logging enabled.",
            "Review exact-name contracts for sensitive tools.",
            "Use project YAML overrides when zero-config defaults are too broad.",
        ],
        "policy": [
            "Custom YAML can tighten approval and path constraints tool by tool.",
            "Catch-all contracts help teams review newly introduced tools.",
        ],
    }
    normalized = topic.strip().lower()
    for key, bullets in knowledge.items():
        if key in normalized:
            return {"topic": topic, "results": bullets}
    return {
        "topic": topic,
        "results": [
            "No canned result matched the topic.",
            "This demo focuses on showing Layer B policy overrides from YAML.",
        ],
    }


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
        framework="custom_yaml_demo",
        args_schema=FILE_READ_SCHEMA,
    )
    register_runtime_tool(
        "project_lookup",
        project_lookup,
        description="Look up Layer B project notes from a small in-memory knowledge base.",
        framework="custom_yaml_demo",
        args_schema=PROJECT_LOOKUP_SCHEMA,
    )


def _decision_payload(decision: dict[str, Any]) -> dict[str, Any]:
    return {
        "decision": decision["decision"],
        "reason_code": decision["reason_code"],
        "details": decision["details"],
        "approval_token": decision["approval_token"],
        "sanitized_args": decision["sanitized_args"],
    }


def _run_case(
    engine: LayerBEngine,
    *,
    title: str,
    tool_name: str,
    tool_args: dict[str, Any],
    user_prompt: str,
    history: list[str],
    auto_approve: bool = False,
) -> None:
    print(f"\n=== {title} ===")
    invocation_context = {
        "args_schema": TOOL_SCHEMAS.get(tool_name),
        "workflow": "custom_yaml_demo",
        "history": history,
        "user_intent": user_prompt,
    }

    decision = engine.explain_decision(
        tool_name,
        tool_args,
        invocation_context=invocation_context,
        framework="custom_yaml_demo",
        agent_id="layer-b-custom-policy-demo",
    )
    print("Initial Layer B decision:")
    print(json.dumps(_decision_payload(decision), indent=2, default=str))

    final_decision = decision
    if str(decision["decision"]) == "require_approval" and auto_approve:
        final_decision = engine.explain_decision(
            tool_name,
            tool_args,
            approval_token=decision["approval_token"],
            invocation_context=invocation_context,
            framework="custom_yaml_demo",
            agent_id="layer-b-custom-policy-demo",
        )
        print("After demo approval:")
        print(json.dumps(_decision_payload(final_decision), indent=2, default=str))

    if str(final_decision["decision"]) != "allow":
        print("Tool execution skipped because Layer B did not allow the call.")
        history.append(tool_name)
        return

    if tool_name not in TOOL_IMPLS:
        print("Layer B allowed the call, but this demo has no local implementation for that tool.")
        history.append(tool_name)
        return

    raw_output = TOOL_IMPLS[tool_name](**tool_args)
    sanitized_output = engine.validator.sanitize_output(tool_name, raw_output)
    print("Sanitized tool output:")
    print(json.dumps(sanitized_output, indent=2, default=str))
    history.append(tool_name)


def main() -> int:
    _register_tools()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    event_log_path = Path("logs") / "layer_b" / f"custom_policy_demo_{timestamp}.jsonl"
    feedback_report_path = Path("logs") / "layer_b" / f"custom_policy_feedback_{timestamp}.json"

    engine = LayerBEngine(
        policy_path=str(CUSTOM_POLICY_PATH),
        event_log_path=str(event_log_path),
        agent_id="layer-b-custom-policy-demo",
        framework="custom_yaml_demo",
    )

    print(f"Custom policy: {CUSTOM_POLICY_PATH}")
    print(json.dumps(engine.describe_paths(), indent=2, default=str))

    history: list[str] = []

    _run_case(
        engine,
        title="Case 1: exact-name override requires approval before README access",
        tool_name="file_read",
        tool_args={"path": "README.md"},
        user_prompt="Read README.md for a quick summary.",
        history=history,
        auto_approve=True,
    )

    _run_case(
        engine,
        title="Case 2: custom YAML path allowlist blocks other files",
        tool_name="file_read",
        tool_args={"path": "layerb/validator.py"},
        user_prompt="Read the validator implementation.",
        history=history,
    )

    _run_case(
        engine,
        title="Case 3: exact-name project_lookup is allowed without approval",
        tool_name="project_lookup",
        tool_args={"topic": "production policy"},
        user_prompt="What matters for production policy?",
        history=history,
    )

    _run_case(
        engine,
        title="Case 4: catch-all policy forces approval for any other tool",
        tool_name="search_notes",
        tool_args={"query": "Layer B defaults"},
        user_prompt="Search project notes for Layer B defaults.",
        history=history,
        auto_approve=True,
    )

    print("\n=== Recent Layer B Events ===")
    print(json.dumps(engine.recent_security_events(limit=20), indent=2, default=str))

    print("\n=== Contract Candidates ===")
    print(json.dumps(engine.generate_contract_candidates(), indent=2, default=str))

    print("\n=== Feedback Report Export ===")
    feedback_report = engine.write_feedback_report(
        feedback_report_path,
        min_occurrences=1,
    )
    print(f"Wrote feedback report to: {feedback_report_path}")
    print(json.dumps(feedback_report, indent=2, default=str))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

