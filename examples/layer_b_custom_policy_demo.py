from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
root_str = str(ROOT)
if root_str not in sys.path:
    sys.path.insert(0, root_str)

from layerb import LayerBEngine, register_runtime_tool


CUSTOM_POLICY_PATH = Path("examples") / "layer_b_custom_policy.yaml"
_APPROVAL_ENV = "LAYERB_DEMO_APPROVAL"

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


def _format_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, default=str)


def _print_section(title: str) -> None:
    line = "=" * len(title)
    print(f"\n{line}\n{title}\n{line}")


def _print_decision(decision: dict[str, Any]) -> None:
    print(f"Decision      : {decision['decision']}")
    print(f"Reason code   : {decision['reason_code']}")
    print(f"Details       : {decision['details'] or '(none)'}")
    print(f"Approval token: {'issued' if decision['approval_token'] else 'not needed'}")
    print("Sanitized args:")
    print(_format_json(decision["sanitized_args"]))


def _approval_choice_from_env() -> bool | None:
    raw = os.getenv(_APPROVAL_ENV, "").strip().lower()
    if raw in {"1", "y", "yes", "approve", "approved", "allow"}:
        return True
    if raw in {"0", "n", "no", "deny", "denied", "block"}:
        return False
    return None


def _prompt_for_approval(tool_name: str, tool_args: dict[str, Any], decision: dict[str, Any]) -> bool:
    _print_section("Approval Required")
    print(f"Tool          : {tool_name}")
    print(f"Reason code   : {decision['reason_code']}")
    print(f"Details       : {decision['details'] or '(none)'}")
    print("Requested args:")
    print(_format_json(tool_args))

    env_choice = _approval_choice_from_env()
    if env_choice is not None:
        choice_label = "APPROVE" if env_choice else "DENY"
        print(f"Approval choice from {_APPROVAL_ENV}: {choice_label}")
        return env_choice

    if not sys.stdin.isatty():
        print(f"No interactive terminal detected. Set {_APPROVAL_ENV}=approve or deny. Defaulting to deny.")
        return False

    while True:
        response = input("Approve this tool call? [y/N]: ").strip().lower()
        if response in {"y", "yes"}:
            return True
        if response in {"", "n", "no"}:
            return False
        print("Please answer with 'y' or 'n'.")


def _maybe_approve(
    engine: LayerBEngine,
    *,
    tool_name: str,
    tool_args: dict[str, Any],
    decision: dict[str, Any],
    invocation_context: dict[str, Any],
) -> dict[str, Any]:
    if str(decision["decision"]) != "require_approval":
        return decision

    if not _prompt_for_approval(tool_name, tool_args, decision):
        print("Approval denied. Tool execution skipped.")
        return decision

    approved = engine.explain_decision(
        tool_name,
        tool_args,
        approval_token=decision["approval_token"],
        invocation_context=invocation_context,
        framework="custom_yaml_demo",
        agent_id="layer-b-custom-policy-demo",
    )

    _print_section("After Approval")
    _print_decision(approved)
    return approved


def _run_case(
    engine: LayerBEngine,
    *,
    title: str,
    tool_name: str,
    tool_args: dict[str, Any],
    user_prompt: str,
    history: list[str],
) -> None:
    _print_section(title)
    print("User prompt:")
    print(user_prompt)
    print("\nPlanned tool call:")
    print(_format_json({"tool": tool_name, "args": tool_args}))

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

    print("\nInitial Layer B decision:")
    _print_decision(decision)

    final_decision = _maybe_approve(
        engine,
        tool_name=tool_name,
        tool_args=tool_args,
        decision=decision,
        invocation_context=invocation_context,
    )

    if str(final_decision["decision"]) != "allow":
        print("Final outcome : not executed")
        return

    if tool_name not in TOOL_IMPLS:
        print("Final outcome : approved by policy, but no local demo implementation is registered.")
        return

    raw_output = TOOL_IMPLS[tool_name](**tool_args)
    sanitized_output = engine.validator.sanitize_output(tool_name, raw_output)
    print("Final outcome : executed")
    print("Sanitized tool output:")
    print(_format_json(sanitized_output))
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
    print(_format_json(engine.describe_paths()))
    print(f"Set {_APPROVAL_ENV}=approve or {_APPROVAL_ENV}=deny to run without prompts.")

    history: list[str] = []

    _run_case(
        engine,
        title="Case 1: exact-name override requires approval before README access",
        tool_name="file_read",
        tool_args={"path": "README.md"},
        user_prompt="Read README.md for a quick summary.",
        history=history,
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
    )

    _print_section("Recent Layer B Events")
    print(_format_json(engine.recent_security_events(limit=20)))

    _print_section("Contract Candidates")
    print(_format_json(engine.generate_contract_candidates()))

    _print_section("Feedback Report Export")
    feedback_report = engine.write_feedback_report(
        feedback_report_path,
        min_occurrences=1,
    )
    print(f"Wrote feedback report to: {feedback_report_path}")
    print(_format_json(feedback_report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
