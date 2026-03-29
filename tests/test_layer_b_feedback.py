from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import yaml

from apps.gateway.middleware.pep_tool import ContractDecision, ContractValidator
from apps.gateway.policies.editor import PolicyEditor
from apps.gateway.policies.feedback import IncidentFeedbackGenerator


def _make_validator_files(name: str, policy: dict[str, object]) -> tuple[Path, Path, Path]:
    root = Path(".pytest_layer_b_feedback") / f"{name}-{uuid4().hex}"
    root.mkdir(parents=True)
    schemas_dir = root / "schemas"
    schemas_dir.mkdir()
    policy_path = root / "tool_permissions.yaml"
    event_log_path = root / "events.jsonl"
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    return policy_path, schemas_dir, event_log_path


def test_validator_writes_jsonl_security_events_with_trace_metadata() -> None:
    schema = {
        "type": "object",
        "required": ["query"],
        "additionalProperties": False,
        "properties": {"query": {"type": "string"}},
    }
    policy = {
        "version": "1.0",
        "capabilities": {
            "demo_tool": {
                "risk": "low",
                "scopes": ["custom"],
                "approval_required": False,
                "schema": "schemas/demo_tool.schema.json",
                "constraints": {},
            }
        },
    }
    policy_path, schemas_dir, event_log_path = _make_validator_files("event-log", policy)
    (schemas_dir / "demo_tool.schema.json").write_text(json.dumps(schema), encoding="utf-8")

    validator = ContractValidator(
        policy_path,
        schemas_dir,
        audit_log_path=event_log_path,
        langwatch_enabled=False,
    )

    result = validator.validate_call(
        "demo_tool",
        {"query": "hello"},
        agent_id="pytest-agent",
        framework="pytest",
        invocation_context={"args_schema": schema},
    )

    payload = [json.loads(line) for line in event_log_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    assert result.decision == ContractDecision.ALLOW
    assert len(payload) == 1
    event = payload[0]
    assert event["component_name"] == "demo_tool"
    assert event["decision"] == "allow"
    assert event["trace"]["policy_match"] == "exact_name"
    assert event["trace"]["contract_name"] == "demo_tool"
    assert event["trace"]["input_schema_hash"]
    assert event["operation_fingerprint"]
    assert event["event_id"]
    assert event["recorded_at"]


def test_incident_feedback_generator_suggests_contract_refinement_for_unknown_tool() -> None:
    policy = {"version": "1.0", "capabilities": {}}
    policy_path, schemas_dir, event_log_path = _make_validator_files("feedback", policy)
    _ = schemas_dir

    event_log_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event_id": "evt-1",
                        "component_type": "tool",
                        "component_name": "search_query",
                        "decision": "require_approval",
                        "reason_code": "APPROVAL_REQUIRED",
                        "details": "Capability 'search_query' is not registered and requires human approval.",
                        "args": {"query": "Layer B status"},
                    }
                ),
                json.dumps(
                    {
                        "event_id": "evt-2",
                        "component_type": "tool",
                        "component_name": "search_query",
                        "decision": "require_approval",
                        "reason_code": "APPROVAL_REQUIRED",
                        "details": "Capability 'search_query' is not registered and requires human approval.",
                        "args": {"query": "Layer B roadmap"},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    generator = IncidentFeedbackGenerator(
        PolicyEditor(policy_path),
        event_log_path=event_log_path,
    )

    suggestions = generator.generate_tool_feedback_suggestions(min_occurrences=2)

    assert len(suggestions) == 1
    suggestion = suggestions[0]
    assert suggestion.name == "search_query"
    assert suggestion.reason_code == "APPROVAL_REQUIRED"
    assert suggestion.recommended_patch == {"approval_required": True}
    assert suggestion.recommended_contract["approval_required"] is True
    assert suggestion.example_event_ids == ["evt-1", "evt-2"]
