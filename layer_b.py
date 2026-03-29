"""
Standalone Layer B surface for typed capability security contracts.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from apps.gateway.middleware.pep_tool import (
    ComponentType,
    ContractDecision,
    ContractResult,
    ContractValidator,
    PermissionScope,
    PolicyValidationError,
    RiskLevel,
)
from apps.gateway.policies import ContractCandidateGenerator, IncidentFeedbackGenerator, PolicyEditor

CapabilityResult = ContractResult
CapabilityValidator = ContractValidator


@dataclass(frozen=True)
class LayerBPaths:
    policy_path: str = "policy/tool_permissions.yaml"
    schemas_dir: str = "schemas"


class LayerBPolicy:
    """Loader for the standalone Layer B contract engine."""

    def __init__(
        self,
        *,
        policy_path: str = "policy/tool_permissions.yaml",
        schemas_dir: str = "schemas",
    ) -> None:
        self.paths = LayerBPaths(policy_path=policy_path, schemas_dir=schemas_dir)

    def load(self) -> ContractValidator:
        return ContractValidator(
            self.paths.policy_path,
            self.paths.schemas_dir,
            unknown_capability_mode=os.getenv("ASCP_UNKNOWN_CAPABILITY_MODE", "auto_allow"),
            audit_log_path=os.getenv("ASCP_LAYER_B_EVENT_LOG"),
            langwatch_enabled=bool(os.getenv("LANGWATCH_KEY") or os.getenv("LANGWATCH_API_KEY")),
            langwatch_api_key=os.getenv("LANGWATCH_KEY") or os.getenv("LANGWATCH_API_KEY"),
            langwatch_endpoint=os.getenv("LANGWATCH_ENDPOINT"),
            langwatch_project=os.getenv("LANGWATCH_PROJECT", "layer-b-sdk"),
            langwatch_debug=str(os.getenv("LANGWATCH_DEBUG", "")).lower() in {"1", "true", "yes", "on"},
        )


class LayerBEngine:
    """Small wrapper around ContractValidator with inspection helpers."""

    def __init__(
        self,
        validator: ContractValidator | None = None,
        *,
        policy_path: str = "policy/tool_permissions.yaml",
        schemas_dir: str = "schemas",
        agent_id: str = "layer-b-local",
        framework: str = "layer_b",
    ) -> None:
        self.policy = LayerBPolicy(policy_path=policy_path, schemas_dir=schemas_dir)
        self.validator = validator or self.policy.load()
        self.agent_id = agent_id
        self.framework = framework

    @classmethod
    def from_defaults(cls) -> LayerBEngine:
        return cls()

    def list_capabilities(self) -> list[str]:
        return self.validator.list_capabilities()

    def list_resources(self) -> list[str]:
        return self.validator.list_resources()

    def list_prompts(self) -> list[str]:
        return self.validator.list_prompts()

    def inspect_capability(self, capability_name: str) -> dict[str, Any]:
        contract = self.validator.get_capability_contract(capability_name)
        schema = self.validator.get_capability_schema(capability_name)
        return {
            "capability": capability_name,
            "risk": contract.get("risk", RiskLevel.UNKNOWN.value),
            "scopes": contract.get("scopes", []),
            "approval_required": contract.get("approval_required", False),
            "constraints": contract.get("constraints", {}),
            "schema": schema,
        }

    def inspect_workflow(self, workflow_name: str) -> dict[str, Any]:
        sequences = getattr(self.validator, "_capability_sequences", {})
        workflows = sequences.get("workflows", {}) if isinstance(sequences, dict) else {}
        workflow = workflows.get(workflow_name, {}) if isinstance(workflows, dict) else {}
        return {
            "workflow": workflow_name,
            "sequence_policy": workflow,
            "global_transition_graph": sequences.get("transition_graph", {})
            if isinstance(sequences, dict)
            else {},
        }

    def validate_capability(
        self,
        capability_name: str,
        arguments: dict[str, Any],
        *,
        approval_token: str | None = None,
        evidence_ids: list[str] | None = None,
        trust_vector: dict[str, Any] | None = None,
        invocation_context: dict[str, Any] | None = None,
        agent_id: str | None = None,
        framework: str | None = None,
    ) -> ContractResult:
        return self.validator.validate_capability_call(
            capability_name,
            arguments,
            approval_token=approval_token,
            evidence_ids=evidence_ids,
            trust_vector=trust_vector,
            invocation_context=invocation_context,
            agent_id=agent_id or self.agent_id,
            framework=framework or self.framework,
        )

    def explain_decision(
        self,
        capability_name: str,
        arguments: dict[str, Any],
        *,
        approval_token: str | None = None,
        evidence_ids: list[str] | None = None,
        trust_vector: dict[str, Any] | None = None,
        invocation_context: dict[str, Any] | None = None,
        agent_id: str | None = None,
        framework: str | None = None,
    ) -> dict[str, Any]:
        result = self.validate_capability(
            capability_name,
            arguments,
            approval_token=approval_token,
            evidence_ids=evidence_ids,
            trust_vector=trust_vector,
            invocation_context=invocation_context,
            agent_id=agent_id,
            framework=framework,
        )
        return {
            "capability": capability_name,
            "decision": result.decision,
            "reason_code": result.reason_code,
            "details": result.details,
            "violations": result.violations,
            "approval_token": result.approval_token,
            "sanitized_args": result.sanitized_args,
        }

    def generate_contract_candidates(self) -> list[dict[str, Any]]:
        editor = PolicyEditor(self.policy.paths.policy_path)
        generator = ContractCandidateGenerator(editor)
        return [candidate.to_dict() for candidate in generator.generate_tool_candidates()]

    def generate_feedback_suggestions(
        self,
        *,
        event_log_path: str | Path | None = None,
        min_occurrences: int = 2,
    ) -> list[dict[str, Any]]:
        source = Path(
            event_log_path
            or os.getenv("ASCP_LAYER_B_EVENT_LOG")
            or "data/layer_b_events.jsonl"
        )
        editor = PolicyEditor(self.policy.paths.policy_path)
        generator = IncidentFeedbackGenerator(editor, event_log_path=source)
        return [
            suggestion.to_dict()
            for suggestion in generator.generate_tool_feedback_suggestions(
                min_occurrences=min_occurrences
            )
        ]

    def recent_security_events(
        self,
        *,
        event_log_path: str | Path | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        source = Path(
            event_log_path
            or os.getenv("ASCP_LAYER_B_EVENT_LOG")
            or "data/layer_b_events.jsonl"
        )
        if not source.exists():
            return []

        events: list[dict[str, Any]] = []
        with source.open("r", encoding="utf-8") as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                events.append(json.loads(raw))
        return events[-limit:]


def _load_json(value: str | None, default: Any) -> Any:
    if value is None:
        return default
    return json.loads(value)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect and run Layer B in isolation.")
    parser.add_argument("--policy", default="policy/tool_permissions.yaml")
    parser.add_argument("--schemas", default="schemas")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List registered capabilities.")
    subparsers.add_parser("events", help="Show recent Layer B security events.")
    subparsers.add_parser("candidates", help="Show auto-generated contract candidates.")
    feedback_parser = subparsers.add_parser("feedback", help="Show feedback-loop contract suggestions.")
    feedback_parser.add_argument("--min-occurrences", type=int, default=2)

    inspect_parser = subparsers.add_parser("inspect", help="Inspect one capability contract.")
    inspect_parser.add_argument("capability")

    workflow_parser = subparsers.add_parser("workflow", help="Inspect one workflow sequence policy.")
    workflow_parser.add_argument("workflow")

    validate_parser = subparsers.add_parser(
        "validate",
        help="Run a Layer B decision for a capability call.",
    )
    validate_parser.add_argument("capability")
    validate_parser.add_argument("--args", required=True, dest="arguments")
    validate_parser.add_argument("--approval-token")
    validate_parser.add_argument("--evidence", help='JSON list, e.g. ["doc-1","doc-2"]')
    validate_parser.add_argument("--trust", help='JSON object, e.g. {"grounding_score":0.9}')
    validate_parser.add_argument(
        "--context",
        help='JSON object, e.g. {"workflow":"review_flow","history":["safe_tool"]}',
    )
    validate_parser.add_argument("--agent-id", default="layer-b-cli")
    validate_parser.add_argument("--framework", default="layer_b")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    engine = LayerBEngine(
        policy_path=args.policy,
        schemas_dir=args.schemas,
    )

    if args.command == "list":
        print(json.dumps(engine.list_capabilities(), indent=2))
        return 0

    if args.command == "events":
        print(json.dumps(engine.recent_security_events(), indent=2, default=str))
        return 0

    if args.command == "candidates":
        print(json.dumps(engine.generate_contract_candidates(), indent=2, default=str))
        return 0

    if args.command == "feedback":
        print(
            json.dumps(
                engine.generate_feedback_suggestions(min_occurrences=args.min_occurrences),
                indent=2,
                default=str,
            )
        )
        return 0

    if args.command == "inspect":
        print(json.dumps(engine.inspect_capability(args.capability), indent=2, default=str))
        return 0

    if args.command == "workflow":
        print(json.dumps(engine.inspect_workflow(args.workflow), indent=2, default=str))
        return 0

    if args.command == "validate":
        payload = engine.explain_decision(
            args.capability,
            _load_json(args.arguments, {}),
            approval_token=args.approval_token,
            evidence_ids=_load_json(args.evidence, None),
            trust_vector=_load_json(args.trust, None),
            invocation_context=_load_json(args.context, None),
            agent_id=args.agent_id,
            framework=args.framework,
        )
        print(json.dumps(payload, indent=2, default=str))
        return 0

    return 1


__all__ = [
    "CapabilityResult",
    "CapabilityValidator",
    "ComponentType",
    "ContractDecision",
    "ContractResult",
    "ContractValidator",
    "LayerBEngine",
    "LayerBPaths",
    "LayerBPolicy",
    "PermissionScope",
    "PolicyValidationError",
    "RiskLevel",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
