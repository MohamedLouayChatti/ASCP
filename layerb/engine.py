"""SDK-facing Layer B surface for typed capability security contracts."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from layerb.validator import (
    ComponentType,
    ContractDecision,
    ContractResult,
    ContractValidator,
    PermissionScope,
    PolicyValidationError,
    RiskLevel,
)
from layerb.policies import ContractCandidateGenerator, IncidentFeedbackGenerator, PolicyEditor

CapabilityResult = ContractResult
CapabilityValidator = ContractValidator

_BUNDLED_ROOT = Path(__file__).resolve().parent
_BUNDLED_DEFAULT_POLICY_PATH = _BUNDLED_ROOT / "policy" / "default_tool_permissions.yaml"
_BUNDLED_SCHEMAS_DIR = _BUNDLED_ROOT / "schemas"
_DEFAULT_PROJECT_POLICY_PATH = Path("policy") / "tool_permissions.yaml"
_DEFAULT_EVENT_LOG_PATH = Path("logs") / "layer_b" / "events.jsonl"


def _resolve_event_log_path(path: str | Path | None = None) -> Path:
    configured = (
        path
        or os.getenv("LAYERB_EVENT_LOG")
        or _DEFAULT_EVENT_LOG_PATH
    )
    return Path(configured)


@dataclass(frozen=True)
class LayerBPaths:
    policy_path: str = str(_DEFAULT_PROJECT_POLICY_PATH)
    schemas_dir: str = str(_BUNDLED_SCHEMAS_DIR)
    base_policy_path: str = str(_BUNDLED_DEFAULT_POLICY_PATH)
    event_log_path: str = str(_DEFAULT_EVENT_LOG_PATH)


class LayerBPolicy:
    """Loader for the standalone Layer B contract engine."""

    def __init__(
        self,
        *,
        policy_path: str = str(_DEFAULT_PROJECT_POLICY_PATH),
        schemas_dir: str = str(_BUNDLED_SCHEMAS_DIR),
        base_policy_path: str | None = str(_BUNDLED_DEFAULT_POLICY_PATH),
        event_log_path: str | None = str(_DEFAULT_EVENT_LOG_PATH),
    ) -> None:
        self.paths = LayerBPaths(
            policy_path=policy_path,
            schemas_dir=schemas_dir,
            base_policy_path=base_policy_path or "",
            event_log_path=event_log_path or "",
        )

    def load(self) -> ContractValidator:
        return ContractValidator(
            self.paths.policy_path,
            self.paths.schemas_dir,
            base_policy_path=self.paths.base_policy_path or None,
            unknown_capability_mode=(
                os.getenv("LAYERB_UNKNOWN_CAPABILITY_MODE")
                or "auto_allow"
            ),
            event_log_path=_resolve_event_log_path(self.paths.event_log_path or None),
        )


class LayerBEngine:
    """Small wrapper around ContractValidator with inspection helpers."""

    def __init__(
        self,
        validator: ContractValidator | None = None,
        *,
        policy_path: str = str(_DEFAULT_PROJECT_POLICY_PATH),
        schemas_dir: str = str(_BUNDLED_SCHEMAS_DIR),
        base_policy_path: str | None = str(_BUNDLED_DEFAULT_POLICY_PATH),
        event_log_path: str | None = str(_DEFAULT_EVENT_LOG_PATH),
        agent_id: str = "layer-b-local",
        framework: str = "layer_b",
    ) -> None:
        self.policy = LayerBPolicy(
            policy_path=policy_path,
            schemas_dir=schemas_dir,
            base_policy_path=base_policy_path,
            event_log_path=event_log_path,
        )
        self.validator = validator or self.policy.load()
        self.agent_id = agent_id
        self.framework = framework
        validator_event_log = getattr(self.validator, "event_log_path", None)
        self.event_log_path = (
            Path(validator_event_log)
            if validator_event_log is not None
            else _resolve_event_log_path(self.policy.paths.event_log_path or None)
        )

    @classmethod
    def from_defaults(cls) -> LayerBEngine:
        return cls()

    def describe_paths(self) -> dict[str, str]:
        return {
            "policy_path": str(Path(self.policy.paths.policy_path)),
            "schemas_dir": str(Path(self.policy.paths.schemas_dir)),
            "base_policy_path": str(Path(self.policy.paths.base_policy_path)),
            "event_log_path": str(self.event_log_path),
        }

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
        source = Path(event_log_path) if event_log_path is not None else self.event_log_path
        editor = PolicyEditor(self.policy.paths.policy_path)
        generator = IncidentFeedbackGenerator(editor, event_log_path=source)
        return [
            suggestion.to_dict()
            for suggestion in generator.generate_tool_feedback_suggestions(
                min_occurrences=min_occurrences
            )
        ]

    def generate_feedback_report(
        self,
        *,
        event_log_path: str | Path | None = None,
        min_occurrences: int = 2,
    ) -> dict[str, Any]:
        source = Path(event_log_path) if event_log_path is not None else self.event_log_path
        editor = PolicyEditor(self.policy.paths.policy_path)
        generator = IncidentFeedbackGenerator(editor, event_log_path=source)
        return generator.generate_tool_feedback_report(
            min_occurrences=min_occurrences
        ).to_dict()

    def write_feedback_report(
        self,
        path: str | Path,
        *,
        event_log_path: str | Path | None = None,
        min_occurrences: int = 2,
    ) -> dict[str, Any]:
        source = Path(event_log_path) if event_log_path is not None else self.event_log_path
        editor = PolicyEditor(self.policy.paths.policy_path)
        generator = IncidentFeedbackGenerator(editor, event_log_path=source)
        return generator.write_tool_feedback_report(
            path,
            min_occurrences=min_occurrences,
        ).to_dict()

    def recent_security_events(
        self,
        *,
        event_log_path: str | Path | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        source = Path(event_log_path) if event_log_path is not None else self.event_log_path
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
    parser.add_argument("--policy", default=str(_DEFAULT_PROJECT_POLICY_PATH))
    parser.add_argument("--schemas", default=str(_BUNDLED_SCHEMAS_DIR))
    parser.add_argument("--event-log", default=str(_DEFAULT_EVENT_LOG_PATH))

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List registered capabilities.")
    subparsers.add_parser("events", help="Show recent Layer B security events.")
    subparsers.add_parser("paths", help="Show the active Layer B paths.")
    subparsers.add_parser("candidates", help="Show auto-generated contract candidates.")
    feedback_parser = subparsers.add_parser("feedback", help="Show feedback-loop contract suggestions.")
    feedback_parser.add_argument("--min-occurrences", type=int, default=2)
    feedback_parser.add_argument("--report", action="store_true", help="Show an aggregated feedback-loop report.")
    feedback_parser.add_argument("--write-report", help="Write the aggregated feedback-loop report to a JSON file.")

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
        event_log_path=args.event_log,
    )

    if args.command == "list":
        print(json.dumps(engine.list_capabilities(), indent=2))
        return 0

    if args.command == "events":
        print(json.dumps(engine.recent_security_events(), indent=2, default=str))
        return 0

    if args.command == "paths":
        print(json.dumps(engine.describe_paths(), indent=2))
        return 0

    if args.command == "candidates":
        print(json.dumps(engine.generate_contract_candidates(), indent=2, default=str))
        return 0

    if args.command == "feedback":
        if args.write_report:
            payload = engine.write_feedback_report(
                args.write_report,
                min_occurrences=args.min_occurrences,
            )
        else:
            payload = (
                engine.generate_feedback_report(min_occurrences=args.min_occurrences)
                if args.report
                else engine.generate_feedback_suggestions(min_occurrences=args.min_occurrences)
            )
        print(json.dumps(payload, indent=2, default=str))
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