"""
Incident-driven contract refinement suggestions for Layer B.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml

from layerb.runtime_registry import list_runtime_tools
from layerb.policies.editor import PolicyEditor


FeedbackConfidence = Literal["low", "medium", "high"]
FeedbackAction = Literal[
    "register_or_review",
    "tighten_constraints",
    "limit_payloads",
    "review_contract",
]

_DEFAULT_DOMAIN_DENYLIST = [
    "169.254.169.254",
    "metadata.google.internal",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
]
_DEFAULT_CIDR_DENYLIST = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _compute_schema_hash(schema: Any) -> str | None:
    if not schema:
        return None
    return hashlib.sha256(_stable_json(schema).encode("utf-8")).hexdigest()


def _deep_merge_dicts(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_dicts(merged[key], value)
        elif isinstance(value, list) and isinstance(merged.get(key), list):
            merged[key] = [*merged[key], *[item for item in value if item not in merged[key]]]
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    if not source.exists():
        return []

    events: list[dict[str, Any]] = []
    with source.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            events.append(json.loads(raw))
    return events


def _observed_stub(name: str, runtime_entry: dict[str, Any]) -> dict[str, Any]:
    description = str(runtime_entry.get("description") or f"Auto-observed tool '{name}'.")
    return {
        "descriptions": [description],
        "last_metadata": {
            "framework": runtime_entry.get("framework", "custom"),
            "tool_path": runtime_entry.get("tool_path"),
            "args_schema": copy.deepcopy(runtime_entry.get("args_schema") or {}),
        },
    }


def _feedback_patch_for_reason(reason_code: str, examples: list[dict[str, Any]]) -> dict[str, Any]:
    if reason_code in {"APPROVAL_REQUIRED", "CAPABILITY_NOT_REGISTERED", "UNKNOWN_CAPABILITY"}:
        return {"approval_required": True}

    if reason_code in {"PATH_TRAVERSAL", "PATH_POLICY_VIOLATION"}:
        return {"constraints": {"deny_path_traversal": True}}

    if reason_code == "DOMAIN_POLICY_VIOLATION":
        domain_denylist = list(_DEFAULT_DOMAIN_DENYLIST)
        for event in examples:
            for key in ("url", "uri", "endpoint", "webhook"):
                raw_value = event.get("args", {}).get(key)
                if raw_value is None:
                    continue
                host = (urlparse(str(raw_value)).hostname or "").strip().lower()
                if host and host not in domain_denylist:
                    domain_denylist.append(host)
        return {
            "constraints": {
                "allowed_schemes": ["http", "https"],
                "resolve_dns": True,
                "domain_denylist": domain_denylist,
                "cidr_denylist": list(_DEFAULT_CIDR_DENYLIST),
            }
        }

    if reason_code == "SQL_POLICY_VIOLATION":
        return {
            "constraints": {
                "sql_mode": "select_only",
                "deny_multi_statement": True,
            }
        }

    if reason_code == "CONTENT_TOO_LARGE":
        return {"constraints": {"max_body_chars": 4000}}

    if reason_code == "ARGUMENT_TOO_LARGE":
        patch: dict[str, Any] = {"constraints": {"max_arg_lengths": {}}}
        for event in examples:
            details = str(event.get("details", ""))
            match = re.search(r"Argument '([^']+)' exceeds maximum length (\d+)", details)
            if not match:
                continue
            field_name = match.group(1)
            max_length = int(match.group(2))
            patch["constraints"]["max_arg_lengths"][field_name] = max_length
        return patch

    if reason_code == "SHELL_DESTRUCTIVE_PATTERN_BLOCKED":
        return {
            "approval_required": True,
            "constraints": {
                "arg_rules": [
                    {
                        "field": "command",
                        "op": "regex",
                        "value": r"(?i)\b(rm\s+-rf|del\s+/[qs]|format\s+[a-z]:|mkfs|shutdown|reboot)\b",
                        "reason": "SHELL_DESTRUCTIVE_PATTERN_BLOCKED",
                        "details": "The requested shell command matches a destructive command pattern.",
                    }
                ]
            },
        }

    return {}


def _feedback_action_for_reason(reason_code: str, existing_contract: bool) -> FeedbackAction:
    if reason_code in {"PATH_TRAVERSAL", "PATH_POLICY_VIOLATION", "DOMAIN_POLICY_VIOLATION", "SQL_POLICY_VIOLATION", "SHELL_DESTRUCTIVE_PATTERN_BLOCKED"}:
        return "tighten_constraints"
    if reason_code in {"CONTENT_TOO_LARGE", "ARGUMENT_TOO_LARGE"}:
        return "limit_payloads"
    if reason_code in {"APPROVAL_REQUIRED", "CAPABILITY_NOT_REGISTERED", "UNKNOWN_CAPABILITY"} and not existing_contract:
        return "register_or_review"
    return "review_contract"


def _summary_for_reason(
    name: str,
    reason_code: str,
    count: int,
    action: FeedbackAction,
    *,
    existing_contract: bool,
) -> str:
    contract_state = "existing contract" if existing_contract else "no exact contract"
    if action == "register_or_review":
        return (
            f"{count} repeated '{reason_code}' incidents for '{name}' suggest adding or explicitly reviewing a project contract; Layer B observed {contract_state}."
        )
    if action == "tighten_constraints":
        return (
            f"{count} repeated '{reason_code}' incidents for '{name}' suggest tightening constraints in the project YAML rather than changing runtime logic."
        )
    if action == "limit_payloads":
        return (
            f"{count} repeated '{reason_code}' incidents for '{name}' suggest adding explicit input size limits to the project YAML."
        )
    return (
        f"{count} repeated '{reason_code}' incidents for '{name}' suggest reviewing the current Layer B contract configuration."
    )


def _collect_policy_matches(events: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for event in events:
        trace = event.get("trace", {})
        if not isinstance(trace, dict):
            continue
        match_name = str(trace.get("policy_match", "")).strip()
        if match_name and match_name not in values:
            values.append(match_name)
    return values


def _collect_example_args(events: list[dict[str, Any]], limit: int = 3) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    seen: set[str] = set()
    for event in events:
        args = event.get("args")
        if not isinstance(args, dict):
            continue
        stable = _stable_json(args)
        if stable in seen:
            continue
        seen.add(stable)
        examples.append(copy.deepcopy(args))
        if len(examples) >= limit:
            break
    return examples


def _last_seen_at(events: list[dict[str, Any]]) -> str | None:
    timestamps = [str(event.get("recorded_at", "")).strip() for event in events if str(event.get("recorded_at", "")).strip()]
    return max(timestamps) if timestamps else None


def _suggested_yaml_for_tool(name: str, contract: dict[str, Any]) -> str:
    payload = {"capabilities": {name: contract}}
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=False).strip()


@dataclass(frozen=True)
class ContractFeedbackSuggestion:
    kind: str
    name: str
    reason_code: str
    count: int
    confidence: FeedbackConfidence
    action: FeedbackAction
    summary: str
    recommended_patch: dict[str, Any]
    recommended_contract: dict[str, Any]
    suggested_yaml: str
    observed_tools: list[str] = field(default_factory=list)
    schema_hash: str | None = None
    example_event_ids: list[str] = field(default_factory=list)
    example_args: list[dict[str, Any]] = field(default_factory=list)
    observed_policy_matches: list[str] = field(default_factory=list)
    last_seen_at: str | None = None
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FeedbackLoopReport:
    generated_at: str
    event_log_path: str
    total_events: int
    analyzed_tool_events: int
    suggestion_count: int
    tools_with_suggestions: list[str]
    reason_counts: dict[str, int]
    suggestions: list[ContractFeedbackSuggestion] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["suggestions"] = [suggestion.to_dict() for suggestion in self.suggestions]
        return payload


class IncidentFeedbackGenerator:
    def __init__(
        self,
        policy_editor: PolicyEditor,
        *,
        event_log_path: str | Path,
    ) -> None:
        self._policy_editor = policy_editor
        self._event_log_path = Path(event_log_path)

    def _existing_capabilities(self) -> dict[str, Any]:
        snapshot = self._policy_editor.snapshot()
        capabilities = snapshot.get("capabilities")
        if isinstance(capabilities, dict) and capabilities:
            return capabilities
        tools = snapshot.get("tools", {})
        return tools if isinstance(tools, dict) else {}

    def _observed_for_tool(self, name: str, runtime_tools: dict[str, dict[str, Any]]) -> dict[str, Any]:
        runtime_entry = runtime_tools.get(name, {})
        return _observed_stub(name, runtime_entry)

    def _base_contract(
        self,
        name: str,
        *,
        existing_capabilities: dict[str, Any],
        runtime_tools: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        existing = existing_capabilities.get(name)
        if isinstance(existing, dict):
            return copy.deepcopy(existing)
        observed = self._observed_for_tool(name, runtime_tools)
        return self._policy_editor.build_default_contract("tool", name, observed)

    def generate_tool_feedback_suggestions(
        self,
        *,
        min_occurrences: int = 2,
    ) -> list[ContractFeedbackSuggestion]:
        events = _load_jsonl(self._event_log_path)
        runtime_tools = list_runtime_tools()
        existing_capabilities = self._existing_capabilities()

        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for event in events:
            if event.get("component_type") != "tool":
                continue
            name = str(event.get("component_name", "")).strip()
            reason_code = str(event.get("reason_code", "")).strip()
            if not name or not reason_code:
                continue
            groups.setdefault((name, reason_code), []).append(event)

        suggestions: list[ContractFeedbackSuggestion] = []
        for (name, reason_code), grouped_events in sorted(groups.items()):
            if len(grouped_events) < min_occurrences:
                continue

            patch = _feedback_patch_for_reason(reason_code, grouped_events)
            if not patch:
                continue

            has_existing_contract = isinstance(existing_capabilities.get(name), dict)
            base_contract = self._base_contract(
                name,
                existing_capabilities=existing_capabilities,
                runtime_tools=runtime_tools,
            )
            recommended = _deep_merge_dicts(base_contract, patch)
            runtime_entry = runtime_tools.get(name, {})
            schema_hash = _compute_schema_hash(runtime_entry.get("args_schema"))
            confidence: FeedbackConfidence = "high" if len(grouped_events) >= 4 else "medium"
            action = _feedback_action_for_reason(reason_code, has_existing_contract)
            summary = _summary_for_reason(
                name,
                reason_code,
                len(grouped_events),
                action,
                existing_contract=has_existing_contract,
            )
            suggestions.append(
                ContractFeedbackSuggestion(
                    kind="tool",
                    name=name,
                    reason_code=reason_code,
                    count=len(grouped_events),
                    confidence=confidence,
                    action=action,
                    summary=summary,
                    recommended_patch=patch,
                    recommended_contract=recommended,
                    suggested_yaml=_suggested_yaml_for_tool(name, recommended),
                    observed_tools=[name],
                    schema_hash=schema_hash,
                    example_event_ids=[
                        str(event.get("event_id", ""))
                        for event in grouped_events[:5]
                        if str(event.get("event_id", "")).strip()
                    ],
                    example_args=_collect_example_args(grouped_events),
                    observed_policy_matches=_collect_policy_matches(grouped_events),
                    last_seen_at=_last_seen_at(grouped_events),
                    reasons=[
                        f"{len(grouped_events)} Layer B incidents observed for '{name}' with reason '{reason_code}'.",
                        "The recommendation is advisory only; it does not mutate the active contract.",
                    ],
                )
            )

        return suggestions

    def generate_tool_feedback_report(
        self,
        *,
        min_occurrences: int = 2,
    ) -> FeedbackLoopReport:
        events = _load_jsonl(self._event_log_path)
        tool_events = [event for event in events if event.get("component_type") == "tool"]
        suggestions = self.generate_tool_feedback_suggestions(min_occurrences=min_occurrences)
        reason_counts: dict[str, int] = {}
        for event in tool_events:
            reason_code = str(event.get("reason_code", "")).strip()
            if not reason_code:
                continue
            reason_counts[reason_code] = reason_counts.get(reason_code, 0) + 1

        return FeedbackLoopReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            event_log_path=str(self._event_log_path),
            total_events=len(events),
            analyzed_tool_events=len(tool_events),
            suggestion_count=len(suggestions),
            tools_with_suggestions=list(dict.fromkeys(suggestion.name for suggestion in suggestions)),
            reason_counts=reason_counts,
            suggestions=suggestions,
        )

    def write_tool_feedback_suggestions(
        self,
        path: str | Path,
        *,
        min_occurrences: int = 2,
    ) -> list[ContractFeedbackSuggestion]:
        suggestions = self.generate_tool_feedback_suggestions(min_occurrences=min_occurrences)
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = [suggestion.to_dict() for suggestion in suggestions]
        destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return suggestions

    def write_tool_feedback_report(
        self,
        path: str | Path,
        *,
        min_occurrences: int = 2,
    ) -> FeedbackLoopReport:
        report = self.generate_tool_feedback_report(min_occurrences=min_occurrences)
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return report


__all__ = [
    "ContractFeedbackSuggestion",
    "FeedbackLoopReport",
    "IncidentFeedbackGenerator",
]

