"""
Incident-driven contract refinement suggestions for Layer B.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from layerb.runtime_registry import list_runtime_tools
from layerb.policies.editor import PolicyEditor


FeedbackConfidence = Literal["low", "medium", "high"]

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


@dataclass(frozen=True)
class ContractFeedbackSuggestion:
    kind: str
    name: str
    reason_code: str
    count: int
    confidence: FeedbackConfidence
    recommended_patch: dict[str, Any]
    recommended_contract: dict[str, Any]
    observed_tools: list[str] = field(default_factory=list)
    schema_hash: str | None = None
    example_event_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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

            base_contract = self._base_contract(
                name,
                existing_capabilities=existing_capabilities,
                runtime_tools=runtime_tools,
            )
            recommended = _deep_merge_dicts(base_contract, patch)
            runtime_entry = runtime_tools.get(name, {})
            schema_hash = _compute_schema_hash(runtime_entry.get("args_schema"))
            confidence: FeedbackConfidence = "high" if len(grouped_events) >= 4 else "medium"
            suggestions.append(
                ContractFeedbackSuggestion(
                    kind="tool",
                    name=name,
                    reason_code=reason_code,
                    count=len(grouped_events),
                    confidence=confidence,
                    recommended_patch=patch,
                    recommended_contract=recommended,
                    observed_tools=[name],
                    schema_hash=schema_hash,
                    example_event_ids=[
                        str(event.get("event_id", ""))
                        for event in grouped_events[:5]
                        if str(event.get("event_id", "")).strip()
                    ],
                    reasons=[
                        f"{len(grouped_events)} Layer B incidents observed for '{name}' with reason '{reason_code}'.",
                        "The recommended patch is derived from repeated runtime decisions, not one-off events.",
                    ],
                )
            )

        return suggestions

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


__all__ = [
    "ContractFeedbackSuggestion",
    "IncidentFeedbackGenerator",
]



