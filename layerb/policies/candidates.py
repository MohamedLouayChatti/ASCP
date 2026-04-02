"""
Auto-generate contract candidates from observed runtime tools.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from collections.abc import Callable
from typing import Any, Literal

from layerb.runtime_registry import list_runtime_tools
from layerb.policies.editor import PolicyEditor


CandidateMatchType = Literal["exact_name", "argument_schema_hash"]


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _compute_schema_hash(schema: Any) -> str:
    return hashlib.sha256(_stable_json(schema).encode("utf-8")).hexdigest()


def _schema_hashes_from_match(contract: dict[str, Any]) -> set[str]:
    match_cfg = contract.get("match", {})
    if not isinstance(match_cfg, dict):
        return set()

    hashes: list[Any] = []
    for key in ("argument_schema_hashes", "arg_schema_hashes", "schema_hashes"):
        value = match_cfg.get(key)
        if isinstance(value, list):
            hashes.extend(value)
        elif value is not None:
            hashes.append(value)
    for key in ("argument_schema_hash", "arg_schema_hash", "schema_hash"):
        value = match_cfg.get(key)
        if value is not None:
            hashes.append(value)
    return {str(item).strip().lower().removeprefix("sha256:") for item in hashes if str(item).strip()}


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


@dataclass(frozen=True)
class ContractCandidate:
    kind: str
    name: str
    match_type: CandidateMatchType
    contract: dict[str, Any]
    observed_tools: list[str] = field(default_factory=list)
    schema_hash: str | None = None
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ContractCandidateGenerator:
    def __init__(
        self,
        policy_editor: PolicyEditor,
        *,
        runtime_tools_provider: Callable[[], dict[str, dict[str, Any]]] = list_runtime_tools,
    ) -> None:
        self._policy_editor = policy_editor
        self._runtime_tools_provider = runtime_tools_provider

    def _existing_capabilities(self) -> dict[str, Any]:
        snapshot = self._policy_editor.snapshot()
        capabilities = snapshot.get("capabilities")
        if isinstance(capabilities, dict) and capabilities:
            return capabilities
        tools = snapshot.get("tools", {})
        return tools if isinstance(tools, dict) else {}

    def _schema_template_name(self, schema_hash: str, tool_names: list[str]) -> str:
        slug = "_".join(sorted(tool_names)[:2])[:40].strip("_")
        suffix = schema_hash[:12]
        return f"{slug or 'tool'}_schema_template_{suffix}"

    def generate_tool_candidates(
        self,
        *,
        observed_tools: dict[str, Any] | None = None,
    ) -> list[ContractCandidate]:
        observed_tools = observed_tools or {}
        runtime_tools = self._runtime_tools_provider()
        existing_capabilities = self._existing_capabilities()
        existing_exact_names = set(existing_capabilities.keys())
        existing_schema_hashes = {
            schema_hash
            for contract in existing_capabilities.values()
            if isinstance(contract, dict)
            for schema_hash in _schema_hashes_from_match(contract)
        }

        groups: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        singles: list[tuple[str, dict[str, Any], str | None]] = []

        for name, runtime_entry in sorted(runtime_tools.items()):
            if name in existing_exact_names:
                continue

            args_schema = runtime_entry.get("args_schema") if isinstance(runtime_entry, dict) else None
            schema_hash = _compute_schema_hash(args_schema) if args_schema else None
            if schema_hash and schema_hash in existing_schema_hashes:
                continue
            if schema_hash:
                groups.setdefault(schema_hash, []).append((name, runtime_entry))
            else:
                singles.append((name, runtime_entry, None))

        candidates: list[ContractCandidate] = []
        exact_candidates: list[tuple[str, dict[str, Any], str | None]] = list(singles)

        for schema_hash, tools in sorted(groups.items()):
            if len(tools) == 1:
                name, runtime_entry = tools[0]
                exact_candidates.append((name, runtime_entry, schema_hash))
                continue

            tool_names = [name for name, _ in tools]
            representative_name, representative_entry = tools[0]
            observed = copy.deepcopy(
                observed_tools.get(representative_name) or _observed_stub(representative_name, representative_entry)
            )
            contract = self._policy_editor.build_default_contract("tool", representative_name, observed)
            contract["match"] = {"argument_schema_hash": schema_hash}
            contract["description"] = (
                f"Auto-generated schema template for tools sharing the same argument schema: "
                f"{', '.join(tool_names)}."
            )
            candidates.append(
                ContractCandidate(
                    kind="tool",
                    name=self._schema_template_name(schema_hash, tool_names),
                    match_type="argument_schema_hash",
                    contract=contract,
                    observed_tools=tool_names,
                    schema_hash=schema_hash,
                    reasons=[
                        "multiple unregistered runtime tools share the same argument schema",
                    ],
                )
            )

        for name, runtime_entry, schema_hash in sorted(exact_candidates, key=lambda item: item[0]):
            observed = copy.deepcopy(
                observed_tools.get(name) or _observed_stub(name, runtime_entry)
            )
            contract = self._policy_editor.build_default_contract("tool", name, observed)
            reasons = ["unregistered runtime tool observed"]
            if schema_hash is not None:
                reasons.append("argument schema observed for future grouping")
            candidates.append(
                ContractCandidate(
                    kind="tool",
                    name=name,
                    match_type="exact_name",
                    contract=contract,
                    observed_tools=[name],
                    schema_hash=schema_hash,
                    reasons=reasons,
                )
            )

        return candidates

    def write_tool_candidates(
        self,
        path: str | Path,
        *,
        observed_tools: dict[str, Any] | None = None,
    ) -> list[ContractCandidate]:
        candidates = self.generate_tool_candidates(observed_tools=observed_tools)
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = [candidate.to_dict() for candidate in candidates]
        destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return candidates


__all__ = [
    "ContractCandidate",
    "ContractCandidateGenerator",
]



