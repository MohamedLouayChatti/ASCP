from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import yaml

from apps.gateway.policies.candidates import ContractCandidateGenerator
from apps.gateway.policies.editor import PolicyEditor


def _schema_hash(schema: dict[str, object]) -> str:
    payload = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _make_editor(name: str, policy: dict[str, object] | None = None) -> PolicyEditor:
    tmp_path = Path(".pytest_contract_candidates") / f"{name}-{uuid4().hex}"
    tmp_path.mkdir(parents=True)
    policy_path = tmp_path / "tool_permissions.yaml"
    policy_path.write_text(
        yaml.safe_dump(policy or {"version": "1.0", "capabilities": {}}),
        encoding="utf-8",
    )
    return PolicyEditor(policy_path)


def test_generate_exact_name_candidate_for_single_runtime_tool() -> None:
    editor = _make_editor("single-runtime-tool")
    generator = ContractCandidateGenerator(
        editor,
        runtime_tools_provider=lambda: {
            "search_query": {
                "description": "Search the web.",
                "framework": "langchain",
                "args_schema": {"type": "object", "properties": {"query": {"type": "string"}}},
            }
        },
    )

    candidates = generator.generate_tool_candidates()

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.name == "search_query"
    assert candidate.match_type == "exact_name"
    assert candidate.contract["description"] == "Search the web."
    assert candidate.schema_hash is not None


def test_generate_schema_hash_template_when_multiple_tools_share_schema() -> None:
    shared_schema = {"type": "object", "properties": {"query": {"type": "string"}}}
    editor = _make_editor("schema-template")
    generator = ContractCandidateGenerator(
        editor,
        runtime_tools_provider=lambda: {
            "search_query": {
                "description": "Search the web.",
                "framework": "langchain",
                "args_schema": shared_schema,
            },
            "docs_query": {
                "description": "Search the docs.",
                "framework": "custom",
                "args_schema": shared_schema,
            },
        },
    )

    candidates = generator.generate_tool_candidates()

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.match_type == "argument_schema_hash"
    assert set(candidate.observed_tools) == {"docs_query", "search_query"}
    assert candidate.contract["match"]["argument_schema_hash"] == candidate.schema_hash


def test_skip_runtime_tools_already_covered_by_policy_name_or_schema_hash() -> None:
    shared_schema = {"type": "object", "properties": {"query": {"type": "string"}}}
    policy = {
        "version": "1.0",
        "capabilities": {
            "search_query": {
                "risk": "low",
                "scopes": ["custom"],
                "approval_required": False,
            },
            "query_template": {
                "risk": "low",
                "scopes": ["custom"],
                "approval_required": False,
                "match": {
                    "argument_schema_hash": _schema_hash(shared_schema)
                },
            },
        },
    }
    editor = _make_editor("covered-tools", policy)
    generator = ContractCandidateGenerator(
        editor,
        runtime_tools_provider=lambda: {
            "search_query": {
                "description": "Already exact-covered.",
                "args_schema": shared_schema,
            },
            "docs_query": {
                "description": "Already schema-covered.",
                "args_schema": shared_schema,
            },
            "file_write": {
                "description": "Needs a candidate.",
                "args_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
            },
        },
    )

    candidates = generator.generate_tool_candidates()

    assert [candidate.name for candidate in candidates] == ["file_write"]


def test_write_tool_candidates_persists_json_snapshot() -> None:
    editor = _make_editor("write-snapshot")
    output_path = editor._path.parent / "contract_candidates.json"  # noqa: SLF001
    generator = ContractCandidateGenerator(
        editor,
        runtime_tools_provider=lambda: {
            "search_query": {
                "description": "Search the web.",
                "args_schema": {"type": "object", "properties": {"query": {"type": "string"}}},
            }
        },
    )

    candidates = generator.write_tool_candidates(output_path)
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert len(candidates) == 1
    assert payload[0]["name"] == "search_query"
    assert payload[0]["match_type"] == "exact_name"
