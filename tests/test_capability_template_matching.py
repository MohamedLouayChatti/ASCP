from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from apps.gateway.middleware.pep_tool import (
    ContractDecision,
    ContractValidator,
    PolicyValidationError,
)


def _schema_hash(schema: dict[str, object]) -> str:
    payload = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _make_validator(
    name: str,
    policy: dict[str, object],
    *,
    unknown_capability_mode: str = "require_approval",
) -> ContractValidator:
    tmp_path = Path(".pytest_capability_template_matching") / f"{name}-{uuid4().hex}"
    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir(parents=True)

    policy_path = tmp_path / "tool_permissions.yaml"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    return ContractValidator(
        policy_path,
        schemas_dir,
        unknown_capability_mode=unknown_capability_mode,
        langwatch_enabled=False,
    )


def test_exact_name_match_wins_over_schema_hash_and_default() -> None:
    schema = {
        "type": "object",
        "properties": {"query": {"type": "string"}},
    }
    validator = _make_validator(
        "exact-name-priority",
        {
            "version": "1.0",
            "capabilities": {
                "search_query": {
                    "risk": "low",
                    "scopes": ["custom"],
                    "approval_required": False,
                },
                "structured_template": {
                    "risk": "high",
                    "scopes": ["custom"],
                    "approval_required": True,
                    "match": {"argument_schema_hash": _schema_hash(schema)},
                },
                "default_template": {
                    "risk": "high",
                    "scopes": ["custom"],
                    "approval_required": True,
                    "match": {"catch_all": True},
                },
            },
        },
    )

    result = validator.validate_call(
        "search_query",
        {"query": "hello"},
        invocation_context={"args_schema": schema},
    )

    assert result.decision == ContractDecision.ALLOW
    assert result.reason_code == "ALLOWED"


def test_argument_schema_hash_match_beats_catch_all_default() -> None:
    schema = {
        "type": "object",
        "properties": {"url": {"type": "string"}},
    }
    validator = _make_validator(
        "schema-hash-priority",
        {
            "version": "1.0",
            "capabilities": {
                "http_template": {
                    "risk": "low",
                    "scopes": ["custom"],
                    "approval_required": False,
                    "match": {"argument_schema_hash": _schema_hash(schema)},
                },
                "default_template": {
                    "risk": "high",
                    "scopes": ["custom"],
                    "approval_required": True,
                    "match": {"catch_all": True},
                },
            },
        },
    )

    result = validator.validate_call(
        "third_party_http_tool",
        {"url": "https://example.com"},
        invocation_context={"args_schema": schema},
    )

    assert result.decision == ContractDecision.ALLOW
    assert result.reason_code == "ALLOWED"


def test_catch_all_default_applies_before_unknown_capability_mode() -> None:
    validator = _make_validator(
        "catch-all-default",
        {
            "version": "1.0",
            "capabilities": {
                "default_template": {
                    "risk": "high",
                    "scopes": ["custom"],
                    "approval_required": True,
                    "match": {"catch_all": True},
                }
            },
        },
        unknown_capability_mode="sandbox_allow",
    )

    result = validator.validate_call("unknown_tool", {"query": "hello"})

    assert result.decision == ContractDecision.REQUIRE_APPROVAL
    assert result.reason_code == "APPROVAL_REQUIRED"
    assert result.approval_token


def test_duplicate_argument_schema_hash_matches_are_rejected() -> None:
    schema = {
        "type": "object",
        "properties": {"query": {"type": "string"}},
    }
    policy = {
        "version": "1.0",
        "capabilities": {
            "template_a": {
                "risk": "low",
                "scopes": ["custom"],
                "approval_required": False,
                "match": {"argument_schema_hash": _schema_hash(schema)},
            },
            "template_b": {
                "risk": "low",
                "scopes": ["custom"],
                "approval_required": False,
                "match": {"argument_schema_hash": _schema_hash(schema)},
            },
        },
    }

    with pytest.raises(PolicyValidationError, match="schema hash matches must be unique"):
        _make_validator("duplicate-schema-hash", policy)


def test_multiple_catch_all_matches_are_rejected() -> None:
    policy = {
        "version": "1.0",
        "capabilities": {
            "default_a": {
                "risk": "low",
                "scopes": ["custom"],
                "approval_required": False,
                "match": {"catch_all": True},
            },
            "default_b": {
                "risk": "low",
                "scopes": ["custom"],
                "approval_required": False,
                "match": {"catch_all": True},
            },
        },
    }

    with pytest.raises(PolicyValidationError, match="Only one catch-all capability is allowed"):
        _make_validator("duplicate-catch-all", policy)
