from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from apps.gateway.middleware.pep_tool import (
    ContractDecision,
    ContractValidator,
    PolicyValidationError,
)


def _make_validator(
    name: str,
    *,
    policy: dict[str, object] | None = None,
    base_policy: dict[str, object] | None = None,
    unknown_capability_mode: str = "sandbox_allow",
) -> ContractValidator:
    tmp_path = Path(".pytest_inferred_family_matching") / f"{name}-{uuid4().hex}"
    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir(parents=True)

    policy_path = tmp_path / "tool_permissions.yaml"
    policy_path.write_text(
        yaml.safe_dump(policy or {"version": "1.0", "capabilities": {}}),
        encoding="utf-8",
    )

    base_policy_path = None
    if base_policy is not None:
        base_policy_path = tmp_path / "default_tool_permissions.yaml"
        base_policy_path.write_text(yaml.safe_dump(base_policy), encoding="utf-8")

    return ContractValidator(
        policy_path,
        schemas_dir,
        base_policy_path=base_policy_path,
        unknown_capability_mode=unknown_capability_mode,
        langwatch_enabled=False,
    )


def test_inferred_file_read_family_applies_to_unknown_tool() -> None:
    validator = _make_validator(
        "file-read-family",
        base_policy={
            "version": "1.0",
            "capabilities": {
                "default_file_read_family": {
                    "risk": "medium",
                    "scopes": ["local_fs"],
                    "approval_required": False,
                    "match": {"inferred_family": "file_read"},
                    "constraints": {"deny_path_traversal": True},
                }
            },
        },
    )

    result = validator.validate_call("project_reader", {"path": "README.md"})

    assert result.decision == ContractDecision.ALLOW
    assert result.reason_code == "ALLOWED"


def test_inferred_file_read_family_still_blocks_path_traversal() -> None:
    validator = _make_validator(
        "file-read-traversal",
        base_policy={
            "version": "1.0",
            "capabilities": {
                "default_file_read_family": {
                    "risk": "medium",
                    "scopes": ["local_fs"],
                    "approval_required": False,
                    "match": {"inferred_family": "file_read"},
                    "constraints": {"deny_path_traversal": True},
                }
            },
        },
    )

    result = validator.validate_call("project_reader", {"path": "../secrets.txt"})

    assert result.decision == ContractDecision.BLOCK
    assert result.reason_code == "PATH_TRAVERSAL"


def test_exact_name_contract_beats_inferred_family_default() -> None:
    validator = _make_validator(
        "exact-name-priority",
        policy={
            "version": "1.0",
            "capabilities": {
                "project_reader": {
                    "risk": "high",
                    "scopes": ["local_fs"],
                    "approval_required": True,
                }
            },
        },
        base_policy={
            "version": "1.0",
            "capabilities": {
                "default_file_read_family": {
                    "risk": "medium",
                    "scopes": ["local_fs"],
                    "approval_required": False,
                    "match": {"inferred_family": "file_read"},
                }
            },
        },
    )

    result = validator.validate_call("project_reader", {"path": "README.md"})

    assert result.decision == ContractDecision.REQUIRE_APPROVAL
    assert result.reason_code == "APPROVAL_REQUIRED"


def test_base_policy_and_project_policy_are_merged() -> None:
    validator = _make_validator(
        "policy-merge",
        policy={
            "version": "1.0",
            "capabilities": {
                "custom_query": {
                    "risk": "high",
                    "scopes": ["read_only"],
                    "approval_required": True,
                }
            },
        },
        base_policy={
            "version": "1.0",
            "capabilities": {
                "default_db_query_family": {
                    "risk": "medium",
                    "scopes": ["read_only"],
                    "approval_required": True,
                    "match": {"inferred_family": "db_query"},
                    "constraints": {"sql_mode": "select_only"},
                }
            },
        },
    )

    inferred = validator.validate_call("run_query", {"sql": "SELECT 1"})
    exact = validator.validate_call("custom_query", {"sql": "SELECT 1"})

    assert inferred.decision == ContractDecision.REQUIRE_APPROVAL
    assert exact.decision == ContractDecision.REQUIRE_APPROVAL
    assert set(validator.list_capabilities()) == {"custom_query", "default_db_query_family"}


def test_duplicate_inferred_family_matches_are_rejected() -> None:
    with pytest.raises(PolicyValidationError, match="inferred family matches must be unique"):
        _make_validator(
            "duplicate-family",
            policy={
                "version": "1.0",
                "capabilities": {
                    "family_a": {
                        "risk": "low",
                        "scopes": ["custom"],
                        "approval_required": False,
                        "match": {"inferred_family": "file_read"},
                    },
                    "family_b": {
                        "risk": "low",
                        "scopes": ["custom"],
                        "approval_required": False,
                        "match": {"inferred_family": "file_read"},
                    },
                },
            },
        )
