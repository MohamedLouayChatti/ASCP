from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from apps.gateway.middleware.pep_tool import ContractDecision, ContractValidator


def _make_validator(
    name: str,
    *,
    unknown_capability_mode: str = "auto_allow",
) -> ContractValidator:
    tmp_path = Path(".pytest_unknown_capability_modes") / f"{name}-{uuid4().hex}"
    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir(parents=True)

    policy_path = tmp_path / "tool_permissions.yaml"
    policy_path.write_text(
        yaml.safe_dump({"version": "1.0", "capabilities": {}}),
        encoding="utf-8",
    )

    return ContractValidator(
        policy_path,
        schemas_dir,
        unknown_capability_mode=unknown_capability_mode,
        langwatch_enabled=False,
    )


def test_unknown_capability_auto_allows_safe_args_by_default() -> None:
    validator = _make_validator("default")

    result = validator.validate_call("unknown_tool", {"query": "hello"})

    assert result.decision == ContractDecision.ALLOW
    assert result.reason_code == "UNKNOWN_CAPABILITY_SANDBOX_ALLOWED"
    assert result.sanitized_args == {"query": "hello"}


def test_unknown_capability_can_be_strictly_blocked() -> None:
    validator = _make_validator("strict-block", unknown_capability_mode="strict_block")

    result = validator.validate_call("unknown_tool", {"query": "hello"})

    assert result.decision == ContractDecision.BLOCK
    assert result.reason_code == "UNKNOWN_CAPABILITY_BLOCKED"


def test_unknown_capability_can_be_allowed_in_sandbox_mode() -> None:
    validator = _make_validator("sandbox-allow", unknown_capability_mode="sandbox_allow")

    result = validator.validate_call("unknown_tool", {"query": "hello"})

    assert result.decision == ContractDecision.ALLOW
    assert result.reason_code == "UNKNOWN_CAPABILITY_SANDBOX_ALLOWED"
    assert result.sanitized_args == {"query": "hello"}


def test_unknown_capability_auto_allow_alias_maps_to_sandbox_allow() -> None:
    validator = _make_validator("auto-allow", unknown_capability_mode="auto_allow")

    result = validator.validate_call("unknown_tool", {"query": "hello"})

    assert result.decision == ContractDecision.ALLOW
    assert result.reason_code == "UNKNOWN_CAPABILITY_SANDBOX_ALLOWED"
    assert result.sanitized_args == {"query": "hello"}


def test_unknown_capability_can_be_allowed_in_discover_only_mode() -> None:
    validator = _make_validator("discover-only", unknown_capability_mode="discover_only")

    result = validator.validate_call("unknown_tool", {"query": "hello"})

    assert result.decision == ContractDecision.ALLOW
    assert result.reason_code == "UNKNOWN_CAPABILITY_DISCOVERED"
    assert result.sanitized_args == {"query": "hello"}


def test_unknown_capability_blocks_path_traversal_before_mode_allow() -> None:
    validator = _make_validator("path-traversal", unknown_capability_mode="sandbox_allow")

    result = validator.validate_call("unknown_tool", {"path": "../secrets.txt"})

    assert result.decision == ContractDecision.BLOCK
    assert result.reason_code == "PATH_TRAVERSAL"


def test_unknown_capability_blocks_ssrf_style_url_before_mode_allow() -> None:
    validator = _make_validator("ssrf", unknown_capability_mode="discover_only")

    result = validator.validate_call("unknown_tool", {"url": "http://169.254.169.254/latest/meta-data"})

    assert result.decision == ContractDecision.BLOCK
    assert result.reason_code == "DOMAIN_POLICY_VIOLATION"


def test_unknown_capability_blocks_unsafe_sql_before_mode_allow() -> None:
    validator = _make_validator("sql", unknown_capability_mode="sandbox_allow")

    result = validator.validate_call("unknown_tool", {"sql": "DROP TABLE users"})

    assert result.decision == ContractDecision.BLOCK
    assert result.reason_code == "SQL_POLICY_VIOLATION"


def test_unknown_capability_blocks_large_body_before_mode_allow() -> None:
    validator = _make_validator("large-body", unknown_capability_mode="discover_only")

    result = validator.validate_call("unknown_tool", {"body": "x" * 4001})

    assert result.decision == ContractDecision.BLOCK
    assert result.reason_code == "CONTENT_TOO_LARGE"


def test_dangerous_unknown_args_escalate_sandbox_allow_to_require_approval() -> None:
    validator = _make_validator("dangerous-sandbox", unknown_capability_mode="sandbox_allow")

    result = validator.validate_call("unknown_tool", {"command": "ls"})

    assert result.decision == ContractDecision.REQUIRE_APPROVAL
    assert result.reason_code == "APPROVAL_REQUIRED"
    assert result.approval_token


def test_dangerous_unknown_args_escalate_discover_only_to_require_approval() -> None:
    validator = _make_validator("dangerous-discover", unknown_capability_mode="discover_only")

    result = validator.validate_call("unknown_tool", {"script": "print('hi')"})

    assert result.decision == ContractDecision.REQUIRE_APPROVAL
    assert result.reason_code == "APPROVAL_REQUIRED"
    assert result.approval_token


def test_dangerous_unknown_args_can_proceed_after_approval_in_sandbox_allow_mode() -> None:
    validator = _make_validator("dangerous-approved", unknown_capability_mode="sandbox_allow")

    approval = validator.validate_call("unknown_tool", {"command": "ls"})
    result = validator.validate_call(
        "unknown_tool",
        {"command": "ls"},
        approval_token=approval.approval_token,
    )

    assert approval.decision == ContractDecision.REQUIRE_APPROVAL
    assert result.decision == ContractDecision.ALLOW
    assert result.reason_code == "UNKNOWN_CAPABILITY_SANDBOX_ALLOWED"


def test_unknown_capability_approval_token_round_trip_still_works() -> None:
    validator = _make_validator("approval-round-trip", unknown_capability_mode="require_approval")

    approval = validator.validate_call("unknown_tool", {"query": "hello"})
    result = validator.validate_call(
        "unknown_tool",
        {"query": "hello"},
        approval_token=approval.approval_token,
    )

    assert approval.decision == ContractDecision.REQUIRE_APPROVAL
    assert result.decision == ContractDecision.ALLOW
    assert result.reason_code == "UNREGISTERED_TOOL_APPROVED"


def test_invalid_unknown_capability_mode_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown_capability_mode"):
        _make_validator("invalid-mode", unknown_capability_mode="not-a-mode")
