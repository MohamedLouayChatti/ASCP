from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from apps.gateway.middleware.pep_tool import ContractDecision, ContractValidator


def _make_validator(
    name: str,
    *,
    unknown_capability_mode: str = "require_approval",
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


def test_unknown_capability_requires_approval_by_default() -> None:
    validator = _make_validator("default")

    result = validator.validate_call("unknown_tool", {"query": "hello"})

    assert result.decision == ContractDecision.REQUIRE_APPROVAL
    assert result.reason_code == "APPROVAL_REQUIRED"
    assert result.approval_token


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


def test_unknown_capability_can_be_allowed_in_discover_only_mode() -> None:
    validator = _make_validator("discover-only", unknown_capability_mode="discover_only")

    result = validator.validate_call("unknown_tool", {"query": "hello"})

    assert result.decision == ContractDecision.ALLOW
    assert result.reason_code == "UNKNOWN_CAPABILITY_DISCOVERED"
    assert result.sanitized_args == {"query": "hello"}


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
