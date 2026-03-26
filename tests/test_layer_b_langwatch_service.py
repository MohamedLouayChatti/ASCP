from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from dotenv import load_dotenv

from apps.gateway.middleware.pep_tool import ContractDecision, ContractValidator


def test_real_langwatch_service_smoke(tmp_path: Path) -> None:
    """Uses real LangWatch SDK path when LANGWATCH_KEY is available in environment/.env."""
    load_dotenv()
    api_key = os.getenv("LANGWATCH_KEY") or os.getenv("LANGWATCH_API_KEY")
    if not api_key:
        pytest.skip("LANGWATCH_KEY not configured")

    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir(parents=True)

    (schemas_dir / "demo.schema.json").write_text(
        json.dumps(
            {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            }
        ),
        encoding="utf-8",
    )

    policy = {
        "version": "1.0",
        "capabilities": {
            "demo_tool": {
                "risk": "low",
                "scopes": ["read_only"],
                "approval_required": False,
                "schema": "schemas/demo.schema.json",
                "constraints": {},
            }
        },
    }

    policy_path = tmp_path / "tool_permissions.yaml"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    validator = ContractValidator(
        policy_path,
        schemas_dir,
        langwatch_enabled=True,
        langwatch_api_key=api_key,
        langwatch_endpoint=os.getenv("LANGWATCH_ENDPOINT"),
        langwatch_project=os.getenv("LANGWATCH_PROJECT", "ascp"),
        langwatch_debug=str(os.getenv("LANGWATCH_DEBUG", "")).lower() in {"1", "true", "yes", "on"},
    )

    result = validator.validate_call(
        "unknown_tool",
        {"query": "hello"},
        agent_id="langwatch-smoke",
        framework="pytest",
    )

    # If this decision succeeds, LangWatch emission path executed without breaking enforcement.
    assert result.decision == ContractDecision.REQUIRE_APPROVAL
    assert result.reason_code == "APPROVAL_REQUIRED"
