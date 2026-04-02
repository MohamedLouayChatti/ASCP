from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import layerb
import layerb.engine as layerb_engine
from layerb import ContractDecision, LayerBEngine


class DummyValidator:
    def __init__(self) -> None:
        self._capability_sequences = {
            "workflows": {
                "safe_flow": {
                    "entry": ["file_read"],
                    "allowed_next": {"file_read": ["web_fetch"]},
                }
            },
            "transition_graph": {"file_read": ["web_fetch"]},
        }

    def list_capabilities(self) -> list[str]:
        return ["file_read", "web_fetch"]

    def get_capability_contract(self, capability_name: str) -> dict[str, Any]:
        return {
            "risk": "low",
            "scopes": ["read_only"],
            "approval_required": False,
            "constraints": {"max_bytes": 1024},
        }

    def get_capability_schema(self, capability_name: str) -> dict[str, Any]:
        return {"type": "object", "properties": {"path": {"type": "string"}}}

    def validate_capability_call(self, capability_name: str, arguments: dict[str, Any], **_: Any):
        return layerb_engine.ContractResult(
            decision=ContractDecision.ALLOW,
            tool_name=capability_name,
            reason_code="ok",
            details="validated",
            violations=[],
            approval_token=None,
            sanitized_args=arguments,
        )


def test_load_json_uses_default_when_missing() -> None:
    """Confirms helper returns the provided default when CLI arg is absent."""
    default_value = {"k": "v"}
    assert layerb_engine._load_json(None, default_value) == default_value


def test_load_json_parses_valid_json() -> None:
    """Confirms helper parses JSON payload strings used by CLI flags."""
    parsed = layerb_engine._load_json('{"a": 1, "b": [2]}', {})
    assert parsed == {"a": 1, "b": [2]}


def test_engine_inspection_and_explain_decision() -> None:
    """Validates inspection payload shape and decision explanation mapping."""
    engine = LayerBEngine(validator=DummyValidator(), agent_id="test-agent", framework="pytest")

    capability = engine.inspect_capability("file_read")
    assert capability["capability"] == "file_read"
    assert capability["risk"] == "low"
    assert capability["schema"]["type"] == "object"

    workflow = engine.inspect_workflow("safe_flow")
    assert workflow["workflow"] == "safe_flow"
    assert workflow["sequence_policy"]["entry"] == ["file_read"]

    decision = engine.explain_decision("file_read", {"path": "README.md"})
    assert decision["decision"] == ContractDecision.ALLOW
    assert decision["reason_code"] == "ok"
    assert decision["sanitized_args"] == {"path": "README.md"}


def test_engine_uses_policy_loader_when_validator_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensures constructor can be tested without real policy/schema files by stubbing loader."""
    dummy = DummyValidator()

    def fake_load(self: layerb_engine.LayerBPolicy) -> DummyValidator:
        return dummy

    monkeypatch.setattr(layerb_engine.LayerBPolicy, "load", fake_load)

    engine = LayerBEngine(validator=None)
    assert engine.validator is dummy
    assert engine.list_capabilities() == ["file_read", "web_fetch"]


def test_validate_capability_passes_default_identity() -> None:
    """Verifies engine forwards default agent/framework identity into validator call."""

    class CapturingValidator(DummyValidator):
        def __init__(self) -> None:
            super().__init__()
            self.last_kwargs: dict[str, Any] = {}

        def validate_capability_call(
            self,
            capability_name: str,
            arguments: dict[str, Any],
            **kwargs: Any,
        ):
            self.last_kwargs = kwargs
            return super().validate_capability_call(capability_name, arguments, **kwargs)

    validator = CapturingValidator()
    engine = LayerBEngine(validator=validator, agent_id="default-agent", framework="layer-b-test")

    result = engine.validate_capability("file_read", {"path": "README.md"})

    assert result.decision == ContractDecision.ALLOW
    assert validator.last_kwargs["agent_id"] == "default-agent"
    assert validator.last_kwargs["framework"] == "layer-b-test"


def test_validate_capability_allows_identity_override() -> None:
    """Verifies per-call agent/framework overrides are forwarded to validator."""

    class CapturingValidator(DummyValidator):
        def __init__(self) -> None:
            super().__init__()
            self.last_kwargs: dict[str, Any] = {}

        def validate_capability_call(
            self,
            capability_name: str,
            arguments: dict[str, Any],
            **kwargs: Any,
        ):
            self.last_kwargs = kwargs
            return super().validate_capability_call(capability_name, arguments, **kwargs)

    validator = CapturingValidator()
    engine = LayerBEngine(validator=validator, agent_id="default-agent", framework="default-fw")

    engine.validate_capability(
        "file_read",
        {"path": "README.md"},
        agent_id="override-agent",
        framework="override-fw",
    )

    assert validator.last_kwargs["agent_id"] == "override-agent"
    assert validator.last_kwargs["framework"] == "override-fw"


def test_engine_describe_paths_exposes_sdk_event_log_path() -> None:
    engine = LayerBEngine(
        validator=DummyValidator(),
        event_log_path="logs/custom/layer_b_events.jsonl",
    )

    paths = engine.describe_paths()

    assert Path(paths["event_log_path"]) == Path("logs/custom/layer_b_events.jsonl")


def test_sdk_package_exposes_bundled_default_paths() -> None:
    engine = layerb.LayerBEngine(validator=DummyValidator())

    paths = engine.describe_paths()

    assert Path(paths["base_policy_path"]).name == "default_tool_permissions.yaml"
    assert Path(paths["schemas_dir"]).name == "schemas"

