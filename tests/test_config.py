from __future__ import annotations

from pathlib import Path

import pytest

from apps.config import ASCPSettings


def test_settings_use_default_values() -> None:
    """Verifies baseline defaults are loaded when no env vars are provided."""
    settings = ASCPSettings()

    assert settings.env == "development"
    assert settings.log_level == "INFO"
    assert settings.telemetry_path == Path("logs/telemetry.jsonl")
    assert settings.is_test is False


def test_settings_read_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensures ASCP_ prefixed environment variables override default settings."""
    monkeypatch.setenv("ASCP_ENV", "test")
    monkeypatch.setenv("ASCP_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("ASCP_RATE_LIMIT", "10/minute")

    settings = ASCPSettings()

    assert settings.env == "test"
    assert settings.log_level == "DEBUG"
    assert settings.rate_limit == "10/minute"
    assert settings.is_test is True
