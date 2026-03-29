"""
Shared ASCP configuration loaded from environment variables and .env file.
All components import this module to access centralised settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal
import os
from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()  # Load .env file if present
class ASCPSettings(BaseSettings):
    """Central settings loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_prefix="ASCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Environment
    env: Literal["development", "production", "test"] = "development"
    log_level: str = "INFO"

    # Telemetry
    telemetry_sink: Literal["jsonl", "sqlite", "both"] = "jsonl"
    telemetry_path: Path = Path("logs/telemetry.jsonl")
    db_url: str = "sqlite+aiosqlite:///data/ascp.db"
    observed_registry_path: Path = Path("data/observed_components.json")
    layer_b_event_log_path: Path = Path("data/layer_b_events.jsonl")

    # Policy paths
    policy_path: Path = Path("policy/policies.yaml")
    tool_permissions_path: Path = Path("policy/tool_permissions.yaml")
    schemas_dir: Path = Path("schemas")

    # Workspace
    workspace_path: Path = Path("apps/workspace")

    # OpenAI / LLM
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    llm_model: str = "gpt-4o-mini"
    llm_temperature: float = 0.0
    llm_timeout_seconds: int = 30

    # Rate limiting
    rate_limit: str = "100/minute"

    # Grounding thresholds (can be overridden per-deployment)
    min_grounding_score: float = 0.6
    max_hallucination_risk: float = 0.4

    # Approval workflow
    approval_required_default: bool = True
    unknown_capability_mode: Literal[
        "strict_block",
        "require_approval",
        "sandbox_allow",
        "auto_allow",
        "discover_only",
    ] = "auto_allow"

    # LangWatch
    langwatch_enabled: bool = True
    langwatch_api_key: str = os.getenv("LANGWATCH_KEY", "")
    langwatch_endpoint: str = "https://app.langwatch.ai"
    langwatch_project: str = "layer-b-sdk"
    langwatch_debug: bool = False

    @property
    def is_test(self) -> bool:
        return self.env == "test"


# Module-level singleton — import this everywhere
settings = ASCPSettings()
