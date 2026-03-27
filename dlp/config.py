import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

from .models import DLPAction


@dataclass
class PatternDef:
    name: str
    regex: str


_DEFAULT_SURFACE_OVERRIDES: dict[str, dict[str, str]] = {
    # On TOOL_ARGS, secrets always escalate to BLOCK regardless of global secrets_action.
    "tool_args": {"secrets_action": "block"},
    # On TOOL_RESULT, downgrade a pure-PII ESCALATE to REDACT (no canary/secret involved).
    "tool_result": {"downgrade_escalate_to_redact": "true"},
}

_DEFAULT_CONTENT_KEYS: list[str] = ["text", "content", "body", "page_content", "chunk"]

_DEFAULT_SALT = "default_insecure_salt_replace_in_prod"


@dataclass
class DLPConfig:
    canary_action: DLPAction
    canary_salt: str
    secrets_action: DLPAction
    pii_action: DLPAction
    enable_ner: bool
    secret_patterns: list[PatternDef] = field(default_factory=list)
    pii_patterns: list[PatternDef] = field(default_factory=list)
    canary_labels: list[str] = field(
        default_factory=lambda: ["api_credential_mock", "db_password", "sys_admin_token"]
    )
    # Ordered list of document keys tried when injecting canaries.
    # Falls back to "_canary" only if none of these keys are present.
    content_keys: list[str] = field(default_factory=lambda: list(_DEFAULT_CONTENT_KEYS))
    # Per-surface enforcement overrides. Keys are surface names in lower-snake-case
    # ("output", "tool_args", "tool_result"). Supported inner keys:
    #   secrets_action / pii_action / canary_action  : DLPAction name string (e.g. "block")
    #   downgrade_escalate_to_redact                 : "true" | "false"
    surface_overrides: dict[str, dict[str, str]] = field(default_factory=dict)

    @classmethod
    def defaults(cls) -> "DLPConfig":
        """Safe defaults for when a policy file is not provided (e.g., in tests)."""
        return cls(
            canary_action=DLPAction.BLOCK,
            canary_salt=_DEFAULT_SALT,
            secrets_action=DLPAction.BLOCK,
            pii_action=DLPAction.REDACT,
            enable_ner=False,
            secret_patterns=[
                PatternDef(name="openai_key", regex=r"sk-[A-Za-z0-9]{48}"),
                PatternDef(name="aws_access_key", regex=r"AKIA[0-9A-Z]{16}"),
                PatternDef(name="github_token", regex=r"ghp_[A-Za-z0-9]{36}"),
            ],
            pii_patterns=[
                PatternDef(name="email", regex=r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]"),
                PatternDef(name="ipv4", regex=r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            ],
            canary_labels=["api_credential_mock", "db_password", "sys_admin_token"],
            content_keys=list(_DEFAULT_CONTENT_KEYS),
            surface_overrides=dict(_DEFAULT_SURFACE_OVERRIDES),
        )


def _parse_action(action_str: str) -> DLPAction:
    try:
        return DLPAction[action_str.upper()]
    except KeyError:
        return DLPAction.ALLOW


def load_dlp_config(policy_path: Path) -> DLPConfig:
    """Loads the DLP configuration from a YAML policy file."""
    if not policy_path.exists():
        return DLPConfig.defaults()

    try:
        import yaml
    except ImportError:
        logging.critical("PyYAML is not installed. Loading defaults.")
        return DLPConfig.defaults()

    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (yaml.YAMLError, IOError) as e:
        logging.critical(f"Failed to parse YAML policy file: {e}. Loading defaults.")
        return DLPConfig.defaults()

    if not data or "dlp" not in data:
        return DLPConfig.defaults()

    dlp_data = data["dlp"]

    secret_patterns = [
        PatternDef(name=p.get("name", "unknown"), regex=p.get("regex", ""))
        for p in dlp_data.get("secret_patterns", [])
    ]

    pii_patterns = [
        PatternDef(name=p.get("name", "unknown"), regex=p.get("regex", ""))
        for p in dlp_data.get("pii_patterns", [])
    ]

    if not secret_patterns and not pii_patterns:
        logging.critical(
            "Both secret_patterns and pii_patterns are empty in the DLP config. "
            "The scanner will not catch any regex-based violations."
        )

    canary_salt = dlp_data.get("canary_salt", _DEFAULT_SALT)
    if canary_salt in (_DEFAULT_SALT, "changeme"):
        logging.warning(
            "SECURITY: canary_salt is set to the default insecure value '%s'. "
            "Replace it with a cryptographically random string before deploying to production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"",
            canary_salt,
        )

    # Parse surface_overrides. Missing entries fall back to the module defaults so that
    # operators only need to specify what they want to change.
    raw_overrides = dlp_data.get("surface_overrides", {})
    surface_overrides: dict[str, dict[str, str]] = dict(_DEFAULT_SURFACE_OVERRIDES)
    for surface_name, overrides in raw_overrides.items():
        if overrides:
            surface_overrides[surface_name.lower()] = {
                k: str(v) for k, v in overrides.items()
            }

    return DLPConfig(
        canary_action=_parse_action(dlp_data.get("canary_action", "BLOCK")),
        canary_salt=canary_salt,
        secrets_action=_parse_action(dlp_data.get("secrets_action", "BLOCK")),
        pii_action=_parse_action(dlp_data.get("pii_action", "REDACT")),
        enable_ner=dlp_data.get("enable_ner", False),
        secret_patterns=secret_patterns,
        pii_patterns=pii_patterns,
        canary_labels=dlp_data.get(
            "canary_labels", ["api_credential_mock", "db_password", "sys_admin_token"]
        ),
        content_keys=dlp_data.get("content_keys", list(_DEFAULT_CONTENT_KEYS)),
        surface_overrides=surface_overrides,
    )
