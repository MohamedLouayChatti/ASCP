import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

from .models import DLPAction


@dataclass
class PatternDef:
    name: str
    regex: str


@dataclass
class DLPConfig:
    canary_action: DLPAction
    canary_salt: str
    secrets_action: DLPAction
    pii_action: DLPAction
    enable_ner: bool
    secret_patterns: list[PatternDef] = field(default_factory=list)
    pii_patterns: list[PatternDef] = field(default_factory=list)
    canary_labels: list[str] = field(default_factory=lambda: ["api_credential_mock", "db_password", "sys_admin_token"])

    @classmethod
    def defaults(cls) -> "DLPConfig":
        """Safe defaults for when a policy file is not provided (e.g., in tests)."""
        return cls(
            canary_action=DLPAction.BLOCK,
            canary_salt="default_insecure_salt_replace_in_prod",
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
            canary_labels=["api_credential_mock", "db_password", "sys_admin_token"]
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

    with open(policy_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

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
        logging.critical("Both secret_patterns and pii_patterns are empty in the DLP config. The scanner will not catch any regex-based violations.")

    return DLPConfig(
        canary_action=_parse_action(dlp_data.get("canary_action", "BLOCK")),
        canary_salt=dlp_data.get("canary_salt", "default_insecure_salt_replace_in_prod"),
        secrets_action=_parse_action(dlp_data.get("secrets_action", "BLOCK")),
        pii_action=_parse_action(dlp_data.get("pii_action", "REDACT")),
        enable_ner=dlp_data.get("enable_ner", False),
        secret_patterns=secret_patterns,
        pii_patterns=pii_patterns,
        canary_labels=dlp_data.get("canary_labels", ["api_credential_mock", "db_password", "sys_admin_token"])
    )
