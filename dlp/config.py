import re
import logging
from pathlib import Path
from dataclasses import dataclass, field

from .models import DLPAction


@dataclass
class PatternDef:
    name: str
    regex: str
    action: DLPAction | None = None
    flags: int = 0  # re.compile flags, e.g. re.MULTILINE


_DEFAULT_SURFACE_OVERRIDES: dict[str, dict[str, str]] = {
    "tool_args": {"secrets_action": "block"},
    "tool_result": {"downgrade_escalate_to_redact": "true"},
}

_DEFAULT_CONTENT_KEYS: list[str] = ["text", "content", "body", "page_content", "chunk"]
_DEFAULT_SALT = "default_insecure_salt_replace_in_prod"

_DEFAULT_CONTEXT_TRIGGERS: list[str] = [
    "my", "our", "here is", "use", "actual", "secret", "real", "paste",
]
_DEFAULT_CONTEXT_NEGATIONS: list[str] = [
    "example", "format", "test", "fake", "sample", "dummy", "placeholder",
    "documentation", "like", "similar",
]


@dataclass
class DLPConfig:
    # ── Core ─────────────────────────────────────────────────────────────────
    canary_action: DLPAction
    canary_salt: str
    secrets_action: DLPAction
    pii_action: DLPAction
    unmatched_action: DLPAction
    secret_patterns: list[PatternDef] = field(default_factory=list)
    pii_patterns: list[PatternDef] = field(default_factory=list)
    canary_labels: list[str] = field(
        default_factory=lambda: ["api_credential_mock", "db_password", "sys_admin_token"]
    )
    content_keys: list[str] = field(default_factory=lambda: list(_DEFAULT_CONTENT_KEYS))
    surface_overrides: dict[str, dict[str, str]] = field(default_factory=dict)

    # ── Luhn validation ───────────────────────────────────────────────────────
    enable_luhn_validation: bool = False

    # ── Contextual window analysis ────────────────────────────────────────────
    enable_context_analysis: bool = False
    context_window: int = 50
    context_trigger_words: list[str] = field(
        default_factory=lambda: list(_DEFAULT_CONTEXT_TRIGGERS)
    )
    context_negation_words: list[str] = field(
        default_factory=lambda: list(_DEFAULT_CONTEXT_NEGATIONS)
    )
    context_on_negation: str = "downgrade"   # "downgrade" | "suppress"

    # ── Format-preserving redaction ───────────────────────────────────────────
    format_preserving_redaction: bool = False

    # ── Fuzzy canary matching ─────────────────────────────────────────────────
    canary_fuzzy_match: bool = False
    canary_fuzzy_overlap: float = 0.8

    # ── ML Inference ──────────────────────────────────────────────────────────
    # Base model must match what was used in training (google/gemma-2-2b-it).
    # Downloaded automatically from HuggingFace on first run (~1.5 GB).
    ml_base_model: str = "google/gemma-2-2b-it"
    # Path to the LoRA adapter folder.  None = use the bundled dlp_lora_package/.
    ml_lora_path: str | None = None

    @classmethod
    def defaults(cls) -> "DLPConfig":
        """Safe defaults used when no policy file is provided."""
        return cls(
            canary_action=DLPAction.BLOCK,
            canary_salt=_DEFAULT_SALT,
            secrets_action=DLPAction.BLOCK,
            pii_action=DLPAction.REDACT,
            unmatched_action=DLPAction.PASS_TO_ML,
            secret_patterns=[
                PatternDef(name="openai_key",    regex=r"sk-[A-Za-z0-9]{20,}", action=DLPAction.BLOCK),
                PatternDef(name="anthropic_key", regex=r"sk-ant-[A-Za-z0-9-]{20,}", action=DLPAction.BLOCK),
                PatternDef(name="stripe_key",    regex=r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}", action=DLPAction.BLOCK),
                PatternDef(name="aws_access_key", regex=r"(?i)(?:aws|access[_-]?key)[\s:='\&quot;]{0,5}(AKIA[0-9A-Z]{16})", action=DLPAction.BLOCK),
                PatternDef(name="github_token",  regex=r"(?:gh[ps]_|github_pat_)[A-Za-z0-9_]+", action=DLPAction.BLOCK),
                PatternDef(name="slack_token",   regex=r"xox[baprs]-[0-9]+-[0-9]+-[A-Za-z0-9_]+", action=DLPAction.BLOCK),
                PatternDef(name="google_api_key", regex=r"AIza[0-9A-Za-z_-]{35}", action=DLPAction.BLOCK),
                PatternDef(name="sendgrid_key",  regex=r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", action=DLPAction.BLOCK),
                PatternDef(name="twilio_sid",    regex=r"AC[a-z0-9]{32}", action=DLPAction.BLOCK),
                PatternDef(name="digitalocean_token", regex=r"dop_v1_[a-f0-9]{64}", action=DLPAction.BLOCK),
                PatternDef(name="generic_api_key", regex=r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token)[\s:='\&quot;]{0,5}[a-zA-Z0-9+/_-]{32,64}={0,2}", action=DLPAction.PASS_TO_ML),
                PatternDef(name="secret",        regex=r"(?i)(secret|client_secret)[\s:='\&quot;]{0,5}[a-zA-Z0-9+/_-]{8,}", action=DLPAction.PASS_TO_ML),
                PatternDef(name="bearer_token",  regex=r"(?i)(bearer\s+[a-zA-Z0-9\-._~+/]+=*)", action=DLPAction.BLOCK),
                PatternDef(name="db_connection_string", regex=r"(?i)(postgres|mysql|mongodb|redis|amqp|jdbc):\/\/[^:\s]+:[^@\s]+@[^\/\s]+\/[^\s]+", action=DLPAction.BLOCK),
                PatternDef(name="jdbc_connection_string", regex=r"jdbc:[a-z]+:\/\/[^\s]+", action=DLPAction.BLOCK),
                PatternDef(name="mongodb_srv",   regex=r"mongodb\+srv:\/\/[^:\s]+:[^@\s]+@[^\/\s]+", action=DLPAction.BLOCK),
                PatternDef(name="private_key",   regex=r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----", action=DLPAction.BLOCK),
                PatternDef(name="env_secrets",   regex=r"(?i)(API_KEY|SECRET_KEY|ACCESS_TOKEN|DB_PASSWORD|PRIVATE_KEY)[\s:='\&quot;]{0,5}[^\s'\&quot;]{8,}", action=DLPAction.BLOCK),
                PatternDef(name="env_style",     regex=r"^[A-Z_]+=(?!.*(example|test|dummy)).+", action=DLPAction.PASS_TO_ML, flags=re.MULTILINE),
                PatternDef(name="high_entropy_token", regex=r"\b[a-zA-Z0-9_\-]{32,}\b", action=DLPAction.PASS_TO_ML),
            ],
            pii_patterns=[
                PatternDef(
                    name="email",
                    regex=r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]",
                    action=DLPAction.PASS_TO_ML,
                ),
                PatternDef(
                    name="phone",
                    regex=r"\+?[1-9]\d{1,3}[-.\s]?\(?\d+\)?[-.\s]?\d+[-.\s]?\d+",
                    action=DLPAction.PASS_TO_ML,
                ),
                PatternDef(
                    name="ipv4",
                    regex=r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                    action=DLPAction.PASS_TO_ML,
                ),
                PatternDef(
                    name="ssn",
                    regex=r"\b\d{3}-\d{2}-\d{4}\b",
                    action=DLPAction.REDACT,
                ),
                # Credit card — enabled by default; Luhn validation removes false positives
                PatternDef(
                    name="credit_card",
                    regex=(
                        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}"
                        r"|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
                    ),
                    action=DLPAction.REDACT,
                ),
            ],
            canary_labels=["api_credential_mock", "db_password", "sys_admin_token"],
            content_keys=list(_DEFAULT_CONTENT_KEYS),
            surface_overrides={k: dict(v) for k, v in _DEFAULT_SURFACE_OVERRIDES.items()},
            # New features default to off — existing deployments unaffected
            enable_luhn_validation=False,
            enable_context_analysis=False,
            format_preserving_redaction=False,
            canary_fuzzy_match=False,
        )


def _parse_action(action_str: str) -> DLPAction:
    try:
        return DLPAction[action_str.upper()]
    except KeyError:
        return DLPAction.ALLOW


def load_dlp_config(policy_path: Path) -> DLPConfig:
    """Load DLP configuration from a YAML policy file. Falls back to defaults."""
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
        logging.critical("Failed to parse YAML policy file: %s. Loading defaults.", e)
        return DLPConfig.defaults()

    if not data or "dlp" not in data:
        return DLPConfig.defaults()

    d = data.get("dlp") or {}

    secret_patterns = [
        PatternDef(
            name=p.get("name", "unknown"),
            regex=p.get("regex", ""),
            action=_parse_action(p["action"]) if "action" in p else None,
        )
        for p in d.get("secret_patterns", [])
    ]
    pii_patterns = [
        PatternDef(
            name=p.get("name", "unknown"),
            regex=p.get("regex", ""),
            action=_parse_action(p["action"]) if "action" in p else None,
        )
        for p in d.get("pii_patterns", [])
    ]

    if not secret_patterns and not pii_patterns:
        logging.critical(
            "Both secret_patterns and pii_patterns are empty. "
            "The scanner will not catch any regex-based violations."
        )

    canary_salt = d.get("canary_salt", _DEFAULT_SALT)
    if canary_salt in (_DEFAULT_SALT, "changeme"):
        logging.warning(
            "SECURITY: canary_salt is set to the default insecure value '%s'. "
            "Replace with: python -c \"import secrets; print(secrets.token_hex(32))\"",
            canary_salt,
        )

    # Surface overrides — merge YAML onto module defaults
    raw_overrides = d.get("surface_overrides", {})
    surface_overrides: dict[str, dict[str, str]] = dict(_DEFAULT_SURFACE_OVERRIDES)
    for surface_name, overrides in raw_overrides.items():
        if overrides:
            surface_overrides[surface_name.lower()] = {
                k: str(v) for k, v in overrides.items()
            }

    # ── New feature sub-blocks ────────────────────────────────────────────────
    defaults = DLPConfig.defaults()

    ctx = d.get("context_analysis", {}) or {}

    return DLPConfig(
        canary_action=_parse_action(d.get("canary_action", "BLOCK")),
        canary_salt=canary_salt,
        secrets_action=_parse_action(d.get("secrets_action", "BLOCK")),
        pii_action=_parse_action(d.get("pii_action", "REDACT")),
        unmatched_action=_parse_action(d.get("unmatched_action", "PASS_TO_ML")),
        secret_patterns=secret_patterns,
        pii_patterns=pii_patterns,
        canary_labels=d.get("canary_labels", ["api_credential_mock", "db_password", "sys_admin_token"]),
        content_keys=d.get("content_keys", list(_DEFAULT_CONTENT_KEYS)),
        surface_overrides=surface_overrides,

        # Luhn
        enable_luhn_validation=bool(d.get("luhn_validation", False)),
        # Context analysis
        enable_context_analysis=ctx.get("enabled", False),
        context_window=int(ctx.get("window", defaults.context_window)),
        context_trigger_words=ctx.get("trigger_words", list(_DEFAULT_CONTEXT_TRIGGERS)),
        context_negation_words=ctx.get("negation_words", list(_DEFAULT_CONTEXT_NEGATIONS)),
        context_on_negation=ctx.get("on_negation", "downgrade"),
        # Format-preserving redaction
        format_preserving_redaction=bool(d.get("format_preserving_redaction", False)),
        # Fuzzy canary
        canary_fuzzy_match=bool(d.get("canary_fuzzy_match", False)),
        canary_fuzzy_overlap=float(d.get("canary_fuzzy_overlap", 0.8)),
        # ML pipeline
        ml_base_model=str(d.get("ml_base_model", "google/gemma-2-2b-it")),
        ml_lora_path=d.get("ml_lora_path"),

    )