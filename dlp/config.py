import logging
from pathlib import Path
from dataclasses import dataclass, field

from .models import DLPAction


@dataclass
class PatternDef:
    name: str
    regex: str


_DEFAULT_SURFACE_OVERRIDES: dict[str, dict[str, str]] = {
    "tool_args": {"secrets_action": "block"},
    "tool_result": {"downgrade_escalate_to_redact": "true"},
}

_DEFAULT_CONTENT_KEYS: list[str] = ["text", "content", "body", "page_content", "chunk"]
_DEFAULT_SALT = "default_insecure_salt_replace_in_prod"

_DEFAULT_ENTROPY_TRIGGERS: list[str] = [
    "key", "token", "secret", "password", "credential", "api", "auth",
]
_DEFAULT_ENTROPY_NEGATIONS: list[str] = [
    "example", "format", "fake", "test", "placeholder", "sample", "dummy",
]
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
    enable_ner: bool
    secret_patterns: list[PatternDef] = field(default_factory=list)
    pii_patterns: list[PatternDef] = field(default_factory=list)
    canary_labels: list[str] = field(
        default_factory=lambda: ["api_credential_mock", "db_password", "sys_admin_token"]
    )
    content_keys: list[str] = field(default_factory=lambda: list(_DEFAULT_CONTENT_KEYS))
    surface_overrides: dict[str, dict[str, str]] = field(default_factory=dict)

    # ── Shannon entropy detection ─────────────────────────────────────────────
    enable_entropy: bool = False
    entropy_threshold: float = 4.5
    entropy_min_length: int = 20
    entropy_context_window: int = 40
    entropy_trigger_words: list[str] = field(
        default_factory=lambda: list(_DEFAULT_ENTROPY_TRIGGERS)
    )
    entropy_negation_words: list[str] = field(
        default_factory=lambda: list(_DEFAULT_ENTROPY_NEGATIONS)
    )
    entropy_action: str = "block"

    # ── Luhn validation ───────────────────────────────────────────────────────
    enable_luhn_validation: bool = True

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

    # ── Document fingerprinting ───────────────────────────────────────────────
    enable_fingerprinting: bool = False
    fingerprint_threshold: float = 0.3
    fingerprint_max_docs: int = 1000
    fingerprint_ttl_seconds: int = 3600   # 1 hour

    # ── Structured data scanning ──────────────────────────────────────────────
    enable_structured_scan: bool = False

    @classmethod
    def defaults(cls) -> "DLPConfig":
        """Safe defaults used when no policy file is provided."""
        return cls(
            canary_action=DLPAction.BLOCK,
            canary_salt=_DEFAULT_SALT,
            secrets_action=DLPAction.BLOCK,
            pii_action=DLPAction.REDACT,
            enable_ner=False,
            secret_patterns=[
                PatternDef(name="openai_key",    regex=r"sk-[A-Za-z0-9]{48}"),
                PatternDef(name="aws_access_key", regex=r"AKIA[0-9A-Z]{16}"),
                PatternDef(name="github_token",  regex=r"ghp_[A-Za-z0-9]{36}"),
            ],
            pii_patterns=[
                PatternDef(
                    name="email",
                    regex=r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]",
                ),
                PatternDef(name="ipv4",  regex=r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
                # Credit card — enabled by default; Luhn validation removes false positives
                PatternDef(
                    name="credit_card",
                    regex=(
                        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}"
                        r"|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
                    ),
                ),
            ],
            canary_labels=["api_credential_mock", "db_password", "sys_admin_token"],
            content_keys=list(_DEFAULT_CONTENT_KEYS),
            surface_overrides={k: dict(v) for k, v in _DEFAULT_SURFACE_OVERRIDES.items()},
            # New features default to off — existing deployments unaffected
            enable_entropy=False,
            enable_luhn_validation=True,   # safe to always validate CC patterns
            enable_context_analysis=False,
            format_preserving_redaction=False,
            canary_fuzzy_match=False,
            enable_fingerprinting=False,
            enable_structured_scan=False,
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

    d = data["dlp"]

    secret_patterns = [
        PatternDef(name=p.get("name", "unknown"), regex=p.get("regex", ""))
        for p in d.get("secret_patterns", [])
    ]
    pii_patterns = [
        PatternDef(name=p.get("name", "unknown"), regex=p.get("regex", ""))
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

    ent = d.get("entropy", {}) or {}
    ctx = d.get("context_analysis", {}) or {}
    fpr = d.get("fingerprinting", {}) or {}

    return DLPConfig(
        canary_action=_parse_action(d.get("canary_action", "BLOCK")),
        canary_salt=canary_salt,
        secrets_action=_parse_action(d.get("secrets_action", "BLOCK")),
        pii_action=_parse_action(d.get("pii_action", "REDACT")),
        enable_ner=d.get("enable_ner", False),
        secret_patterns=secret_patterns,
        pii_patterns=pii_patterns,
        canary_labels=d.get("canary_labels", ["api_credential_mock", "db_password", "sys_admin_token"]),
        content_keys=d.get("content_keys", list(_DEFAULT_CONTENT_KEYS)),
        surface_overrides=surface_overrides,
        # Entropy
        enable_entropy=ent.get("enabled", False),
        entropy_threshold=float(ent.get("threshold", defaults.entropy_threshold)),
        entropy_min_length=int(ent.get("min_length", defaults.entropy_min_length)),
        entropy_context_window=int(ent.get("context_window", defaults.entropy_context_window)),
        entropy_trigger_words=ent.get("trigger_words", list(_DEFAULT_ENTROPY_TRIGGERS)),
        entropy_negation_words=ent.get("negation_words", list(_DEFAULT_ENTROPY_NEGATIONS)),
        entropy_action=ent.get("action", "block"),
        # Luhn
        enable_luhn_validation=bool(d.get("luhn_validation", True)),
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
        # Fingerprinting
        enable_fingerprinting=fpr.get("enabled", False),
        fingerprint_threshold=float(fpr.get("threshold", defaults.fingerprint_threshold)),
        fingerprint_max_docs=int(fpr.get("max_docs", defaults.fingerprint_max_docs)),
        fingerprint_ttl_seconds=int(fpr.get("ttl_seconds", defaults.fingerprint_ttl_seconds)),
        # Structured scan
        enable_structured_scan=bool(d.get("enable_structured_scan", False)),
    )
