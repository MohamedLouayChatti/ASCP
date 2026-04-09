import json

from .models import DLPResult, DLPMatch, ScanSurface, DLPAction
from .config import DLPConfig
from .canary import CanaryEngine
from .patterns import PatternEngine
from .validators import MatchValidator
from .context import ContextAnalyzer


class DLPScanner:
    def __init__(self, config: DLPConfig, canary_engine: CanaryEngine):
        self.config = config
        self.canary_engine = canary_engine
        self.pattern_engine = PatternEngine(config)
        self.match_validator = MatchValidator(config)

        # Optional engines — only instantiated when enabled; saves import cost
        self.context_analyzer: ContextAnalyzer | None = (
            ContextAnalyzer(config) if config.enable_context_analysis else None
        )

    # ── Placeholder builder ───────────────────────────────────────────────────

    def _placeholder(self, m: DLPMatch) -> str:
        if self.config.format_preserving_redaction:
            return self.pattern_engine.format_preserve(m.value, m.pattern_name)
        return f"[REDACTED_{m.category}_{m.pattern_name}]"

    # ── Main scan() ───────────────────────────────────────────────────────────

    def scan(self, text: str, surface: ScanSurface) -> DLPResult:
        from .features import extract_features
        from .ml import classify

        # 1. Canary (HARD STOP)
        canary_hits = self.canary_engine.detect(text, surface)
        if canary_hits:
            violations = []
            for ch in canary_hits:
                prefix = "canary_fuzzy_leak" if ch.fuzzy else "canary_leak"
                violations.append(f"{prefix}:{ch.label}")
            return DLPResult(
                original_text=text,
                clean_text="[BLOCKED_BY_POLICY]",
                action=DLPAction.BLOCK,
                surface=surface,
                canary_hits=canary_hits,
                violations=violations,
            )

        # 2. Pattern Engine
        pattern_result = self.pattern_engine.scan(text, surface)
        
        secrets = pattern_result.secrets
        pii = pattern_result.pii
        
        violations = []
        for sm in secrets:
            violations.append(f"secret_leak:{sm.pattern_name}")
        for pm in pii:
            violations.append(f"pii_leak:{pm.pattern_name}")

        if pattern_result.action == "BLOCK":
            return DLPResult(
                original_text=text,
                clean_text="[BLOCKED_BY_POLICY]",
                action=DLPAction.BLOCK,
                surface=surface,
                secret_matches=secrets,
                pii_matches=pii,
                violations=violations,
            )

        if pattern_result.action == "REDACT":
            return DLPResult(
                original_text=text,
                clean_text=pattern_result.redacted_text,
                action=DLPAction.REDACT,
                surface=surface,
                secret_matches=secrets,
                pii_matches=pii,
                violations=violations,
            )

        # 3. Feature Extraction
        features = extract_features(text, surface)

        # 4. ML Classification (placeholder)
        label_action, confidence = classify(text, surface, features)

        # 5. Policy Resolution
        final_action = label_action
        if confidence < self.config.ml_confidence_threshold:
            final_action = DLPAction.ESCALATE

        clean_text = text
        if final_action == DLPAction.BLOCK:
            clean_text = "[BLOCKED_BY_POLICY]"
        elif final_action == DLPAction.REDACT:
            clean_text = pattern_result.redacted_text

        return DLPResult(
            original_text=text,
            clean_text=clean_text,
            action=final_action,
            surface=surface,
            secret_matches=secrets,
            pii_matches=pii,
            violations=violations,
        )