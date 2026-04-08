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
        """
        Full scanning pipeline on a plain string:

        1. Canary detection (exact + optional fuzzy)
        2. Regex scan → Luhn validation → context analysis
        3. Compute action, build redacted text
        """
        # 1. Canary — any hit is always BLOCK regardless of policy config.
        # Canary tokens should NEVER cross an external boundary; detection means
        # critical system failure (prompt injection, instruction override, or
        # data exfiltration via tool call).
        canary_hits = self.canary_engine.detect(text, surface)
        current_action = DLPAction.ALLOW
        if canary_hits:
            current_action = DLPAction.BLOCK

        secret_matches: list[DLPMatch] = []
        pii_matches: list[DLPMatch] = []
        all_redactions: list[tuple[int, int, str]] = []

        # 2a. Regex
        regex_matches, _ = self.pattern_engine.scan_text(text, surface)

        # 2b. Luhn validation (drop invalid credit card matches)
        regex_matches = self.match_validator.filter(regex_matches)

        # 2c. Context window analysis
        if self.context_analyzer is not None:
            regex_matches = self.context_analyzer.filter(regex_matches, text)

        for m in regex_matches:
            if m.action == DLPAction.REDACT:
                for span in m.spans:
                    all_redactions.append((span[0], span[1], self._placeholder(m)))
            if m.category == "secret":
                secret_matches.append(m)
                current_action = max(current_action, m.action)
            elif m.category == "pii":
                pii_matches.append(m)
                current_action = max(current_action, m.action)

        # 3. Compute output
        redacted = PatternEngine.apply_redactions(text, all_redactions)

        violations = []
        for ch in canary_hits:
            prefix = "canary_fuzzy_leak" if ch.fuzzy else "canary_leak"
            violations.append(f"{prefix}:{ch.label}")
        for sm in secret_matches:
            violations.append(f"secret_leak:{sm.pattern_name}")
        for pm in pii_matches:
            violations.append(f"pii_leak:{pm.pattern_name}")

        clean_text = text
        if current_action == DLPAction.BLOCK:
            clean_text = "[BLOCKED_BY_POLICY]"
        elif current_action == DLPAction.REDACT:
            clean_text = redacted

        return DLPResult(
            original_text=text,
            clean_text=clean_text,
            action=current_action,
            surface=surface,
            canary_hits=canary_hits,
            secret_matches=secret_matches,
            pii_matches=pii_matches,
            violations=violations,
        )