import json

from .models import DLPResult, DLPMatch, FingerprintHit, ScanSurface, DLPAction
from .config import DLPConfig
from .canary import CanaryEngine
from .patterns import PatternEngine
from .ner import NERDetector
from .validators import MatchValidator
from .entropy import EntropyScanner
from .context import ContextAnalyzer
from .fingerprint import DocumentFingerprinter


class DLPScanner:
    def __init__(self, config: DLPConfig, canary_engine: CanaryEngine):
        self.config = config
        self.canary_engine = canary_engine
        self.pattern_engine = PatternEngine(config)
        self.ner_detector = NERDetector(config)
        self.match_validator = MatchValidator(config)

        # Optional engines — only instantiated when enabled; saves import cost
        self.entropy_scanner: EntropyScanner | None = (
            EntropyScanner(config) if config.enable_entropy else None
        )
        self.context_analyzer: ContextAnalyzer | None = (
            ContextAnalyzer(config) if config.enable_context_analysis else None
        )
        self.fingerprinter: DocumentFingerprinter | None = (
            DocumentFingerprinter(config) if config.enable_fingerprinting else None
        )

    # ── Fingerprinting helper (called from __init__.py on inject) ─────────────

    def fingerprint_docs(self, docs: list[dict]) -> None:
        """Persist trigram fingerprints for the given docs (no-op if disabled)."""
        if self.fingerprinter is not None:
            self.fingerprinter.fingerprint_docs(docs, self.config.content_keys)

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
        3. Shannon entropy detection (deduped against regex)
        4. NER       (skipped when already BLOCKing — saves inference cost)
        5. Document fingerprint check
        6. Compute action, build redacted text
        """
        # 1. Canary
        canary_hits = self.canary_engine.detect(text, surface)
        current_action = DLPAction.ALLOW
        if canary_hits:
            current_action = max(current_action, self.config.canary_action)

        secret_matches: list[DLPMatch] = []
        pii_matches: list[DLPMatch] = []
        fingerprint_hits: list[FingerprintHit] = []
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

        # 3. Entropy detection (novel secrets not caught by regex)
        if self.entropy_scanner is not None:
            regex_secret_spans = {span for m in secret_matches for span in m.spans}
            for em in self.entropy_scanner.scan(text, surface):
                em_span = em.spans[0]
                if not any(
                    max(em_span[0], rs[0]) < min(em_span[1], rs[1])
                    for rs in regex_secret_spans
                ):
                    secret_matches.append(em)
                    current_action = max(current_action, em.action)
                    if em.action == DLPAction.REDACT:
                        all_redactions.append((em_span[0], em_span[1], self._placeholder(em)))

        # 4. NER (skip if already BLOCKing — expensive model inference)
        if current_action < DLPAction.BLOCK and self.config.enable_ner:
            ner_matches = self.ner_detector.detect(text, surface)
            regex_pii_spans = {span for m in pii_matches for span in m.spans}
            for nm in ner_matches:
                any_overlap = any(
                    max(ns[0], rs[0]) < min(ns[1], rs[1])
                    for ns in nm.spans
                    for rs in regex_pii_spans
                )
                if not any_overlap:
                    pii_matches.append(nm)
                    current_action = max(current_action, nm.action)
                    if nm.action == DLPAction.REDACT:
                        ph = f"[REDACTED_pii_{nm.pattern_name}]"
                        for ns in nm.spans:
                            all_redactions.append((ns[0], ns[1], ph))

        # 5. Fingerprint
        if self.fingerprinter is not None:
            fingerprint_hits = self.fingerprinter.scan(text, surface)
            if fingerprint_hits:
                current_action = max(current_action, self.config.canary_action)

        # 6. Compute output
        redacted = PatternEngine.apply_redactions(text, all_redactions)

        violations = []
        for ch in canary_hits:
            prefix = "canary_fuzzy_leak" if ch.fuzzy else "canary_leak"
            violations.append(f"{prefix}:{ch.label}")
        for sm in secret_matches:
            violations.append(f"secret_leak:{sm.pattern_name}")
        for pm in pii_matches:
            violations.append(f"pii_leak:{pm.pattern_name}")
        for fh in fingerprint_hits:
            violations.append(f"fingerprint_leak:{fh.doc_id}")

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
            fingerprint_hits=fingerprint_hits,
        )

    # ── Dual-pass structured scan ─────────────────────────────────────────────

    def scan_structured(self, data: dict | list, surface: ScanSurface) -> DLPResult:
        """
        Dual-pass scan for structured data (dict/list):

        Pass 1 — Structured walk (regex + entropy + Luhn + context) on every
                  leaf string independently, with full JSON path attribution in
                  each DLPMatch.source_path.

        Pass 2 — JSON string scan for global detectors that need the full
                  serialised representation: canary detection, NER, fingerprinting.

        The two passes are merged: pass-1 matches drive the action and
        redacted-dict output; pass-2 provides canary/NER/fingerprint hits.
        NER matches are deduped against pass-1 pii by value.
        """
        from .structured import scan_dict as _scan_dict, redact_dict as _redact_dict

        json_text = json.dumps(data, default=str)

        # Pass 1: structured walk with path attribution
        structured_matches = _scan_dict(
            data=data,
            surface=surface,
            pattern_engine=self.pattern_engine,
            config=self.config,
            entropy_scanner=self.entropy_scanner,
            match_validator=self.match_validator,
            context_analyzer=self.context_analyzer,
        )

        secret_matches = [
            m for m in structured_matches
            if m.category == "secret" and m.action != DLPAction.ALLOW
        ]
        pii_matches = [
            m for m in structured_matches
            if m.category == "pii" and m.action != DLPAction.ALLOW
        ]

        # Pass 2: global detectors on JSON text
        canary_hits = self.canary_engine.detect(json_text, surface)

        fingerprint_hits: list[FingerprintHit] = []
        if self.fingerprinter is not None:
            fingerprint_hits = self.fingerprinter.scan(json_text, surface)

        # NER on JSON text (no source_path — global text spans)
        if self.config.enable_ner:
            pii_values = {m.value for m in pii_matches}
            for nm in self.ner_detector.detect(json_text, surface):
                if nm.value not in pii_values:
                    pii_matches.append(nm)

        # Compute action
        current_action = DLPAction.ALLOW
        if canary_hits:
            current_action = max(current_action, self.config.canary_action)
        if fingerprint_hits:
            current_action = max(current_action, self.config.canary_action)
        for m in secret_matches + pii_matches:
            current_action = max(current_action, m.action)

        # Build clean output
        if current_action == DLPAction.BLOCK:
            clean_text = "[BLOCKED_BY_POLICY]"
        elif current_action == DLPAction.REDACT:
            redacted_data = _redact_dict(data, structured_matches, self.config, self.pattern_engine)
            clean_text = json.dumps(redacted_data, default=str)
        else:
            clean_text = json_text

        # Violations with path attribution where available
        violations = []
        for ch in canary_hits:
            prefix = "canary_fuzzy_leak" if ch.fuzzy else "canary_leak"
            violations.append(f"{prefix}:{ch.label}")
        for sm in secret_matches:
            path_suffix = f"@{sm.source_path}" if sm.source_path else ""
            violations.append(f"secret_leak:{sm.pattern_name}{path_suffix}")
        for pm in pii_matches:
            path_suffix = f"@{pm.source_path}" if pm.source_path else ""
            violations.append(f"pii_leak:{pm.pattern_name}{path_suffix}")
        for fh in fingerprint_hits:
            violations.append(f"fingerprint_leak:{fh.doc_id}")

        return DLPResult(
            original_text=json_text,
            clean_text=clean_text,
            action=current_action,
            surface=surface,
            canary_hits=canary_hits,
            secret_matches=secret_matches,
            pii_matches=pii_matches,
            violations=violations,
            fingerprint_hits=fingerprint_hits,
        )
