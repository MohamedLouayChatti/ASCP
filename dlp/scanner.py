from .models import DLPResult, DLPMatch, CanaryHit, ScanSurface, DLPAction
from .config import DLPConfig
from .canary import CanaryEngine
from .patterns import PatternEngine
from .ner import NERDetector


class DLPScanner:
    def __init__(self, config: DLPConfig, canary_engine: CanaryEngine):
        self.config = config
        self.canary_engine = canary_engine
        self.pattern_engine = PatternEngine(config)
        self.ner_detector = NERDetector(config)

    def scan(self, text: str, surface: ScanSurface) -> DLPResult:
        """
        Orchestrates scanning: Canaries -> Regex (Secrets, PII) -> NER.
        Computes the worst-case action using priority and produces the final clean_text.
        """
        canary_hits = self.canary_engine.detect(text, surface)

        secret_matches: list[DLPMatch] = []
        pii_matches: list[DLPMatch] = []

        # Determine current worst action to see if we should short-circuit
        current_action = DLPAction.ALLOW
        if canary_hits:
            current_action = max(current_action, self.config.canary_action)

        # Regex scan for both secrets and PII via pattern_engine.scan_text
        regex_matches, _ = self.pattern_engine.scan_text(text, surface)

        all_redactions = []
        for m in regex_matches:
            if m.action == DLPAction.REDACT:
                for span in m.spans:
                    all_redactions.append((span[0], span[1], f"[REDACTED_{m.category}_{m.pattern_name}]"))

            if m.category == "secret":
                secret_matches.append(m)
                current_action = max(current_action, m.action)
            elif m.category == "pii":
                pii_matches.append(m)
                current_action = max(current_action, m.action)

        # Only run NER if we aren't already going to BLOCK (saves expensive model calls)
        # and if NER is enabled in config.
        if current_action < DLPAction.BLOCK and self.config.enable_ner:
            ner_matches = self.ner_detector.detect(text, surface)
            # Deduplicate NER matches against regex PII matches (prefer regex for the same span).
            # Build a flat set of all regex PII spans across all regex matches.
            regex_pii_spans = {span for m in pii_matches for span in m.spans}

            for nm in ner_matches:
                # Check ALL spans of this NER match against ALL regex PII spans.
                # If any span of the NER match overlaps any regex PII span, drop the
                # entire NER match to avoid double-counting.
                any_span_overlaps = any(
                    max(nm_span[0], rs[0]) < min(nm_span[1], rs[1])
                    for nm_span in nm.spans
                    for rs in regex_pii_spans
                )
                if not any_span_overlaps:
                    pii_matches.append(nm)
                    current_action = max(current_action, nm.action)

                    # Queue redaction entries for every span of the kept NER match.
                    if nm.action == DLPAction.REDACT:
                        placeholder = f"[REDACTED_pii_{nm.pattern_name}]"
                        for nm_span in nm.spans:
                            all_redactions.append((nm_span[0], nm_span[1], placeholder))

        # Apply all redactions in a single pass
        redacted_text = PatternEngine.apply_redactions(text, all_redactions)

        # Construct violation strings for telemetry
        violations = []
        for ch in canary_hits:
            violations.append(f"canary_leak:{ch.label}")
        for sm in secret_matches:
            violations.append(f"secret_leak:{sm.pattern_name}")
        for pm in pii_matches:
            violations.append(f"pii_leak:{pm.pattern_name}")

        # Compute clean_text
        clean_text = text
        if current_action == DLPAction.BLOCK:
            clean_text = "[BLOCKED_BY_POLICY]"
        elif current_action == DLPAction.REDACT:
            clean_text = redacted_text

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
