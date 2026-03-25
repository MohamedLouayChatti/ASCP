from typing import List

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
        
        secret_matches: List[DLPMatch] = []
        pii_matches: List[DLPMatch] = []
        
        # Determine current worst action to see if we should short-circuit
        current_action = DLPAction.ALLOW
        if canary_hits:
            current_action = max(current_action, self.config.canary_action)

        # We can do regex scan for both secrets and PII via pattern_engine.scan_text
        # which returns both match lists and the redacted string
        regex_matches, redacted_text = self.pattern_engine.scan_text(text, surface)
        
        for m in regex_matches:
            if m.category == "secret":
                secret_matches.append(m)
                current_action = max(current_action, m.action)
            elif m.category == "pii":
                pii_matches.append(m)
                current_action = max(current_action, m.action)

        # Only run NER if we aren't already going to BLOCK (to save time) 
        # and if it's enabled in config. But typical DLP might want complete telemetry.
        # Following the prompt: "if a canary fires, you might short-circuit and avoid expensive NER"
        if current_action < DLPAction.BLOCK and self.config.enable_ner:
            ner_matches = self.ner_detector.detect(text, surface)
            # Deduplicate NER matches against regex PII matches (prefer regex for the same span)
            regex_pii_spans = {span for m in pii_matches for span in m.spans}
            
            for nm in ner_matches:
                nm_span = nm.spans[0]
                # Check overlap (naive deduplication: if exact match or simple overlap)
                overlap = any(
                    max(nm_span[0], rs[0]) < min(nm_span[1], rs[1]) 
                    for rs in regex_pii_spans
                )
                if not overlap:
                    pii_matches.append(nm)
                    current_action = max(current_action, nm.action)
                    
                    # Apply redaction for the NER hit
                    if nm.action == DLPAction.REDACT:
                         # Simple replacement for NER redactions if we need to
                         # Note: doing it post-hoc on 'redacted_text' is tricky due to offsets changing,
                         # but since we only care if it's REDACT and not BLOCK, we can just replace the string value directly.
                         # A more robust approach integrates NER into PatternEngine's single pass,
                         # but for now we do string replacement for newly found NER matches
                         placeholder = f"[REDACTED_pii_{nm.pattern_name}]"
                         redacted_text = redacted_text.replace(nm.value, placeholder)

        # Construct Violations for Telemetry
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
            violations=violations
        )
