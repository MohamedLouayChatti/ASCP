"""
Shannon entropy scanner for novel credential detection.

Many API keys, tokens, and credentials are randomly generated and therefore
exhibit high Shannon entropy (> 4.5 bits/character). This scanner detects
long, high-entropy alphanumeric strings that don't match any known regex
pattern — catching novel credential formats before dedicated patterns exist.

This is the same heuristic used by truffleHog for secret detection in repos.
"""

import math
import re
from collections import Counter

from .models import DLPMatch, ScanSurface, DLPAction
from .config import DLPConfig, _parse_action


def shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy in bits per character.
    Returns 0.0 for empty strings. Maximum is log2(charset_size).
    """
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


class EntropyScanner:
    """
    Detects high-entropy strings that are likely credentials.

    Firing conditions (configurable via DLPConfig):
    1. entropy >= threshold  AND  trigger word in surrounding window
       (high confidence — context confirms this is a credential)
    2. entropy >= threshold + 0.5  AND  no negation word in window
       (very high entropy without any exemption signal — catches novel formats)

    Suppressed when a negation word ("example", "test", "fake"…) is present
    without any trigger word — avoids false positives in documentation.
    """

    def __init__(self, config: DLPConfig):
        self.config = config
        self._candidate_re = re.compile(
            rf"[A-Za-z0-9+/=_\-]{{{config.entropy_min_length},}}"
        )
        self._trigger_words = [w.lower() for w in config.entropy_trigger_words]
        self._negation_words = [w.lower() for w in config.entropy_negation_words]
        self._action = _parse_action(config.entropy_action)
        # High-confidence threshold: fire without trigger word
        self._high_threshold = config.entropy_threshold + 0.5

    def scan(self, text: str, surface: ScanSurface) -> list[DLPMatch]:
        """Scan text for high-entropy candidate strings."""
        matches: list[DLPMatch] = []
        window = self.config.entropy_context_window

        for m in self._candidate_re.finditer(text):
            candidate = m.group()
            start, end = m.start(), m.end()
            score = shannon_entropy(candidate)

            if score < self.config.entropy_threshold:
                continue

            pre = text[max(0, start - window):start].lower()
            post = text[end:min(len(text), end + window)].lower()
            context = pre + " " + post

            has_trigger = any(t in context for t in self._trigger_words)
            has_negation = any(n in context for n in self._negation_words)

            # Suppress: negation present, no trigger → likely documentation/example
            if has_negation and not has_trigger:
                continue

            fire = (has_trigger and score >= self.config.entropy_threshold) or (
                score >= self._high_threshold and not has_negation
            )

            if fire:
                matches.append(
                    DLPMatch(
                        pattern_name=f"entropy_{candidate[:8].lower()}",
                        category="secret",
                        action=self._action,
                        value=candidate,
                        spans=[(start, end)],
                        surface=surface,
                        entropy_score=round(score, 4),
                    )
                )

        return matches
