import re
from typing import Any
from collections import defaultdict

from .models import DLPAction, DLPMatch, ScanSurface
from .config import DLPConfig


class PatternEngine:
    def __init__(self, config: DLPConfig):
        self.config = config

        # list of (name, compiled_pattern, action, category)
        self._patterns: list[tuple[str, re.Pattern, DLPAction, str]] = []

        for p in self.config.secret_patterns:
            self._patterns.append((p.name, re.compile(p.regex), self.config.secrets_action, "secret"))

        for p in self.config.pii_patterns:
            self._patterns.append((p.name, re.compile(p.regex), self.config.pii_action, "pii"))

    @staticmethod
    def apply_redactions(text: str, redactions: list[tuple[int, int, str]]) -> str:
        if not redactions:
            return text

        # Merge overlaps before applying (keep the wider span)
        # Ascending sort to merge
        redactions_asc = sorted(redactions, key=lambda x: x[0])
        merged_redactions = []
        if redactions_asc:
            current_start, current_end, current_ph = redactions_asc[0]
            for r in redactions_asc[1:]:
                if r[0] < current_end:  # Overlap
                    current_end = max(current_end, r[1])
                    # Use a single placeholder for overlaps to avoid leaking
                    # information about how many patterns fired.
                    if current_ph != r[2]:
                        current_ph = "[REDACTED]"
                else:
                    merged_redactions.append((current_start, current_end, current_ph))
                    current_start, current_end, current_ph = r
            merged_redactions.append((current_start, current_end, current_ph))

        # Re-sort descending so we replace from the end of the string backwards,
        # keeping earlier offsets valid.
        merged_redactions.sort(key=lambda x: x[0], reverse=True)

        clean_text = text
        for start, end, placeholder in merged_redactions:
            clean_text = clean_text[:start] + placeholder + clean_text[end:]

        return clean_text

    def scan_text(self, text: str, surface: ScanSurface) -> tuple[list[DLPMatch], str]:
        """
        Scans a string, finding matches and returning both the matches and the
        redacted text in a single pass.

        Returns: (matches, redacted_text)
        """
        matches: list[DLPMatch] = []

        # Collect all redactions: (start, end, placeholder)
        redactions = []

        for name, pattern, action, category in self._patterns:
            for m in pattern.finditer(text):
                matched_str = m.group(0)
                start, end = m.span()
                matches.append(
                    DLPMatch(
                        pattern_name=name,
                        category=category,
                        action=action,
                        value=matched_str,
                        spans=[(start, end)],
                        surface=surface,
                    )
                )
                if action == DLPAction.REDACT:
                    placeholder = f"[REDACTED_{category}_{name}]"
                    redactions.append((start, end, placeholder))

        if not redactions:
            return matches, text

        clean_text = self.apply_redactions(text, redactions)
        return matches, clean_text
