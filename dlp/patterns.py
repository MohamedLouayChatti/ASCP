import re
import json
from typing import List, Tuple, Dict, Any
from collections import defaultdict

from .models import DLPAction, DLPMatch, ScanSurface
from .config import DLPConfig


class PatternEngine:
    def __init__(self, config: DLPConfig):
        self.config = config
        
        # list of (name, compiled_pattern, action, category)
        self._patterns: List[Tuple[str, re.Pattern, DLPAction, str]] = []
        
        for p in self.config.secret_patterns:
            self._patterns.append((p.name, re.compile(p.regex), self.config.secrets_action, "secret"))
            
        for p in self.config.pii_patterns:
            self._patterns.append((p.name, re.compile(p.regex), self.config.pii_action, "pii"))

    def scan_text(self, text: str, surface: ScanSurface) -> Tuple[List[DLPMatch], str]:
        """
        Scans a string, finding matches and returning both the matches and the redacted text in a single pass.
        Returns: (matches, redacted_text)
        """
        matches: List[DLPMatch] = []
        
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
                        surface=surface
                    )
                )
                if action == DLPAction.REDACT:
                    # e.g., REDACTED_secret_openai_key
                    placeholder = f"[REDACTED_{category}_{name}]"
                    redactions.append((start, end, placeholder))

        if not redactions:
            return matches, text

        # Single-pass redaction based on sorted spans (descending)
        # to ensure that earlier substring replacements don't invalidate later offsets
        redactions.sort(key=lambda x: x[0], reverse=True)
        
        # We also need to handle overlapping intervals by filtering or merging.
        # But if we assume simple descending and no overlap, it's just:
        
        clean_text_list = iter(text)
        text_chars = list(text)
        
        # Merge overlaps before applying (keep the wider span)
        # Ascending sort to merge
        redactions_asc = sorted(redactions, key=lambda x: x[0])
        merged_redactions = []
        if redactions_asc:
            current_start, current_end, current_ph = redactions_asc[0]
            for r in redactions_asc[1:]:
                if r[0] < current_end:  # Overlap 
                    current_end = max(current_end, r[1])
                    # concatenate placeholders or just use the larger one? We can just use "REDACTED_multiple"
                    if current_ph != r[2]:
                        current_ph = "[REDACTED_multiple]"
                else:
                    merged_redactions.append((current_start, current_end, current_ph))
                    current_start, current_end, current_ph = r
            merged_redactions.append((current_start, current_end, current_ph))

        # Re-sort descending
        merged_redactions.sort(key=lambda x: x[0], reverse=True)
        
        # Apply
        clean_text = text
        for start, end, placeholder in merged_redactions:
            clean_text = clean_text[:start] + placeholder + clean_text[end:]

        return matches, clean_text

    def scan_args(self, tool_name: str, args: Dict[str, Any]) -> List[DLPMatch]:
        """
        Serializes tool arguments to JSON to detect secrets within string values 
        regardless of key names.
        """
        # Serialize simply to capture all string data 
        serialized = json.dumps(args, default=str)
        # Surface is TOOL_ARGS
        matches, _ = self.scan_text(serialized, surface=ScanSurface.TOOL_ARGS)
        return matches
