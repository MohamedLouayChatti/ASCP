import re
from collections import defaultdict
from typing import Any

from .models import DLPAction, DLPMatch, ScanSurface
from .config import DLPConfig


# Known structural prefixes for format-preserving redaction
_TOKEN_PREFIXES: dict[str, str] = {
    "openai_key":    "sk-",
    "aws_access_key": "AKIA",
    "github_token":  "ghp_",
}


class PatternEngine:
    def __init__(self, config: DLPConfig):
        self.config = config
        self._patterns: list[tuple[str, re.Pattern, DLPAction, str]] = []

        for p in self.config.secret_patterns:
            self._patterns.append(
                (p.name, re.compile(p.regex), p.action if p.action is not None else self.config.secrets_action, "secret")
            )
        for p in self.config.pii_patterns:
            self._patterns.append(
                (p.name, re.compile(p.regex), p.action if p.action is not None else self.config.pii_action, "pii")
            )

    # ── Redaction helpers ─────────────────────────────────────────────────────

    @staticmethod
    def apply_redactions(text: str, redactions: list[tuple[int, int, str]]) -> str:
        """Apply a list of (start, end, placeholder) redactions in a single pass."""
        if not redactions:
            return text

        redactions_asc = sorted(redactions, key=lambda x: x[0])
        merged: list[tuple[int, int, str]] = []

        current_start, current_end, current_ph = redactions_asc[0]
        for r in redactions_asc[1:]:
            if r[0] < current_end:
                current_end = max(current_end, r[1])
                if current_ph != r[2]:
                    current_ph = "[REDACTED]"
            else:
                merged.append((current_start, current_end, current_ph))
                current_start, current_end, current_ph = r
        merged.append((current_start, current_end, current_ph))

        merged.sort(key=lambda x: x[0], reverse=True)
        clean = text
        for start, end, placeholder in merged:
            clean = clean[:start] + placeholder + clean[end:]
        return clean

    @staticmethod
    def format_preserve(value: str, pattern_name: str) -> str:
        """
        Return a structurally valid synthetic substitute for the matched value.

        The goal is to allow downstream systems to continue parsing the structure
        while ensuring the actual sensitive data cannot be recovered.

          email:        user@example.com    → xxxx@xxxxxxx.xxx
          ipv4:         192.168.1.1         → xxx.xxx.x.x
          credit_card:  4111111111111111    → XXXXXXXXXXXX1111  (last 4 visible)
          openai_key:   sk-ABCD...          → sk-XXXX...
          aws_access_key: AKIA1234...       → AKIAXXXXXXXX...
          github_token: ghp_abc...          → ghp_xxx...
          generic:      MyToken123          → XxXXXXX000
        """
        # Email
        if pattern_name == "email" and "@" in value:
            local, _, domain = value.partition("@")
            masked_local = "x" * min(len(local), 8)
            domain_parts = domain.split(".")
            masked_domain = ".".join("x" * min(len(p), 7) for p in domain_parts)
            return f"{masked_local}@{masked_domain}"

        # IPv4
        if pattern_name == "ipv4" and "." in value:
            return ".".join("x" * len(o) for o in value.split("."))

        # Credit card — keep last 4 digits, mask the rest
        if pattern_name == "credit_card":
            digits = "".join(c for c in value if c.isdigit())
            return "X" * (len(digits) - 4) + digits[-4:]

        # Known token prefixes — preserve prefix, mask suffix with case-matched X
        for pname, prefix in _TOKEN_PREFIXES.items():
            if pattern_name == pname and value.startswith(prefix):
                suffix = value[len(prefix):]
                masked = "".join(
                    "X" if c.isupper() else "x" if c.islower() else c
                    for c in suffix
                )
                return prefix + masked

        # Generic fallback — preserve structural characters (-, _, ., @, /)
        # Replace letters with X/x (preserving case), digits with 0
        return "".join(
            "X" if c.isupper()
            else "x" if c.islower()
            else "0" if c.isdigit()
            else c
            for c in value
        )

    # ── Scanning ──────────────────────────────────────────────────────────────

    def scan_text(self, text: str, surface: ScanSurface) -> tuple[list[DLPMatch], str]:
        """
        Scan a string against all configured patterns.
        Returns (matches, redacted_text). Redaction uses format-preserving or
        bracket placeholders depending on config.format_preserving_redaction.
        """
        matches: list[DLPMatch] = []
        redactions: list[tuple[int, int, str]] = []

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
                    if self.config.format_preserving_redaction:
                        placeholder = self.format_preserve(matched_str, name)
                    else:
                        placeholder = f"[REDACTED_{category}_{name}]"
                    redactions.append((start, end, placeholder))

        if not redactions:
            return matches, text

        return matches, self.apply_redactions(text, redactions)
