"""
Policy Enforcement Point — Input layer.

Sanitizes and validates user input before it reaches the agent:
  - Unicode normalization (defends against obfuscation attacks)
  - HTML stripping
  - Null byte removal
  - Length enforcement
  - Injection heuristics (prompt injection patterns)
"""

from __future__ import annotations

import logging
import re

from security.sanitization.unicode_normalize import sanitize

logger = logging.getLogger(__name__)

# Heuristic patterns for prompt injection attempts
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(
        r"(you are now|act as|pretend (to be|you are))\s+(a |an )?(?!helpful)", re.IGNORECASE
    ),
    re.compile(r"system\s*prompt\s*[:=]", re.IGNORECASE),
    re.compile(r"\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>", re.IGNORECASE),
    re.compile(r"disregard\s+(your|all)\s+(training|guidelines|restrictions)", re.IGNORECASE),
    re.compile(r"jailbreak|DAN mode|developer mode", re.IGNORECASE),
]


def inspect_input(
    text: str,
    *,
    max_length: int = 32768,
    strip_html: bool = True,
    unicode_norm: bool = True,
) -> tuple[str, list[str], bool]:
    """
    Sanitize and inspect user input.

    Returns:
        (sanitized_text, applied_ops, injection_detected)
    """
    sanitized, ops = sanitize(
        text,
        unicode_norm=unicode_norm,
        strip_html=strip_html,
        max_length=max_length,
    )

    injection_detected = False
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(sanitized):
            injection_detected = True
            logger.warning("Injection pattern detected in input: pattern=%s", pattern.pattern[:40])
            ops.append("injection_flagged")
            break

    return sanitized, ops, injection_detected
