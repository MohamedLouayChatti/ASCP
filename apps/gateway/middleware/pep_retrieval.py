"""
Policy Enforcement Point — Retrieval layer.

Intercepts retrieved documents before they are passed to the LLM:
  - Injection content detection in retrieved docs
  - Context size limiting
  - Instruction-hierarchy protection (I4)
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Patterns that suggest retrieved content is trying to hijack the agent
_HIERARCHY_HIJACK_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"new\s+(system\s+)?instructions?\s*:", re.IGNORECASE),
    re.compile(r"<system>|</system>|\[system\]", re.IGNORECASE),
    re.compile(r"you\s+must\s+now\s+(follow|obey|execute)", re.IGNORECASE),
    re.compile(r"override\s+(policy|rules|guidelines)", re.IGNORECASE),
    re.compile(r"CONFIDENTIAL.*DO NOT REVEAL.*instructions", re.IGNORECASE),
]

_MAX_DOC_CHARS = 10_000
_MAX_DOCS = 20


def inspect_retrieval(
    documents: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], bool]:
    """
    Sanitize and inspect retrieved documents.

    Returns:
        (cleaned_documents, hierarchy_violation_detected)
    """
    cleaned: list[dict[str, Any]] = []
    hierarchy_violation = False

    for i, doc in enumerate(documents[:_MAX_DOCS]):
        text = doc.get("text", "")

        # Truncate oversized docs
        if len(text) > _MAX_DOC_CHARS:
            text = text[:_MAX_DOC_CHARS]
            logger.debug("Truncated doc[%d] to %d chars", i, _MAX_DOC_CHARS)

        # Hierarchy hijack detection (I4)
        for pattern in _HIERARCHY_HIJACK_PATTERNS:
            if pattern.search(text):
                logger.warning(
                    "Hierarchy hijack attempt in retrieved doc[%d]: pattern=%s",
                    i,
                    pattern.pattern[:40],
                )
                # Neutralize the injection by escaping brackets
                text = pattern.sub("[SANITIZED-INJECTION-ATTEMPT]", text)
                hierarchy_violation = True

        cleaned.append({**doc, "text": text})

    return cleaned, hierarchy_violation
