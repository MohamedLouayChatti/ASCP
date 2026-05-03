"""Claim extraction primitives used across Layer A checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Claim:
    """Atomic claim representation used by support and consistency checks."""

    claim_id: str
    text: str
    sentence_index: int
    checkable: bool


class ClaimExtractor:
    """Deterministic regex-based claim extractor (safe fallback)."""

    def extract(self, answer: str) -> List[Claim]:
        if not answer or not answer.strip():
            return []

        sentences = re.split(r"(?<=[.!?])\s+", answer.strip())
        claims: List[Claim] = []
        for i, sent in enumerate(sentences):
            text = sent.strip()
            if not text:
                continue
            checkable = bool(
                re.search(
                    r"\b(is|are|was|were|has|have|had|will|can|must|should)\b",
                    text.lower(),
                )
            )
            claims.append(
                Claim(
                    claim_id=f"c{i + 1}",
                    text=text,
                    sentence_index=i,
                    checkable=checkable,
                )
            )

        return claims
