"""Claim extraction utilities for Layer A (grounding).

This module converts an assistant answer into atomic, checkable claims.
The extractor is deterministic and dependency-free so it can run in CI.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, List


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")
_BULLET_PREFIX_RE = re.compile(r"^\s*(?:[-*]|\d+[.)])\s+")
_WHITESPACE_RE = re.compile(r"\s+")

# Clause boundaries that frequently combine multiple facts in one sentence.
_CLAUSE_SEPARATOR_RE = re.compile(
    r"\s*(?:;|\s+but\s+|\s+however\s+|\s+while\s+|\s+whereas\s+|"
    r"\s+although\s+|\s+and\s+then\s+|\s+in addition\s+|\s+also\s+)\s*",
    flags=re.IGNORECASE,
)

# Very common non-factual sentence starters.
_NON_CHECKABLE_PREFIXES = (
    "i think",
    "i believe",
    "in my opinion",
    "maybe",
    "perhaps",
    "please",
    "let us",
    "let's",
)

# A claim should typically contain at least one action/state indicator.
_VERB_HINTS = {
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "has",
    "have",
    "had",
    "do",
    "does",
    "did",
    "can",
    "could",
    "will",
    "would",
    "should",
    "may",
    "might",
    "must",
    "contains",
    "include",
    "includes",
    "included",
    "increase",
    "decrease",
    "reached",
    "caused",
    "built",
    "founded",
    "located",
}


@dataclass(frozen=True)
class Claim:
    """Atomic claim extracted from a generated answer."""

    claim_id: str
    text: str
    sentence_index: int
    checkable: bool


class ClaimExtractor:
    """Extracts atomic, checkable claims from answer text."""

    def __init__(self, min_tokens: int = 3) -> None:
        self.min_tokens = min_tokens

    def extract(self, answer: str, keep_uncheckable: bool = False) -> List[Claim]:
        """Extract claims from an answer.

        Args:
            answer: Assistant answer paragraph/text.
            keep_uncheckable: If True, returns all extracted clauses and marks
                whether each clause is checkable. If False, returns only
                checkable claims.

        Returns:
            List of extracted claim objects.
        """
        normalized = _normalize(answer)
        if not normalized:
            return []

        claims: List[Claim] = []
        claim_counter = 0

        for sentence_index, sentence in enumerate(_split_sentences(normalized)):
            for clause in _split_compound_sentence(sentence):
                clause = _clean_clause(clause)
                if not clause:
                    continue

                checkable = _is_checkable_claim(clause, self.min_tokens)
                if not keep_uncheckable and not checkable:
                    continue

                claim_counter += 1
                claims.append(
                    Claim(
                        claim_id=f"c{claim_counter}",
                        text=clause,
                        sentence_index=sentence_index,
                        checkable=checkable,
                    )
                )

        return claims


def extract_claims(answer: str, keep_uncheckable: bool = False) -> List[Claim]:
    """Convenience function for default claim extraction."""
    return ClaimExtractor().extract(answer, keep_uncheckable=keep_uncheckable)


def _normalize(text: str) -> str:
    text = text.strip()
    if not text:
        return ""

    # Normalize whitespace and bullet starts while preserving sentence punctuation.
    lines = [_BULLET_PREFIX_RE.sub("", line) for line in text.splitlines()]
    return _WHITESPACE_RE.sub(" ", " ".join(lines)).strip()


def _split_sentences(text: str) -> Iterable[str]:
    for chunk in _SENTENCE_SPLIT_RE.split(text):
        sentence = chunk.strip()
        if sentence:
            yield sentence


def _split_compound_sentence(sentence: str) -> Iterable[str]:
    # First split by clause separators.
    parts = [part.strip(" ,") for part in _CLAUSE_SEPARATOR_RE.split(sentence)]
    parts = [p for p in parts if p]

    # Then split lightweight enumerations: "X, Y, and Z are..."
    expanded: List[str] = []
    for part in parts:
        if part.count(",") >= 2 and " and " in part.lower():
            subparts = [p.strip() for p in part.split(",") if p.strip()]
            expanded.extend(subparts)
        else:
            expanded.append(part)

    return expanded


def _clean_clause(clause: str) -> str:
    clause = clause.strip(" .,!?:;")
    clause = _WHITESPACE_RE.sub(" ", clause)
    return clause


def _is_checkable_claim(clause: str, min_tokens: int) -> bool:
    lowered = clause.lower().strip()
    if not lowered:
        return False

    if lowered.startswith(_NON_CHECKABLE_PREFIXES):
        return False

    if lowered.endswith("?"):
        return False

    tokens = [t for t in re.split(r"\W+", lowered) if t]
    if len(tokens) < min_tokens:
        return False

    has_verb_hint = any(token in _VERB_HINTS for token in tokens)
    has_fact_marker = bool(re.search(r"\d", clause)) or bool(re.search(r"[A-Z][a-z]+", clause))

    # Accept if there is at least a verb indicator and one factual marker.
    return has_verb_hint and has_fact_marker
