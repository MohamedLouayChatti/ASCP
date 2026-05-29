"""Shared text processing utilities for Layer A grounding modules."""

from __future__ import annotations

import re


_STOPWORDS = {
    "a",
    "an",
    "the",
    "in",
    "on",
    "at",
    "to",
    "for",
    "of",
    "by",
    "from",
    "with",
    "into",
    "through",
    "about",
    "between",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "have",
    "has",
    "had",
    "do",
    "does",
    "did",
    "said",
    "stated",
    "noted",
    "described",
    "mentioned",
    "and",
    "or",
    "but",
    "that",
    "which",
    "who",
    "whom",
    "this",
    "these",
    "those",
    "their",
    "its",
    "it",
    "also",
    "however",
    "therefore",
    "thus",
    "according",
    "as",
    "so",
    "yet",
    "both",
    "each",
    "more",
    "most",
}


_NEGATION_WORDS = {
    "not",
    "never",
    "no",
    "none",
    "without",
    "cannot",
    "can't",
    "isn't",
    "aren't",
    "wasn't",
    "weren't",
    "doesn't",
    "don't",
    "didn't",
    "won't",
    "wouldn't",
    "shouldn't",
    "couldn't",
    "forbidden",
    "prohibited",
    "denied",
    "blocked",
    "disallowed",
    "unauthorized",
}


def content_tokens(text: str) -> set[str]:
    """Extract meaningful content tokens for overlap checks."""
    tokens = [t.lower() for t in re.findall(r"\b\w+\b", text)]
    return {t for t in tokens if t not in _STOPWORDS and len(t) > 2}


def has_negation(text: str) -> bool:
    """Check if text contains any negation token."""
    return bool(set(text.lower().split()) & _NEGATION_WORDS)


def topic_overlap(text_a: str, text_b: str) -> float:
    """Claim-recall overlap for gating comparisons."""
    tokens_a = content_tokens(text_a)
    tokens_b = content_tokens(text_b)
    if not tokens_a:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a)
