"""Context sufficiency and retrieval relevance checks for Layer A / E2."""

from __future__ import annotations

import re
from typing import Iterable, Sequence


_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "that",
    "the",
    "to",
    "was",
    "were",
    "with",
}


def check_sufficiency(query: str, documents: Sequence[str]) -> dict:
    """Estimate whether retrieved context is enough to answer the query.

    Baseline approach:
    1. Extract query keywords.
    2. Check whether each keyword appears in any retrieved document.
    3. Convert keyword coverage ratio to sufficiency flag.
    """
    query_words = _keywords(query)
    if not query_words:
        return {
            "context_sufficiency": "insufficient",
            "retrieval_relevance": 0.0,
            "covered_keywords": 0,
            "total_keywords": 0,
        }

    lowered_docs = [doc.lower() for doc in documents]

    covered = sum(
        1 for word in query_words if any(_word_in_document(word, doc) for doc in lowered_docs)
    )
    coverage = covered / max(len(query_words), 1)

    if coverage > 0.7:
        flag = "sufficient"
    elif coverage > 0.4:
        flag = "partial"
    else:
        flag = "insufficient"

    return {
        "context_sufficiency": flag,
        "retrieval_relevance": round(coverage, 3),
        "covered_keywords": covered,
        "total_keywords": len(query_words),
    }


def _keywords(text: str) -> list[str]:
    tokens = [t.lower() for t in re.findall(r"\b\w+\b", text)]
    return [t for t in tokens if t not in _STOPWORDS and len(t) > 1]


def _word_in_document(word: str, document: str) -> bool:
    return bool(re.search(rf"\b{re.escape(word)}\b", document))
