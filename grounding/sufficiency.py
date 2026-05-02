"""Context sufficiency and retrieval relevance checks for Layer A / E2."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Literal, Sequence

from grounding.semantic_scorer import cosine_similarity, get_embedding


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


QueryType = Literal["factual", "numeric", "complex", "definition", "unknown"]

_NUMERIC_HINTS = re.compile(
    r"\b(how many|how much|what year|what date|when|count|number|total|percentage|rate)\b",
    re.IGNORECASE,
)
_DEFINITION_HINTS = re.compile(
    r"\b(what is|what are|define|definition|meaning|explain)\b",
    re.IGNORECASE,
)
_COMPLEX_HINTS = re.compile(
    r"\b(why|how does|how do|what caused|what impact|compare|difference|relationship)\b",
    re.IGNORECASE,
)


def _classify_query(query: str) -> QueryType:
    if _NUMERIC_HINTS.search(query):
        return "numeric"
    if _DEFINITION_HINTS.search(query):
        return "definition"
    if _COMPLEX_HINTS.search(query):
        return "complex"
    if len(query.split()) <= 6:
        return "factual"
    return "unknown"


_THRESHOLDS: dict[QueryType, dict[str, float]] = {
    "numeric": {"sufficient": 0.75, "partial": 0.45},
    "complex": {"sufficient": 0.70, "partial": 0.40},
    "definition": {"sufficient": 0.65, "partial": 0.35},
    "factual": {"sufficient": 0.60, "partial": 0.30},
    "unknown": {"sufficient": 0.65, "partial": 0.35},
}


@dataclass
class DocumentRelevance:
    doc_index: int
    keyword_coverage: float
    semantic_score: float
    combined_score: float
    is_relevant: bool


@dataclass
class SufficiencyResult:
    context_sufficiency: str
    retrieval_relevance: float
    recommendation: str
    query_type: QueryType
    covered_keywords: int
    total_keywords: int
    keyword_coverage: float
    semantic_coverage: float
    relevant_doc_count: int
    total_doc_count: int
    doc_scores: List[DocumentRelevance]


def _keywords(text: str) -> List[str]:
    tokens = [t.lower() for t in re.findall(r"\b\w+\b", text)]
    return [t for t in tokens if t not in _STOPWORDS and len(t) > 2]


def _keyword_present(keyword: str, doc_lower: str) -> bool:
    if re.search(rf"\b{re.escape(keyword)}\b", doc_lower):
        return True
    if len(keyword) > 4:
        stem = keyword[:max(4, len(keyword) - 3)]
        if re.search(rf"\b{re.escape(stem)}\w*\b", doc_lower):
            return True
    return False


def _keyword_coverage(query_keywords: List[str], doc_text: str) -> float:
    if not query_keywords:
        return 0.0
    doc_lower = doc_text.lower()
    covered = sum(1 for kw in query_keywords if _keyword_present(kw, doc_lower))
    return covered / len(query_keywords)


def _score_document(
    doc_index: int,
    doc_text: str,
    query_keywords: List[str],
    query_embedding: List[float] | None,
    relevance_threshold: float = 0.35,
) -> DocumentRelevance:
    kw_score = _keyword_coverage(query_keywords, doc_text)

    sem_score = 0.0
    if query_embedding is not None:
        doc_embedding = get_embedding(doc_text[:1000])
        if doc_embedding is not None:
            sem_score = cosine_similarity(query_embedding, doc_embedding)

    if query_embedding is not None and sem_score > 0:
        combined = 0.45 * kw_score + 0.55 * sem_score
    else:
        combined = kw_score

    return DocumentRelevance(
        doc_index=doc_index,
        keyword_coverage=round(kw_score, 3),
        semantic_score=round(sem_score, 3),
        combined_score=round(combined, 3),
        is_relevant=combined >= relevance_threshold,
    )


def check_sufficiency(
    query: str,
    documents: Sequence[str],
    use_semantic: bool = True,
) -> SufficiencyResult:
    query_keywords = _keywords(query)
    query_type = _classify_query(query)
    thresholds = _THRESHOLDS[query_type]

    if not documents:
        return SufficiencyResult(
            context_sufficiency="insufficient",
            retrieval_relevance=0.0,
            recommendation="abstain",
            query_type=query_type,
            covered_keywords=0,
            total_keywords=len(query_keywords),
            keyword_coverage=0.0,
            semantic_coverage=0.0,
            relevant_doc_count=0,
            total_doc_count=0,
            doc_scores=[],
        )

    query_embedding = None
    if use_semantic:
        query_embedding = get_embedding(query)

    doc_scores = [
        _score_document(i, doc, query_keywords, query_embedding)
        for i, doc in enumerate(documents)
    ]

    best_doc_score = max(d.combined_score for d in doc_scores)
    avg_doc_score = sum(d.combined_score for d in doc_scores) / len(doc_scores)
    aggregate_score = 0.65 * best_doc_score + 0.35 * avg_doc_score

    covered_keywords = sum(
        1 for kw in query_keywords
        if any(_keyword_present(kw, doc.lower()) for doc in documents)
    )
    keyword_coverage = covered_keywords / max(len(query_keywords), 1)

    sem_scores = sorted([d.semantic_score for d in doc_scores], reverse=True)
    semantic_coverage = sum(sem_scores[:2]) / 2 if sem_scores else 0.0

    relevant_docs = [d for d in doc_scores if d.is_relevant]

    if query_type == "numeric":
        docs_with_numbers = [
            d for d in doc_scores
            if d.is_relevant and re.search(r"\b\d+\b", documents[d.doc_index])
        ]
        if not docs_with_numbers:
            return SufficiencyResult(
                context_sufficiency="insufficient",
                retrieval_relevance=round(aggregate_score, 3),
                recommendation="retrieve_more",
                query_type=query_type,
                covered_keywords=covered_keywords,
                total_keywords=len(query_keywords),
                keyword_coverage=round(keyword_coverage, 3),
                semantic_coverage=round(semantic_coverage, 3),
                relevant_doc_count=len(relevant_docs),
                total_doc_count=len(documents),
                doc_scores=doc_scores,
            )

    if aggregate_score >= thresholds["sufficient"]:
        flag = "sufficient"
        recommendation = "proceed"
    elif aggregate_score >= thresholds["partial"]:
        flag = "partial"
        recommendation = "retrieve_more"
    else:
        flag = "insufficient"
        recommendation = "abstain"

    return SufficiencyResult(
        context_sufficiency=flag,
        retrieval_relevance=round(aggregate_score, 3),
        recommendation=recommendation,
        query_type=query_type,
        covered_keywords=covered_keywords,
        total_keywords=len(query_keywords),
        keyword_coverage=round(keyword_coverage, 3),
        semantic_coverage=round(semantic_coverage, 3),
        relevant_doc_count=len(relevant_docs),
        total_doc_count=len(documents),
        doc_scores=doc_scores,
    )
