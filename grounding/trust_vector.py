"""Full trust vector assembly for Layer A.

This module combines:
- E1 grounding signals (claim support)
- E2 context sufficiency/relevance

Output is a single payload for policy enforcement (E4).
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Sequence

from grounding.support_checker import RetrievedDocument, compute_grounding_score
from grounding.sufficiency import check_sufficiency


def assemble_trust_vector(
    query: str,
    answer: str,
    documents: Sequence[str] | Sequence[RetrievedDocument],
) -> dict:
    """Assemble a full trust vector for one answer.

    Args:
        query: User query / task prompt.
        answer: Assistant answer to evaluate.
        documents: Retrieved context as raw strings or RetrievedDocument items.

    Returns:
        Trust vector with normalized signals and policy-oriented metadata.
    """
    grounding = compute_grounding_score(answer=answer, documents=documents)
    document_texts = _extract_document_texts(documents)
    sufficiency = check_sufficiency(query=query, documents=document_texts)
    sufficiency_payload = _sufficiency_to_dict(sufficiency)

    contradiction_ratio = _safe_ratio(
        grounding.get("contradicted_claims", 0),
        grounding.get("total_claims", 0),
    )

    hallucination_risk = _compute_hallucination_risk(
        grounding_score=grounding.get("grounding_score", 0.0),
        contradiction_ratio=contradiction_ratio,
        retrieval_relevance=sufficiency_payload.get("retrieval_relevance", 0.0),
    )

    return {
        "trust_vector_version": "v1",
        "query": query,
        "answer": answer,
        "signals": {
            "grounding_score": grounding.get("grounding_score", 0.0),
            "retrieval_relevance": sufficiency_payload.get("retrieval_relevance", 0.0),
            "context_sufficiency": sufficiency_payload.get("context_sufficiency", "insufficient"),
            "contradiction_ratio": round(contradiction_ratio, 3),
            "hallucination_risk": hallucination_risk,
        },
        "counts": {
            "supported_claims": grounding.get("supported_claims", 0),
            "unsupported_claims": grounding.get("unsupported_claims", 0),
            "contradicted_claims": grounding.get("contradicted_claims", 0),
            "insufficient_claims": grounding.get("insufficient_claims", 0),
            "total_claims": grounding.get("total_claims", 0),
            "covered_keywords": sufficiency_payload.get("covered_keywords", 0),
            "total_keywords": sufficiency_payload.get("total_keywords", 0),
        },
        "decision_hint": _decision_hint(
            grounding_score=grounding.get("grounding_score", 0.0),
            context_sufficiency=sufficiency_payload.get("context_sufficiency", "insufficient"),
            hallucination_risk=hallucination_risk,
        ),
        "reason_codes": _reason_codes(
            grounding_score=grounding.get("grounding_score", 0.0),
            context_sufficiency=sufficiency_payload.get("context_sufficiency", "insufficient"),
            contradicted_claims=grounding.get("contradicted_claims", 0),
            total_claims=grounding.get("total_claims", 0),
            hallucination_risk=hallucination_risk,
        ),
        "details": {
            "grounding": grounding,
            "sufficiency": sufficiency_payload,
        },
    }


def _sufficiency_to_dict(sufficiency: Any) -> dict:
    if isinstance(sufficiency, dict):
        return sufficiency
    if is_dataclass(sufficiency):
        return asdict(sufficiency)
    if hasattr(sufficiency, "__dict__"):
        return dict(sufficiency.__dict__)
    return {}


def _extract_document_texts(documents: Sequence[str] | Sequence[RetrievedDocument]) -> list[str]:
    if not documents:
        return []

    first = documents[0]
    if isinstance(first, RetrievedDocument):
        return [doc.text for doc in documents]  # type: ignore[union-attr]

    return list(documents)  # type: ignore[arg-type]


def _compute_hallucination_risk(
    grounding_score: float,
    contradiction_ratio: float,
    retrieval_relevance: float,
) -> float:
    # Transparent weighted baseline for Layer A risk signal.
    risk = (
        0.55 * (1.0 - grounding_score)
        + 0.30 * contradiction_ratio
        + 0.15 * (1.0 - retrieval_relevance)
    )
    return round(max(0.0, min(1.0, risk)), 3)


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def _decision_hint(grounding_score: float, context_sufficiency: str, hallucination_risk: float) -> str:
    if hallucination_risk >= 0.6 or grounding_score < 0.5:
        return "block"

    if context_sufficiency == "insufficient" or hallucination_risk >= 0.35:
        return "retrieve_more"

    if context_sufficiency == "partial" or grounding_score < 0.8:
        return "review"

    return "allow"


def _reason_codes(
    grounding_score: float,
    context_sufficiency: str,
    contradicted_claims: int,
    total_claims: int,
    hallucination_risk: float,
) -> list[str]:
    codes: list[str] = []

    if total_claims == 0:
        codes.append("RAG_NO_CHECKABLE_CLAIMS")

    if grounding_score < 0.6:
        codes.append("RAG_LOW_GROUNDING")

    if contradicted_claims > 0:
        codes.append("RAG_CONTRADICTION_DETECTED")

    if context_sufficiency == "insufficient":
        codes.append("RAG_CONTEXT_INSUFFICIENT")
    elif context_sufficiency == "partial":
        codes.append("RAG_CONTEXT_PARTIAL")

    if hallucination_risk >= 0.6:
        codes.append("RAG_HIGH_HALLUCINATION_RISK")

    return codes
