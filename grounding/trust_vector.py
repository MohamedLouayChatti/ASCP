"""Full trust vector assembly for Layer A.

Combines:
  E1 — grounding signals (claim support checker)
  E2 — context sufficiency and retrieval relevance
  E3 — consistency check (self-contradiction + doc-contradiction)

Design rule:
  Claims are extracted ONCE via LocalLLMClaimExtractor and shared
  across E1 and E3. Never extract twice for the same answer.
  E2 does not need claims — it works on query + documents only.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, List, Sequence

from common.config import settings
from grounding.llm_claim_extractor import LocalLLMClaimExtractor
from grounding.support_checker import (
    RetrievedDocument,
    SupportChecker,
    _normalize_documents,
    _select_best_result,
)
from grounding.sufficiency import check_sufficiency
from grounding.consistency_checker import check_consistency


# ── Main entry point ──────────────────────────────────────────────────────────

def assemble_trust_vector(
    query: str,
    answer: str,
    documents: Sequence[str] | Sequence[RetrievedDocument],
    answer_id: str = "",
) -> dict:
    """
    Assemble a full Layer A trust vector for one answer.

    Args:
        query     : User query / task prompt.
        answer    : Assistant answer to evaluate.
        documents : Retrieved context as raw strings or RetrievedDocument items.
        answer_id : Optional ID for telemetry correlation across layers.

    Returns:
        Trust vector dict with signals, counts, E3 results,
        decision hint, and reason codes.
    """

    # ── Step 0 — Normalize documents once ────────────────────────────
    normalized_docs = _normalize_documents(documents)
    document_texts = [doc.text for doc in normalized_docs]
    doc_ids = [doc.doc_id for doc in normalized_docs]

    # ── Step 1 — Extract claims ONCE (shared by E1 and E3) ───────────
    extractor = LocalLLMClaimExtractor(
        model=settings.ollama_model,
        ollama_url=settings.ollama_url,
        timeout_seconds=settings.ollama_timeout,
        fallback_on_error=True,
    )
    extraction = extractor.extract(answer, answer_id=answer_id)
    claims = extraction.claims

    # ── Step 2 — E1: Grounding (support check) ───────────────────────
    grounding = _run_grounding(claims, normalized_docs)

    # ── Step 3 — E2: Context sufficiency ─────────────────────────────
    sufficiency = check_sufficiency(
        query=query,
        documents=document_texts,
        use_semantic=settings.use_semantic_checker,
    )
    sufficiency_payload = _sufficiency_to_dict(sufficiency)

    # ── Step 4 — E3: Consistency check (reuses same claims) ──────────
    consistency = check_consistency(
        claims=claims,               # same claims — no second extraction
        documents=document_texts,
        doc_ids=doc_ids,
        use_semantic=settings.use_semantic_checker,
    )

    # ── Step 5 — Aggregate signals ────────────────────────────────────
    contradiction_ratio = _safe_ratio(
        grounding.get("contradicted_claims", 0),
        grounding.get("total_claims", 0),
    )

    hallucination_risk = _compute_hallucination_risk(
        grounding_score=grounding.get("grounding_score", 0.0),
        contradiction_ratio=contradiction_ratio,
        retrieval_relevance=sufficiency_payload.get("retrieval_relevance", 0.0),
        consistency_risk=consistency.contradiction_risk,
    )

    # ── Step 6 — Assemble output ──────────────────────────────────────
    return {
        "trust_vector_version": "v2",
        "answer_id": answer_id,
        "query": query,
        "answer": answer,

        # ── Core signals ──────────────────────────────────────────────
        "signals": {
            # E1
            "grounding_score": grounding.get("grounding_score", 0.0),
            "hallucination_risk": hallucination_risk,
            "contradiction_ratio": round(contradiction_ratio, 3),
            # E2
            "retrieval_relevance": sufficiency_payload.get("retrieval_relevance", 0.0),
            "context_sufficiency": sufficiency_payload.get("context_sufficiency", "insufficient"),
            # E3
            "consistency_risk": consistency.contradiction_risk,
            "has_contradiction": consistency.has_contradiction,
        },

        # ── Claim-level counts ────────────────────────────────────────
        "counts": {
            "supported_claims": grounding.get("supported_claims", 0),
            "unsupported_claims": grounding.get("unsupported_claims", 0),
            "contradicted_claims": grounding.get("contradicted_claims", 0),
            "insufficient_claims": grounding.get("insufficient_claims", 0),
            "total_claims": grounding.get("total_claims", 0),
            "covered_keywords": sufficiency_payload.get("covered_keywords", 0),
            "total_keywords": sufficiency_payload.get("total_keywords", 0),
            "self_contradictions": consistency.self_contradiction_count,
            "doc_contradictions": consistency.doc_contradiction_count,
        },

        # ── E4 policy decision ────────────────────────────────────────
        "decision_hint": _decision_hint(
            grounding_score=grounding.get("grounding_score", 0.0),
            context_sufficiency=sufficiency_payload.get("context_sufficiency", "insufficient"),
            hallucination_risk=hallucination_risk,
            has_contradiction=consistency.has_contradiction,
            consistency_risk=consistency.contradiction_risk,
        ),
        "reason_codes": _reason_codes(
            grounding_score=grounding.get("grounding_score", 0.0),
            context_sufficiency=sufficiency_payload.get("context_sufficiency", "insufficient"),
            contradicted_claims=grounding.get("contradicted_claims", 0),
            total_claims=grounding.get("total_claims", 0),
            hallucination_risk=hallucination_risk,
            has_contradiction=consistency.has_contradiction,
            self_contradiction_count=consistency.self_contradiction_count,
            doc_contradiction_count=consistency.doc_contradiction_count,
            contradiction_pairs=consistency.contradiction_pairs,
        ),

        # ── Full detail payloads for Layer D telemetry ────────────────
        "details": {
            "grounding": grounding,
            "sufficiency": sufficiency_payload,
            "consistency": {
                "has_contradiction": consistency.has_contradiction,
                "contradiction_risk": consistency.contradiction_risk,
                "self_contradiction_count": consistency.self_contradiction_count,
                "doc_contradiction_count": consistency.doc_contradiction_count,
                "checked_claim_pairs": consistency.checked_claim_pairs,
                "checked_doc_pairs": consistency.checked_doc_pairs,
                "contradiction_pairs": [
                    {
                        "type": p.contradiction_type,
                        "claim_a_id": p.claim_a_id,
                        "claim_b_id": p.claim_b_id,
                        "claim_a_text": p.claim_a_text,
                        "claim_b_text": p.claim_b_text,
                        "confidence": p.confidence,
                        "reason": p.reason,
                        "reason_code": p.reason_code,
                    }
                    for p in consistency.contradiction_pairs
                ],
            },
        },

        # ── Extraction metadata for Layer D ───────────────────────────
        "extraction_meta": {
            "model": extraction.model,
            "used_fallback": extraction.used_fallback,
            "latency_ms": extraction.latency_ms,
            "total_claims_extracted": len(claims),
        },
    }


# ── E1: Grounding runner ──────────────────────────────────────────────────────

def _run_grounding(
    claims: list,
    normalized_docs: List[RetrievedDocument],
) -> dict:
    """
    Run E1 support check on pre-extracted claims.
    Does NOT re-extract — claims come from the shared extraction step.
    """
    checker = SupportChecker(
        use_semantic=settings.use_semantic_checker,
        semantic_weight=settings.semantic_weight,
        token_weight=settings.token_weight,
        bge_model=settings.bge_model,
        bge_timeout=settings.bge_timeout,
    )

    details = []
    supported_count = 0
    contradicted_count = 0

    for claim in claims:
        pair_results = checker.check_claim_against_documents(
            claim, normalized_docs
        )
        best = _select_best_result(pair_results)

        if best.verdict == "supported":
            supported_count += 1
        elif best.verdict == "contradicted":
            contradicted_count += 1

        details.append({
            "claim": claim.text,
            "claim_id": claim.claim_id,
            "best_result": {
                "doc_id": best.doc_id,
                "verdict": best.verdict,
                "confidence": best.confidence,
                "overlap_score": best.overlap_score,
                "reason": best.reason,
            },
            "all_results": [
                {
                    "doc_id": r.doc_id,
                    "verdict": r.verdict,
                    "confidence": r.confidence,
                    "overlap_score": r.overlap_score,
                    "reason": r.reason,
                }
                for r in pair_results
            ],
        })

    total = len(claims)
    insufficient_count = total - supported_count - contradicted_count

    return {
        "grounding_score": round(supported_count / total, 3) if total > 0 else 0.0,
        "supported_claims": supported_count,
        "unsupported_claims": total - supported_count,
        "contradicted_claims": contradicted_count,
        "insufficient_claims": max(0, insufficient_count),
        "total_claims": total,
        "details": details,
    }


# ── Hallucination risk ────────────────────────────────────────────────────────

def _compute_hallucination_risk(
    grounding_score: float,
    contradiction_ratio: float,
    retrieval_relevance: float,
    consistency_risk: float,
) -> float:
    """
    Weighted hallucination risk combining E1, E2, E3 signals.

    Weights:
      0.45 — grounding score (primary E1 signal)
      0.25 — E3 consistency risk (active contradiction)
      0.20 — contradiction ratio (E1 contradicted claims)
      0.10 — retrieval relevance (E2 signal)

    E3 consistency_risk is now a first-class input — previously
    the old v1 trust vector had no E3 signal at all.
    """
    risk = (
        0.45 * (1.0 - grounding_score)
        + 0.25 * consistency_risk
        + 0.20 * contradiction_ratio
        + 0.10 * (1.0 - retrieval_relevance)
    )
    return round(max(0.0, min(1.0, risk)), 3)


# ── Decision hint (E4 input) ──────────────────────────────────────────────────

def _decision_hint(
    grounding_score: float,
    context_sufficiency: str,
    hallucination_risk: float,
    has_contradiction: bool,
    consistency_risk: float,
) -> str:
    """
    Policy-oriented decision hint for E4.
    Returns one of: "block" | "retrieve_more" | "review" | "allow"

    Priority order:
    1. Active contradiction detected by E3 → block immediately
    2. High hallucination risk or low grounding → block
    3. Insufficient context → retrieve more
    4. Partial context or borderline grounding → review
    5. All signals healthy → allow
    """

    # E3 contradiction is highest priority — security-critical
    if has_contradiction and consistency_risk >= 0.50:
        return "block"

    if hallucination_risk >= 0.60 or grounding_score < 0.50:
        return "block"

    if context_sufficiency == "insufficient":
        return "retrieve_more"

    if hallucination_risk >= 0.35 or has_contradiction:
        return "review"

    if context_sufficiency == "partial" or grounding_score < 0.80:
        return "review"

    return "allow"


# ── Reason codes ──────────────────────────────────────────────────────────────

def _reason_codes(
    grounding_score: float,
    context_sufficiency: str,
    contradicted_claims: int,
    total_claims: int,
    hallucination_risk: float,
    has_contradiction: bool,
    self_contradiction_count: int,
    doc_contradiction_count: int,
    contradiction_pairs: list,
) -> list[str]:
    """
    Machine-readable reason codes for Layer D telemetry.
    Each code maps to a specific invariant from the ASCP spec.
    """
    codes: list[str] = []

    if total_claims == 0:
        codes.append("RAG_NO_CHECKABLE_CLAIMS")

    if grounding_score < 0.60:
        codes.append("RAG_LOW_GROUNDING")

    if contradicted_claims > 0:
        codes.append("RAG_E1_CONTRADICTION_DETECTED")

    if context_sufficiency == "insufficient":
        codes.append("RAG_CONTEXT_INSUFFICIENT")
    elif context_sufficiency == "partial":
        codes.append("RAG_CONTEXT_PARTIAL")

    if hallucination_risk >= 0.60:
        codes.append("RAG_HIGH_HALLUCINATION_RISK")

    # E3-specific codes — new in v2
    if self_contradiction_count > 0:
        codes.append("RAG_E3_SELF_CONTRADICTION")

    if doc_contradiction_count > 0:
        codes.append("RAG_E3_DOC_CONTRADICTION")

    # Surface the specific E3 reason codes from ContradictionPairs
    # These map directly to Layer D telemetry event types
    e3_codes = {p.reason_code for p in contradiction_pairs}
    codes.extend(sorted(e3_codes))

    return codes


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sufficiency_to_dict(sufficiency: Any) -> dict:
    if isinstance(sufficiency, dict):
        return sufficiency
    if is_dataclass(sufficiency):
        return asdict(sufficiency)
    if hasattr(sufficiency, "__dict__"):
        return dict(sufficiency.__dict__)
    return {}


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator