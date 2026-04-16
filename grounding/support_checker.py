"""Support checker for Layer A / E1.

This module evaluates whether a retrieved document supports, contradicts,
or is insufficient for a given claim.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, List, Literal, Sequence

from grounding.claim_extractor import Claim, extract_claims

SupportVerdict = Literal["supported", "contradicted", "insufficient"]


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

_NEGATION_WORDS = {"not", "never", "no", "none", "without", "cannot", "can't"}


@dataclass(frozen=True)
class RetrievedDocument:
    """Minimal representation of a retrieved context chunk/document."""

    doc_id: str
    text: str
    source_id: str | None = None


@dataclass(frozen=True)
class SupportResult:
    """Pairwise support evaluation output."""

    claim_id: str
    doc_id: str
    verdict: SupportVerdict
    confidence: float
    overlap_score: float
    reason: str


class SupportChecker:
    """Heuristic support checker for claim-document pairs.

    This baseline is deterministic and dependency-free so it can run in CI.
    """

    def __init__(
        self,
        supported_threshold: float = 0.55,
        weak_threshold: float = 0.30,
    ) -> None:
        self.supported_threshold = supported_threshold
        self.weak_threshold = weak_threshold

    def check_pair(self, claim_text: str, document_text: str, claim_id: str, doc_id: str) -> SupportResult:
        """Evaluate one claim against one retrieved document."""
        claim_tokens = _content_tokens(claim_text)
        doc_tokens = _content_tokens(document_text)

        if not claim_tokens or not doc_tokens:
            return SupportResult(
                claim_id=claim_id,
                doc_id=doc_id,
                verdict="insufficient",
                confidence=0.95,
                overlap_score=0.0,
                reason="empty_claim_or_document",
            )

        overlap_score = _overlap_ratio(claim_tokens, doc_tokens)
        number_signal = _number_signal(claim_text, document_text)
        contradiction_signal = _contradiction_signal(claim_text, document_text)

        adjusted_score = overlap_score
        if number_signal == "match":
            adjusted_score += 0.15
        elif number_signal == "mismatch":
            adjusted_score -= 0.20

        adjusted_score = max(0.0, min(1.0, adjusted_score))

        if contradiction_signal or number_signal == "mismatch":
            confidence = min(0.98, 0.65 + (1.0 - adjusted_score) * 0.35)
            reason = "contradiction_detected" if contradiction_signal else "numeric_mismatch"
            return SupportResult(
                claim_id=claim_id,
                doc_id=doc_id,
                verdict="contradicted",
                confidence=round(confidence, 3),
                overlap_score=round(adjusted_score, 3),
                reason=reason,
            )

        if adjusted_score >= self.supported_threshold:
            confidence = min(0.99, 0.55 + adjusted_score * 0.45)
            return SupportResult(
                claim_id=claim_id,
                doc_id=doc_id,
                verdict="supported",
                confidence=round(confidence, 3),
                overlap_score=round(adjusted_score, 3),
                reason="strong_overlap",
            )

        if adjusted_score >= self.weak_threshold:
            confidence = 0.5 + (self.supported_threshold - adjusted_score)
            return SupportResult(
                claim_id=claim_id,
                doc_id=doc_id,
                verdict="insufficient",
                confidence=round(min(0.9, confidence), 3),
                overlap_score=round(adjusted_score, 3),
                reason="partial_overlap",
            )

        return SupportResult(
            claim_id=claim_id,
            doc_id=doc_id,
            verdict="insufficient",
            confidence=0.9,
            overlap_score=round(adjusted_score, 3),
            reason="low_overlap",
        )

    def check_claim_against_documents(
        self,
        claim: Claim,
        documents: Sequence[RetrievedDocument],
    ) -> List[SupportResult]:
        """Evaluate one claim against all retrieved documents."""
        return [
            self.check_pair(claim_text=claim.text, document_text=doc.text, claim_id=claim.claim_id, doc_id=doc.doc_id)
            for doc in documents
        ]

    def check_all(
        self,
        claims: Sequence[Claim],
        documents: Sequence[RetrievedDocument],
    ) -> List[SupportResult]:
        """Evaluate all claim-document combinations."""
        results: List[SupportResult] = []
        for claim in claims:
            results.extend(self.check_claim_against_documents(claim, documents))
        return results


def check_all_support(
    claims: Sequence[Claim],
    documents: Sequence[RetrievedDocument],
) -> List[SupportResult]:
    """Convenience function for default support checking."""
    return SupportChecker().check_all(claims, documents)


def compute_grounding_score(answer: str, documents: Sequence[str] | Sequence[RetrievedDocument]) -> dict:
    """Compute groundedness metrics for an answer against retrieved documents.

    Args:
        answer: Assistant answer text.
        documents: Retrieved documents as raw strings or RetrievedDocument objects.

    Returns:
        A dictionary with aggregate grounding metrics and per-claim details.
    """
    claims = extract_claims(answer)
    normalized_documents = _normalize_documents(documents)
    checker = SupportChecker()

    details: List[dict] = []
    supported_count = 0
    contradicted_count = 0

    for claim in claims:
        pair_results = checker.check_claim_against_documents(claim, normalized_documents)
        best = _select_best_result(pair_results)

        if best.verdict == "supported":
            supported_count += 1
        elif best.verdict == "contradicted":
            contradicted_count += 1

        details.append(
            {
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
                        "doc_id": result.doc_id,
                        "verdict": result.verdict,
                        "confidence": result.confidence,
                        "overlap_score": result.overlap_score,
                        "reason": result.reason,
                    }
                    for result in pair_results
                ],
            }
        )

    total = len(claims)
    unsupported_count = total - supported_count
    insufficient_count = total - supported_count - contradicted_count

    return {
        "grounding_score": (supported_count / total) if total > 0 else 0.0,
        "supported_claims": supported_count,
        "unsupported_claims": unsupported_count,
        "contradicted_claims": contradicted_count,
        "insufficient_claims": max(0, insufficient_count),
        "total_claims": total,
        "details": details,
    }


def _content_tokens(text: str) -> List[str]:
    tokens = [token.lower() for token in re.findall(r"\b[\w'-]+\b", text)]
    return [token for token in tokens if token not in _STOPWORDS and len(token) > 1]


def _normalize_documents(documents: Sequence[str] | Sequence[RetrievedDocument]) -> List[RetrievedDocument]:
    if not documents:
        return []

    if isinstance(documents[0], RetrievedDocument):
        return list(documents)  # type: ignore[arg-type]

    return [RetrievedDocument(doc_id=f"d{i + 1}", text=doc_text) for i, doc_text in enumerate(documents)]


def _select_best_result(results: Sequence[SupportResult]) -> SupportResult:
    if not results:
        return SupportResult(
            claim_id="unknown",
            doc_id="none",
            verdict="insufficient",
            confidence=1.0,
            overlap_score=0.0,
            reason="no_documents",
        )

    supported = [r for r in results if r.verdict == "supported"]
    if supported:
        return max(supported, key=lambda r: (r.overlap_score, r.confidence))

    contradicted = [r for r in results if r.verdict == "contradicted"]
    if contradicted:
        return max(contradicted, key=lambda r: (r.confidence, r.overlap_score))

    return max(results, key=lambda r: (r.overlap_score, -r.confidence))


def _overlap_ratio(claim_tokens: Iterable[str], doc_tokens: Iterable[str]) -> float:
    claim_set = set(claim_tokens)
    doc_set = set(doc_tokens)
    if not claim_set:
        return 0.0
    overlap = claim_set.intersection(doc_set)
    return len(overlap) / len(claim_set)


def _extract_numbers(text: str) -> List[str]:
    return re.findall(r"\b\d+(?:[.,]\d+)?\b", text)


def _number_signal(claim_text: str, document_text: str) -> Literal["none", "match", "mismatch"]:
    claim_numbers = set(_extract_numbers(claim_text))
    if not claim_numbers:
        return "none"

    doc_numbers = set(_extract_numbers(document_text))
    if not doc_numbers:
        return "mismatch"

    if claim_numbers.intersection(doc_numbers):
        return "match"

    return "mismatch"


def _has_negation(text: str) -> bool:
    lowered = text.lower()
    return any(word in lowered.split() for word in _NEGATION_WORDS)


def _contradiction_signal(claim_text: str, document_text: str) -> bool:
    # Negation mismatch is a high-precision contradiction hint.
    claim_neg = _has_negation(claim_text)
    doc_neg = _has_negation(document_text)
    return claim_neg != doc_neg and _overlap_ratio(_content_tokens(claim_text), _content_tokens(document_text)) >= 0.5
