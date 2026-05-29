"""Support checker for Layer A / E1.

This module evaluates whether a retrieved document supports, contradicts,
or is insufficient for a given claim.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, List, Literal, Sequence

from common.config import settings

from grounding.llm_claim_extractor import Claim, LocalLLMClaimExtractor
from grounding.semantic_scorer import best_semantic_score
from grounding.text_utils import _STOPWORDS, content_tokens, has_negation

SupportVerdict = Literal["supported", "contradicted", "insufficient"]




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
        use_semantic: bool = True,
        semantic_weight: float = 0.50,
        token_weight: float = 0.50,
        bge_model: str = settings.bge_model,
        bge_timeout: float = settings.bge_timeout,
    ) -> None:
        self.supported_threshold = supported_threshold
        self.weak_threshold = weak_threshold
        self.use_semantic = use_semantic
        self.semantic_weight = semantic_weight
        self.token_weight = token_weight
        self.bge_model = bge_model
        self.bge_timeout = bge_timeout

    def check_pair(self, claim_text: str, document_text: str, claim_id: str, doc_id: str) -> SupportResult:
        """Evaluate one claim against one retrieved document."""
        claim_tokens = list(content_tokens(claim_text))
        doc_tokens = list(content_tokens(document_text))
        return self._check_with_tokens(
            claim_text=claim_text,
            document_text=document_text,
            claim_id=claim_id,
            doc_id=doc_id,
            claim_tokens=claim_tokens,
            doc_tokens=doc_tokens,
        )

    def _check_with_tokens(
        self,
        claim_text: str,
        document_text: str,
        claim_id: str,
        doc_id: str,
        claim_tokens: List[str],
        doc_tokens: List[str],
    ) -> SupportResult:
        if not claim_tokens or not doc_tokens:
            return SupportResult(
                claim_id=claim_id,
                doc_id=doc_id,
                verdict="insufficient",
                confidence=0.95,
                overlap_score=0.0,
                reason="empty_claim_or_document",
            )

        contradiction_signal = _contradiction_signal(claim_text, document_text)
        if contradiction_signal:
            token_score = _best_sentence_overlap(claim_tokens, document_text)
            return SupportResult(
                claim_id=claim_id,
                doc_id=doc_id,
                verdict="contradicted",
                confidence=0.85,
                overlap_score=round(token_score, 3),
                reason="contradiction_detected",
            )

        token_score = _best_sentence_overlap(claim_tokens, document_text)

        semantic_score = 0.0
        if self.use_semantic:
            doc_sentences = re.split(r"(?<=[.!?])\s+", document_text)
            semantic_score, _best_span = best_semantic_score(
                claim_text,
                doc_sentences,
                model=self.bge_model,
                timeout=self.bge_timeout,
            )

        if self.use_semantic and semantic_score > 0:
            combined_score = (self.token_weight * token_score) + (self.semantic_weight * semantic_score)
        else:
            combined_score = token_score

        number_signal = _number_signal(claim_text, document_text)

        adjusted_score = combined_score
        if number_signal == "match":
            adjusted_score += 0.10
        elif number_signal == "mismatch":
            adjusted_score -= 0.10

        adjusted_score = max(0.0, min(1.0, adjusted_score))

        if adjusted_score >= self.supported_threshold:
            confidence = min(0.99, 0.55 + adjusted_score * 0.45)
            return SupportResult(
                claim_id=claim_id,
                doc_id=doc_id,
                verdict="supported",
                confidence=round(confidence, 3),
                overlap_score=round(adjusted_score, 3),
                reason="semantic_and_token_overlap" if self.use_semantic else "strong_overlap",
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
        doc_token_cache = {doc.doc_id: _content_tokens(doc.text) for doc in documents}
        results: List[SupportResult] = []
        for claim in claims:
            claim_tokens = list(content_tokens(claim.text))
            for doc in documents:
                doc_tokens = doc_token_cache[doc.doc_id]
                results.append(
                    self._check_with_tokens(
                        claim_text=claim.text,
                        document_text=doc.text,
                        claim_id=claim.claim_id,
                        doc_id=doc.doc_id,
                        claim_tokens=claim_tokens,
                        doc_tokens=doc_tokens,
                    )
                )
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
    extractor = LocalLLMClaimExtractor(
        model=settings.ollama_model,
        ollama_url=settings.ollama_url,
        timeout_seconds=settings.ollama_timeout,
    )
    claims = extractor.extract(answer).claims
    normalized_documents = _normalize_documents(documents)
    checker = SupportChecker(
        use_semantic=settings.use_semantic_checker,
        semantic_weight=settings.semantic_weight,
        token_weight=settings.token_weight,
        bge_model=settings.bge_model,
        bge_timeout=settings.bge_timeout,
    )

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
    union = claim_set.union(doc_set)
    return len(overlap) / len(union)


def _best_sentence_overlap(claim_tokens: List[str], doc_text: str) -> float:
    """Score claim against each sentence individually, return best score."""
    sentences = re.split(r"(?<=[.!?])\s+", doc_text)
    best = 0.0
    claim_set = set(claim_tokens)
    if not claim_set:
        return 0.0

    for sent in sentences:
        sent_tokens = content_tokens(sent)
        if not sent_tokens:
            continue
        score = _overlap_ratio(claim_set, sent_tokens)
        if score > best:
            best = score
    return best


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


def _contradiction_signal(claim_text: str, document_text: str) -> bool:
    """
    Only flag contradiction if the most-overlapping sentence
    has opposite negation polarity.
    """
    sentences = re.split(r"(?<=[.!?])\s+", document_text)
    claim_set = content_tokens(claim_text)
    claim_neg = has_negation(claim_text)

    best_sent = ""
    best_score = 0.0
    for sent in sentences:
        sent_tokens = content_tokens(sent)
        if not sent_tokens or not claim_set:
            continue
        overlap = claim_set & sent_tokens
        score = len(overlap) / len(claim_set)
        if score > best_score:
            best_score = score
            best_sent = sent

    if best_score < 0.35 or not best_sent:
        return False

    sent_neg = has_negation(best_sent)
    return claim_neg != sent_neg
