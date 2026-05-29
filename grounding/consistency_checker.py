"""Consistency checker for Layer A / E3.

Detects two types of contradiction:
  Type 1 — Self-contradiction : claims in the answer conflict with each other
  Type 2 — Doc-contradiction  : claims conflict with source documents

Integration note:
  Accepts claims already extracted by LocalLLMClaimExtractor (ExtractionResult.claims)
  OR accepts a raw answer string and runs extraction internally.
  This matches the pattern used by compute_grounding_score in support_checker.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Literal, Optional, Sequence

from grounding.llm_claim_extractor import Claim, LocalLLMClaimExtractor
from grounding.semantic_scorer import get_embedding, cosine_similarity
from grounding.text_utils import content_tokens, has_negation, topic_overlap
from common.config import settings

# ── Types ─────────────────────────────────────────────────────────────────────

ContradictionType = Literal["self_contradiction", "doc_contradiction"]

# ── Vocabulary ────────────────────────────────────────────────────────────────


_ANTONYM_PAIRS = [
    ("allowed",    "forbidden"),
    ("allowed",    "prohibited"),
    ("allowed",    "denied"),
    ("allowed",    "blocked"),
    ("allowed",    "disallowed"),
    ("enabled",    "disabled"),
    ("active",     "inactive"),
    ("authorized", "unauthorized"),
    ("secure",     "insecure"),
    ("encrypted",  "unencrypted"),
    ("required",   "optional"),
    ("mandatory",  "optional"),
    ("public",     "private"),
    ("internal",   "external"),
    ("permitted",  "forbidden"),
    ("permitted",  "prohibited"),
    ("true",       "false"),
    ("valid",      "invalid"),
    ("success",    "failure"),
    ("increase",   "decrease"),
    ("pass",       "fail"),
    ("grant",      "deny"),
    ("grant",      "revoke"),
]

_ANTONYM_STEMS: dict[str, str] = {
    "allowed": "allow",
    "forbidden": "forbi",
    "prohibited": "prohib",
    "prohibits": "prohib",
    "denied": "deni",
    "blocked": "block",
    "disallowed": "disall",
    "enabled": "enabl",
    "disabled": "disabl",
    "active": "activ",
    "inactive": "inactiv",
    "authorized": "author",
    "unauthorized": "unauth",
    "secure": "secur",
    "insecure": "insecur",
    "encrypted": "encrypt",
    "unencrypted": "unencrypt",
    "required": "requir",
    "optional": "option",
    "mandatory": "mandator",
    "public": "public",
    "private": "privat",
    "internal": "intern",
    "external": "extern",
    "permitted": "permi",
    "true": "true",
    "false": "fals",
    "valid": "valid",
    "invalid": "invalid",
    "success": "success",
    "failure": "failur",
    "increase": "increas",
    "decrease": "decreas",
    "pass": "pass",
    "fail": "fail",
    "grant": "grant",
    "deny": "deni",
    "revoke": "revok",
}


def _get_stem(word: str) -> str:
    """Get the regex stem for a word. Falls back to first 5 chars."""
    return _ANTONYM_STEMS.get(word, word[:5])

# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ContradictionPair:
    """
    A single detected contradiction — structured for Layer D telemetry.
    Every field is machine-readable for incident reports.
    """
    contradiction_type: ContradictionType
    claim_a_id: str
    claim_b_id: str         # claim ID (self) or doc_id (doc contradiction)
    claim_a_text: str
    claim_b_text: str       # conflicting claim text or doc sentence
    confidence: float
    reason: str             # human-readable — shown in decision panel
    reason_code: str        # machine-readable — used by Layer D


@dataclass
class ConsistencyResult:
    """Full E3 output — feeds directly into TrustVector."""
    has_contradiction: bool
    contradiction_risk: float
    self_contradiction_count: int
    doc_contradiction_count: int
    contradiction_pairs: List[ContradictionPair] = field(default_factory=list)
    checked_claim_pairs: int = 0
    checked_doc_pairs: int = 0
    # Extractor metadata — carried through for Layer D telemetry
    extraction_used_fallback: bool = False
    extraction_latency_ms: float = 0.0




def _best_matching_sentence(
    claim_text: str,
    doc_text: str,
) -> tuple[str, float]:
    """
    Find the sentence in doc_text most topically related to claim_text.
    Scopes all contradiction checks to the relevant part of the document —
    prevents false positives from unrelated content in long documents.
    """
    sentences = re.split(r"(?<=[.!?])\s+", doc_text)
    best_sent, best_score = "", 0.0
    for sent in sentences:
        score = topic_overlap(claim_text, sent)
        if score > best_score:
            best_score = score
            best_sent = sent
    return best_sent, best_score


# ── Detection primitives ──────────────────────────────────────────────────────

def _detect_antonym_conflict(
    text_a: str,
    text_b: str,
    min_topic_overlap: float = 0.20,
) -> tuple[bool, str]:
    """
    Check for opposing antonym pairs between two texts.
    Most reliable signal for security policy text — catches
    'allowed vs forbidden', 'authorized vs unauthorized' etc.
    without requiring any negation word to be present.
    """
    if topic_overlap(text_a, text_b) < min_topic_overlap:
        return False, ""
    lower_a, lower_b = text_a.lower(), text_b.lower()
    for word_a, word_b in _ANTONYM_PAIRS:
        stem_a = _get_stem(word_a)
        stem_b = _get_stem(word_b)
        a_has_a = bool(re.search(rf"\b{re.escape(stem_a)}\w*\b", lower_a))
        b_has_b = bool(re.search(rf"\b{re.escape(stem_b)}\w*\b", lower_b))
        a_has_b = bool(re.search(rf"\b{re.escape(stem_b)}\w*\b", lower_a))
        b_has_a = bool(re.search(rf"\b{re.escape(stem_a)}\w*\b", lower_b))
        if (a_has_a and b_has_b) or (a_has_b and b_has_a):
            return True, f"'{word_a}' vs '{word_b}'"
    return False, ""


def _detect_negation_conflict(
    text_a: str,
    text_b: str,
    min_overlap: float = 0.25,
) -> bool:
    """
    Negation polarity mismatch on topically related texts.
    Stricter overlap threshold than support_checker (0.35 vs 0.30)
    because here we are building a telemetry record — fewer false
    positives preferred over higher recall.
    """
    if topic_overlap(text_a, text_b) < min_overlap:
        return False
    return has_negation(text_a) != has_negation(text_b)


def _detect_numeric_conflict(
    text_a: str,
    text_b: str,
    min_overlap: float = 0.35,
) -> tuple[bool, str]:
    """
    Numeric value conflict on topically related texts.
    Both texts contain numbers, no numbers are shared,
    and they discuss the same topic = contradicting numeric claims.
    """
    if topic_overlap(text_a, text_b) < min_overlap:
        return False, ""
    nums_a = set(re.findall(r"\b\d+(?:[.,]\d+)?\b", text_a))
    nums_b = set(re.findall(r"\b\d+(?:[.,]\d+)?\b", text_b))
    if not nums_a or not nums_b or (nums_a & nums_b):
        return False, ""
    return True, f"{nums_a} vs {nums_b}"


def _detect_semantic_contradiction(
    text_a: str,
    text_b: str,
    min_topic_overlap: float = 0.30,
    min_semantic_similarity: float = 0.20,
    max_semantic_similarity: float = 0.50,
) -> tuple[bool, float]:
    """
    BGE-based semantic contradiction detection.
    Topically related texts (share keywords) that are semantically
    dissimilar (low cosine) are likely contradicting each other.
    Catches paraphrased contradictions that rule-based methods miss.

    Only runs after methods 1-3 all miss — avoids unnecessary
    embedding calls since llama3.2:1b is already under load.
    """
    if topic_overlap(text_a, text_b) < min_topic_overlap:
        return False, 0.0
    vec_a = get_embedding(text_a)
    vec_b = get_embedding(text_b)
    if vec_a is None or vec_b is None:
        return False, 0.0
    similarity = cosine_similarity(vec_a, vec_b)
    in_contradiction_zone = min_semantic_similarity < similarity < max_semantic_similarity
    return in_contradiction_zone, similarity


# ── Part 1 — Self-contradiction ───────────────────────────────────────────────

def _check_self_contradiction(
    claim_a: Claim,
    claim_b: Claim,
    use_semantic: bool,
) -> ContradictionPair | None:
    """
    Check if two claims from the SAME answer contradict each other.
    Claims come from LocalLLMClaimExtractor — they are already atomic
    and pronoun-resolved, which makes self-contradiction more detectable
    than with regex-extracted claims.
    """
    # Gate: unrelated topics cannot contradict
    if topic_overlap(claim_a.text, claim_b.text) < 0.15:
        return None

    # Method 1 — Antonym (fastest, most precise)
    antonym_found, antonym_desc = _detect_antonym_conflict(
        claim_a.text, claim_b.text
    )
    if antonym_found:
        return ContradictionPair(
            contradiction_type="self_contradiction",
            claim_a_id=claim_a.claim_id,
            claim_b_id=claim_b.claim_id,
            claim_a_text=claim_a.text,
            claim_b_text=claim_b.text,
            confidence=0.88,
            reason=f"Answer contains conflicting terms: {antonym_desc}",
            reason_code="E3_SELF_ANTONYM",
        )

    # Method 2 — Negation polarity
    if _detect_negation_conflict(claim_a.text, claim_b.text, min_overlap=0.25):
        return ContradictionPair(
            contradiction_type="self_contradiction",
            claim_a_id=claim_a.claim_id,
            claim_b_id=claim_b.claim_id,
            claim_a_text=claim_a.text,
            claim_b_text=claim_b.text,
            confidence=0.75,
            reason="Answer affirms and denies the same topic",
            reason_code="E3_SELF_NEGATION",
        )

    # Method 3 — Numeric conflict
    num_found, num_desc = _detect_numeric_conflict(
        claim_a.text, claim_b.text, min_overlap=0.35
    )
    if num_found:
        return ContradictionPair(
            contradiction_type="self_contradiction",
            claim_a_id=claim_a.claim_id,
            claim_b_id=claim_b.claim_id,
            claim_a_text=claim_a.text,
            claim_b_text=claim_b.text,
            confidence=0.78,
            reason=f"Answer contains conflicting numeric values: {num_desc}",
            reason_code="E3_SELF_NUMERIC",
        )

    # Method 4 — BGE semantic (only if 1-3 all missed)
    if use_semantic:
        sem_found, similarity = _detect_semantic_contradiction(
            claim_a.text, claim_b.text
        )
        if sem_found:
            return ContradictionPair(
                contradiction_type="self_contradiction",
                claim_a_id=claim_a.claim_id,
                claim_b_id=claim_b.claim_id,
                claim_a_text=claim_a.text,
                claim_b_text=claim_b.text,
                confidence=round(max(0.55, 0.75 - similarity), 3),
                reason=f"Semantic contradiction in answer (similarity={similarity:.3f})",
                reason_code="E3_SELF_SEMANTIC",
            )

    return None


# ── Part 2 — Document contradiction ──────────────────────────────────────────

def _check_doc_contradiction(
    claim: Claim,
    doc_id: str,
    doc_text: str,
    use_semantic: bool,
) -> ContradictionPair | None:
    """
    Check if a claim contradicts a source document.
    Most security-critical check in E3 — AI saying the opposite
    of what the policy document says.

    Uses best-matching sentence scoping throughout — never compares
    the claim against the full document to avoid false positives
    from unrelated content in long policy documents.
    """
    best_sent, best_overlap = _best_matching_sentence(claim.text, doc_text)
    if best_overlap < 0.20 or not best_sent:
        return None

    # Method 1 — Antonym (highest confidence for policy text)
    antonym_found, antonym_desc = _detect_antonym_conflict(
        claim.text, best_sent
    )
    if antonym_found:
        return ContradictionPair(
            contradiction_type="doc_contradiction",
            claim_a_id=claim.claim_id,
            claim_b_id=doc_id,
            claim_a_text=claim.text,
            claim_b_text=best_sent,
            confidence=0.92,
            reason=f"Claim contradicts document: {antonym_desc}",
            reason_code="E3_DOC_ANTONYM",
        )

    # Method 2 — Negation polarity
    # Runs here even though support_checker also catches this —
    # we need the ContradictionPair for Layer D telemetry regardless
    if _detect_negation_conflict(claim.text, best_sent, min_overlap=0.40):
        return ContradictionPair(
            contradiction_type="doc_contradiction",
            claim_a_id=claim.claim_id,
            claim_b_id=doc_id,
            claim_a_text=claim.text,
            claim_b_text=best_sent,
            confidence=0.80,
            reason="Claim negation polarity conflicts with document",
            reason_code="E3_DOC_NEGATION",
        )

    # Method 3 — Numeric (check full doc — numbers can appear anywhere)
    num_found, num_desc = _detect_numeric_conflict(
        claim.text, doc_text, min_overlap=0.30
    )
    if num_found:
        return ContradictionPair(
            contradiction_type="doc_contradiction",
            claim_a_id=claim.claim_id,
            claim_b_id=doc_id,
            claim_a_text=claim.text,
            claim_b_text=best_sent,
            confidence=0.72,
            reason=f"Claim numeric value conflicts with document: {num_desc}",
            reason_code="E3_DOC_NUMERIC",
        )

    # Method 4 — BGE semantic (claim vs best sentence only)
    if use_semantic:
        sem_found, similarity = _detect_semantic_contradiction(
            claim.text, best_sent
        )
        if sem_found:
            return ContradictionPair(
                contradiction_type="doc_contradiction",
                claim_a_id=claim.claim_id,
                claim_b_id=doc_id,
                claim_a_text=claim.text,
                claim_b_text=best_sent,
                confidence=round(max(0.55, 0.75 - similarity), 3),
                reason=f"Semantic contradiction with document (similarity={similarity:.3f})",
                reason_code="E3_DOC_SEMANTIC",
            )

    return None


# ── Main checker ──────────────────────────────────────────────────────────────

class ConsistencyChecker:
    """
    Full E3 consistency checker.
    Accepts claims from LocalLLMClaimExtractor directly.
    """

    def __init__(self, use_semantic: bool = True) -> None:
        self.use_semantic = use_semantic

    def check(
        self,
        claims: Sequence[Claim],
        documents: Sequence[str],
        doc_ids: Sequence[str] | None = None,
    ) -> ConsistencyResult:
        if doc_ids is None:
            doc_ids = [f"d{i+1}" for i in range(len(documents))]

        pairs: List[ContradictionPair] = []
        checked_claim_pairs = 0
        checked_doc_pairs = 0
        claims_list = list(claims)

        # Sweep 1 — Self-contradiction (claim vs claim)
        for i, claim_a in enumerate(claims_list):
            for claim_b in claims_list[i + 1:]:
                checked_claim_pairs += 1
                if topic_overlap(claim_a.text, claim_b.text) < 0.10:
                    continue
                result = _check_self_contradiction(
                    claim_a, claim_b, self.use_semantic
                )
                if result:
                    pairs.append(result)

        # Sweep 2 — Document contradiction (claim vs document)
        for claim in claims_list:
            for doc_id, doc_text in zip(doc_ids, documents):
                checked_doc_pairs += 1
                result = _check_doc_contradiction(
                    claim, doc_id, doc_text, self.use_semantic
                )
                if result:
                    pairs.append(result)

        # Risk scoring
        self_count = sum(
            1 for p in pairs if p.contradiction_type == "self_contradiction"
        )
        doc_count = sum(
            1 for p in pairs if p.contradiction_type == "doc_contradiction"
        )

        doc_rate = doc_count / max(checked_doc_pairs, 1)
        self_rate = self_count / max(checked_claim_pairs, 1)

        # Doc contradictions weighted higher — core ASCP security mission
        risk = min(1.0, (self_rate * 0.30) + (doc_rate * 0.70))

        # Any high-confidence hit floors risk at 0.50
        if any(p.confidence >= 0.85 for p in pairs):
            risk = max(risk, 0.50)

        return ConsistencyResult(
            has_contradiction=len(pairs) > 0,
            contradiction_risk=round(risk, 3),
            self_contradiction_count=self_count,
            doc_contradiction_count=doc_count,
            contradiction_pairs=pairs,
            checked_claim_pairs=checked_claim_pairs,
            checked_doc_pairs=checked_doc_pairs,
        )


# ── Convenience functions ─────────────────────────────────────────────────────

def check_consistency(
    claims: Sequence[Claim],
    documents: Sequence[str],
    doc_ids: Sequence[str] | None = None,
    use_semantic: bool = True,
) -> ConsistencyResult:
    """
    Check consistency from already-extracted claims.
    Use this when you already ran LocalLLMClaimExtractor upstream
    (e.g. in trust_vector.py where claims are shared across E1/E2/E3).
    """
    return ConsistencyChecker(use_semantic=use_semantic).check(
        claims, documents, doc_ids
    )


def check_consistency_from_answer(
    answer: str,
    documents: Sequence[str],
    doc_ids: Sequence[str] | None = None,
    answer_id: str = "",
    use_semantic: bool = True,
) -> ConsistencyResult:
    """
    Check consistency starting from a raw answer string.
    Runs LocalLLMClaimExtractor internally — use this when you need
    to run E3 standalone without a prior E1 pass.

    Carries extraction metadata (fallback flag, latency) into the result
    for Layer D telemetry.
    """
    extractor = LocalLLMClaimExtractor(
        model=settings.ollama_model,
        ollama_url=settings.ollama_url,
        timeout_seconds=settings.ollama_timeout,
        fallback_on_error=True,
    )
    extraction = extractor.extract(answer, answer_id=answer_id)

    result = ConsistencyChecker(use_semantic=use_semantic).check(
        extraction.claims, documents, doc_ids
    )

    # Attach extractor metadata to result for telemetry
    result.extraction_used_fallback = extraction.used_fallback
    result.extraction_latency_ms = extraction.latency_ms

    return result