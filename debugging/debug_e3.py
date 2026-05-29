# debugging/debug_e3.py

import sys
sys.path.insert(0, ".")

from grounding.consistency_checker import (
    _best_matching_sentence,
    _detect_antonym_conflict,
    _detect_negation_conflict,
    _check_doc_contradiction,
    _ANTONYM_PAIRS,
)
from grounding.llm_claim_extractor import Claim, LocalLLMClaimExtractor
from grounding.text_utils import _NEGATION_WORDS, _STOPWORDS, content_tokens, topic_overlap
from common.config import settings

# ── The exact texts from the smoke test ──────────────────────────────────────

claim_text = "External access is allowed for all verified users."
doc_text = (
    "The security policy strictly forbids external access except for "
    "approved contractors with explicit written authorization."
)

print("=" * 60)
print("STEP 0 — Vocabulary check")
print("=" * 60)
print(f"_ANTONYM_PAIRS populated : {len(_ANTONYM_PAIRS)} pairs")
print(f"_NEGATION_WORDS populated: {len(_NEGATION_WORDS)} words")
print(f"_STOPWORDS populated     : {len(_STOPWORDS)} words")
print()

# ── Step 1 — What tokens survive after filtering ─────────────────────────────

print("=" * 60)
print("STEP 1 — Token extraction")
print("=" * 60)
claim_tokens = content_tokens(claim_text)
doc_tokens = content_tokens(doc_text)
print(f"Claim tokens : {claim_tokens}")
print(f"Doc tokens   : {doc_tokens}")
print(f"Shared tokens: {claim_tokens & doc_tokens}")
print()

# ── Step 2 — Topic overlap gate ───────────────────────────────────────────────

print("=" * 60)
print("STEP 2 — Topic overlap gate")
print("=" * 60)
overlap = topic_overlap(claim_text, doc_text)
print(f"Topic overlap      : {overlap:.3f}")
print(f"Gate 0.25 passes   : {overlap >= 0.25}")
print(f"Gate 0.20 passes   : {overlap >= 0.20}")
print()

# ── Step 3 — Best matching sentence ──────────────────────────────────────────

print("=" * 60)
print("STEP 3 — Best matching sentence")
print("=" * 60)
best_sent, best_score = _best_matching_sentence(claim_text, doc_text)
print(f"Best sentence : '{best_sent}'")
print(f"Best score    : {best_score:.3f}")
print(f"Gate 0.25     : {best_score >= 0.25}")
print()

# ── Step 4 — Antonym detection ────────────────────────────────────────────────

print("=" * 60)
print("STEP 4 — Antonym detection")
print("=" * 60)

# Check all relevant antonym pairs manually
import re
lower_claim = claim_text.lower()
lower_doc = doc_text.lower()
lower_sent = best_sent.lower()

print("Manual antonym scan:")
for word_a, word_b in _ANTONYM_PAIRS:
    a_in_claim = bool(re.search(rf"\b{word_a}\b", lower_claim))
    b_in_claim = bool(re.search(rf"\b{word_b}\b", lower_claim))
    a_in_doc   = bool(re.search(rf"\b{word_a}\b", lower_doc))
    b_in_doc   = bool(re.search(rf"\b{word_b}\b", lower_doc))
    a_in_sent  = bool(re.search(rf"\b{word_a}\b", lower_sent))
    b_in_sent  = bool(re.search(rf"\b{word_b}\b", lower_sent))

    # Only print pairs where at least one word appears somewhere
    if any([a_in_claim, b_in_claim, a_in_doc, b_in_doc]):
        print(
            f"  ({word_a:12} / {word_b:12}) | "
            f"claim=({a_in_claim}/{b_in_claim}) "
            f"doc=({a_in_doc}/{b_in_doc}) "
            f"sent=({a_in_sent}/{b_in_sent})"
        )

print()
found_full, desc_full = _detect_antonym_conflict(claim_text, doc_text)
found_sent, desc_sent = _detect_antonym_conflict(claim_text, best_sent)
print(f"_detect_antonym_conflict(claim, full_doc) : {found_full} | {desc_full}")
print(f"_detect_antonym_conflict(claim, sentence) : {found_sent} | {desc_sent}")
print()

# ── Step 5 — Negation detection ──────────────────────────────────────────────

print("=" * 60)
print("STEP 5 — Negation detection")
print("=" * 60)
neg_found = _detect_negation_conflict(claim_text, best_sent, min_overlap=0.40)
print(f"Negation conflict (min_overlap=0.40): {neg_found}")
neg_found_low = _detect_negation_conflict(claim_text, best_sent, min_overlap=0.25)
print(f"Negation conflict (min_overlap=0.25): {neg_found_low}")
print()

# ── Step 6 — Full _check_doc_contradiction ────────────────────────────────────

print("=" * 60)
print("STEP 6 — Full _check_doc_contradiction (no semantic)")
print("=" * 60)
claim = Claim(
    claim_id="debug_c1",
    text=claim_text,
    sentence_index=0,
    checkable=True,
)
result = _check_doc_contradiction(claim, "doc_1", doc_text, use_semantic=False)
print(f"Result: {result}")
print()

# ── Step 7 — What claims did the LLM actually extract? ───────────────────────

print("=" * 60)
print("STEP 7 — Actual extracted claims from LLM")
print("=" * 60)
answer = """
External access is allowed for all verified users.
The system requires two-factor authentication for all connections.
Access logs are maintained for 90 days.
"""
extractor = LocalLLMClaimExtractor(
    model=settings.ollama_model,
    ollama_url=settings.ollama_url,
    timeout_seconds=settings.ollama_timeout,
    fallback_on_error=True,
)
extraction = extractor.extract(answer, answer_id="debug")
print(f"Model used   : {extraction.model}")
print(f"Used fallback: {extraction.used_fallback}")
print(f"Claims ({len(extraction.claims)}):")
for c in extraction.claims:
    print(f"  [{c.claim_id}] '{c.text}'")
print()

# ── Step 8 — Run E3 on actual extracted claims ────────────────────────────────

print("=" * 60)
print("STEP 8 — E3 on actual extracted claims vs actual documents")
print("=" * 60)
from grounding.consistency_checker import check_consistency

documents = [
    "The security policy strictly forbids external access except for "
    "approved contractors with explicit written authorization.",
    "Two-factor authentication is mandatory for all system connections.",
    "Audit logs are retained for a minimum of 90 days per compliance requirements.",
]
doc_ids = ["policy_doc", "auth_doc", "audit_doc"]

consistency = check_consistency(
    claims=extraction.claims,
    documents=documents,
    doc_ids=doc_ids,
    use_semantic=False,    # disable semantic first — isolate rule-based
)
print(f"has_contradiction      : {consistency.has_contradiction}")
print(f"contradiction_risk     : {consistency.contradiction_risk}")
print(f"self_contradiction     : {consistency.self_contradiction_count}")
print(f"doc_contradiction      : {consistency.doc_contradiction_count}")
print(f"checked_claim_pairs    : {consistency.checked_claim_pairs}")
print(f"checked_doc_pairs      : {consistency.checked_doc_pairs}")
if consistency.contradiction_pairs:
    for p in consistency.contradiction_pairs:
        print(f"\n  [{p.reason_code}] confidence={p.confidence}")
        print(f"  claim : {p.claim_a_text}")
        print(f"  vs    : {p.claim_b_text}")
else:
    print("No contradiction pairs found.")