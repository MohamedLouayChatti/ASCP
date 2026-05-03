# scripts/test_consistency_checker.py

from grounding.claim_extractor import Claim
from grounding.consistency_checker import check_consistency


def make_claim(cid: str, text: str) -> Claim:
    return Claim(claim_id=cid, text=text, sentence_index=0, checkable=True)


# ── Test 1: Doc contradiction via antonym ─────────────────────────────────────
# Most security-critical case for ASCP
print("=== Test 1: Doc contradiction — antonym ===")
result = check_consistency(
    claims=[make_claim("c1", "External access is allowed for all users.")],
    documents=["The security policy states that external access is forbidden."],
    doc_ids=["policy_doc"],
)
print(f"  has_contradiction : {result.has_contradiction}")
print(f"  contradiction_risk: {result.contradiction_risk}")
print(f"  doc_contradictions: {result.doc_contradiction_count}")
if result.contradiction_pairs:
    p = result.contradiction_pairs[0]
    print(f"  reason_code       : {p.reason_code}")
    print(f"  confidence        : {p.confidence}")
    print(f"  conflicting_sent  : {p.claim_b_text}")

# ── Test 2: Self-contradiction via negation ───────────────────────────────────
print("\n=== Test 2: Self-contradiction — negation ===")
result = check_consistency(
    claims=[
        make_claim("c1", "The system requires authentication for all users."),
        make_claim("c2", "The system does not require authentication."),
    ],
    documents=[],
)
print(f"  has_contradiction  : {result.has_contradiction}")
print(f"  self_contradictions: {result.self_contradiction_count}")
if result.contradiction_pairs:
    print(f"  reason_code        : {result.contradiction_pairs[0].reason_code}")

# ── Test 3: No contradiction ──────────────────────────────────────────────────
print("\n=== Test 3: No contradiction ===")
result = check_consistency(
    claims=[
        make_claim("c1", "The Eiffel Tower is located in Paris."),
        make_claim("c2", "The Eiffel Tower was built in 1889."),
    ],
    documents=["The Eiffel Tower is a famous landmark in Paris built in 1889."],
)
print(f"  has_contradiction : {result.has_contradiction}")
print(f"  contradiction_risk: {result.contradiction_risk}")

# ── Test 4: Numeric contradiction ────────────────────────────────────────────
print("\n=== Test 4: Numeric contradiction ===")
result = check_consistency(
    claims=[make_claim("c1", "The tower stands 300 metres tall.")],
    documents=["The Eiffel Tower stands 330 metres tall."],
)
print(f"  has_contradiction : {result.has_contradiction}")
print(f"  doc_contradictions: {result.doc_contradiction_count}")
if result.contradiction_pairs:
    print(f"  reason_code       : {result.contradiction_pairs[0].reason_code}")

# ── Test 5: Self-contradiction via antonym ────────────────────────────────────
print("\n=== Test 5: Self-contradiction — antonym ===")
result = check_consistency(
    claims=[
        make_claim("c1", "Encryption is required for all data transfers."),
        make_claim("c2", "Encryption is optional for internal transfers."),
    ],
    documents=[],
)
print(f"  has_contradiction  : {result.has_contradiction}")
print(f"  self_contradictions: {result.self_contradiction_count}")
if result.contradiction_pairs:
    print(f"  reason_code        : {result.contradiction_pairs[0].reason_code}")