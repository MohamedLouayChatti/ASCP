# scripts/test_consistency_checker.py

import sys
from pathlib import Path

# Ensure the project root is importable when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from grounding.consistency_checker import check_consistency_from_answer


def run_check(answer: str, documents: list[str], label: str, doc_ids: list[str] | None = None) -> None:
    result = check_consistency_from_answer(
        answer=answer,
        documents=documents,
        doc_ids=doc_ids,
        answer_id=label,
    )
    if result.extraction_used_fallback:
        print(f"  [warn] LLM extractor unavailable, using fallback for {label}")
    print(f"  has_contradiction : {result.has_contradiction}")
    print(f"  contradiction_risk: {result.contradiction_risk}")
    print(f"  self_contradictions: {result.self_contradiction_count}")
    print(f"  doc_contradictions : {result.doc_contradiction_count}")
    if result.contradiction_pairs:
        p = result.contradiction_pairs[0]
        print(f"  reason_code        : {p.reason_code}")
        print(f"  confidence         : {p.confidence}")
        print(f"  conflicting_text   : {p.claim_b_text}")


# ── Test 1: Doc contradiction via antonym ─────────────────────────────────────
# Most security-critical case for ASCP
print("=== Test 1: Doc contradiction — antonym ===")
run_check(
    answer="External access is allowed for all users.",
    documents=["The security policy states that external access is forbidden."],
    doc_ids=["policy_doc"],
    label="t1",
)

# ── Test 2: Self-contradiction via negation ───────────────────────────────────
print("\n=== Test 2: Self-contradiction — negation ===")
run_check(
    answer=(
        "The system requires authentication for all users. "
        "The system does not require authentication."
    ),
    documents=[],
    label="t2",
)

# ── Test 3: No contradiction ──────────────────────────────────────────────────
print("\n=== Test 3: No contradiction ===")
run_check(
    answer=(
        "The Eiffel Tower is located in Paris. "
        "The Eiffel Tower was built in 1889."
    ),
    documents=["The Eiffel Tower is a famous landmark in Paris built in 1889."],
    label="t3",
)

# ── Test 4: Numeric contradiction ────────────────────────────────────────────
print("\n=== Test 4: Numeric contradiction ===")
run_check(
    answer="The tower stands 300 metres tall.",
    documents=["The Eiffel Tower stands 330 metres tall."],
    label="t4",
)

# ── Test 5: Self-contradiction via antonym ────────────────────────────────────
print("\n=== Test 5: Self-contradiction — antonym ===")
run_check(
    answer=(
        "Encryption is required for all data transfers. "
        "Encryption is optional for internal transfers."
    ),
    documents=[],
    label="t5",
)