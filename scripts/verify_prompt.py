# scripts/verify_prompt.py

import sys
sys.path.insert(0, ".")

from pathlib import Path

# Ensure the project root is importable when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from grounding.llm_claim_extractor import LocalLLMClaimExtractor
from grounding.consistency_checker import check_consistency
from common.config import settings

answer = """
External access is allowed for all verified users.
The system requires two-factor authentication for all connections.
Access logs are maintained for 90 days.
"""

documents = [
    "The security policy strictly forbids external access except for "
    "approved contractors with explicit written authorization.",
    "Two-factor authentication is mandatory for all system connections.",
    "Audit logs are retained for a minimum of 90 days per compliance requirements.",
]
doc_ids = ["policy_doc", "auth_doc", "audit_doc"]

extractor = LocalLLMClaimExtractor(
    model=settings.ollama_model,
    ollama_url=settings.ollama_url,
    timeout_seconds=settings.ollama_timeout,
    fallback_on_error=True,
)

# Run 3 times — LLM output can vary slightly between runs
for run in range(1, 4):
    extraction = extractor.extract(answer, answer_id=f"verify_{run}")
    print(f"\n=== Run {run} ===")
    for c in extraction.claims:
        # Flag claims that lost permission words
        PERMISSION_WORDS = [
            "allow", "allows", "allowed",
            "forbid", "forbids", "forbidden",
            "require", "requires", "required",
            "prohibit", "prohibits", "prohibited",
            "permit", "permits", "permitted",
            "deny", "denies", "denied",
            "block", "blocks", "blocked",
            "mandatory", "optional",
            "authoriz",
            "must", "cannot", "can not",
            "enabl", "disabl",
        ]
        has_permission_word = any(
            w in c.text.lower()
            for w in PERMISSION_WORDS
        )
        status = "✓" if has_permission_word else "⚠ MISSING PERMISSION WORD"
        print(f"  {status} [{c.claim_id}] {c.text}")

    # Run E3
    consistency = check_consistency(
        claims=extraction.claims,
        documents=documents,
        doc_ids=doc_ids,
        use_semantic=False,
    )
    print(f"  E3: has_contradiction={consistency.has_contradiction} | "
          f"risk={consistency.contradiction_risk}")
    if consistency.contradiction_pairs:
        for p in consistency.contradiction_pairs:
            print(f"  → [{p.reason_code}] {p.claim_a_text[:50]}")