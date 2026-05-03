# scripts/test_trust_vector.py

import sys
from pathlib import Path

# Ensure the project root is importable when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from grounding.trust_vector import assemble_trust_vector

query = "Is external access allowed under the security policy?"

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

result = assemble_trust_vector(
    query=query,
    answer=answer,
    documents=documents,
    answer_id="test_001",
)

print(f"Version          : {result['trust_vector_version']}")
print(f"Grounding score  : {result['signals']['grounding_score']}")
print(f"Hallucination    : {result['signals']['hallucination_risk']}")
print(f"Consistency risk : {result['signals']['consistency_risk']}")
print(f"Has contradiction: {result['signals']['has_contradiction']}")
print(f"Decision         : {result['decision_hint']}")
print(f"Reason codes     : {result['reason_codes']}")
print(f"Extraction model : {result['extraction_meta']['model']}")
print(f"Used fallback    : {result['extraction_meta']['used_fallback']}")

if result['details']['consistency']['contradiction_pairs']:
    print("\nContradictions detected:")
    for p in result['details']['consistency']['contradiction_pairs']:
        print(f"  [{p['reason_code']}] {p['claim_a_text']}")
        print(f"   vs: {p['claim_b_text']}")