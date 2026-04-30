# scripts/test_support_checker.py

import sys
from pathlib import Path

# Ensure the project root is importable when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from grounding.support_checker import SupportChecker

checker = SupportChecker(use_semantic=True)

# Test 1 — should be SUPPORTED (same meaning, different words)
result = checker.check_pair(
    claim_text="The Eiffel Tower was constructed in 1889.",
    document_text="Paris's iconic iron lattice structure was erected in 1889 by engineer Gustave Eiffel.",
    claim_id="c1",
    doc_id="d1",
)
print(f"Test 1 (paraphrase — expect supported): {result.verdict} | score={result.overlap_score}")

# Test 2 — should be CONTRADICTED
result = checker.check_pair(
    claim_text="The policy does not allow external access.",
    document_text="The policy allows external access for verified users.",
    claim_id="c2",
    doc_id="d2",
)
print(f"Test 2 (contradiction — expect contradicted): {result.verdict} | score={result.overlap_score}")

# Test 3 — should be INSUFFICIENT (unrelated document)
result = checker.check_pair(
    claim_text="The Eiffel Tower is 330 metres tall.",
    document_text="The weather in Paris is mild during spring and autumn months.",
    claim_id="c3",
    doc_id="d3",
)
print(f"Test 3 (unrelated — expect insufficient): {result.verdict} | score={result.overlap_score}")