#debugging/verify_fixes.py

import sys
from pathlib import Path

# Ensure the project root is importable when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from grounding.consistency_checker import (
    _detect_antonym_conflict,
    _check_doc_contradiction,
)
from grounding.llm_claim_extractor import Claim
from grounding.text_utils import topic_overlap

claim_text = "External access is allowed for all verified users."
doc_text = "The security policy strictly forbids external access."

# Should now be ~0.333 not 0.125
print(f"Topic overlap : {topic_overlap(claim_text, doc_text):.3f}")

# Should now be True
found, desc = _detect_antonym_conflict(claim_text, doc_text)
print(f"Antonym found : {found} | {desc}")

# Should now return ContradictionPair
claim = Claim(claim_id="c1", text=claim_text, sentence_index=0, checkable=True)
result = _check_doc_contradiction(claim, "doc_1", doc_text, use_semantic=False)
print(f"E3 result     : {result}")