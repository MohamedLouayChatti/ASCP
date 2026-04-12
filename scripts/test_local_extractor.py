"""Manual smoke test for the local LLM claim extractor.

Run with:
    python scripts/test_local_extractor.py
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

# Ensure the project root is importable when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def _load_extractor_class() -> type:
    for module_name in ("grounding.llm_claim_extractor", "ascp.grounding.local_llm_claim_extractor"):
        try:
            module = importlib.import_module(module_name)
            return module.LocalLLMClaimExtractor
        except ModuleNotFoundError:
            continue
    raise ModuleNotFoundError("Could not import LocalLLMClaimExtractor from known paths.")


LocalLLMClaimExtractor = _load_extractor_class()


extractor = LocalLLMClaimExtractor(model="llama3.2")

# First check the server is up.
if not extractor.health_check():
    print("Ollama is not running. Start it with: ollama serve")
    raise SystemExit(1)

answer = """
The Eiffel Tower is located in Paris, France.
It was built in 1889 by Gustave Eiffel and stands 330 metres tall.
It attracts around 7 million visitors per year, making it the most
visited paid monument in the world.
"""

result = extractor.extract(answer, answer_id="test_001")

print(f"Model     : {result.model}")
print(f"Latency   : {result.latency_ms:.0f}ms")
print(f"Fallback  : {result.used_fallback}")
print(f"Claims ({len(result.claims)}):")
for claim in result.claims:
    print(f"  [{claim.claim_id}] {claim.text}")
