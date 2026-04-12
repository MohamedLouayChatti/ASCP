import json
import httpx
import logging
from typing import List
from ascp.grounding.claim_extractor import Claim, ClaimExtractor
from ascp.grounding.prompts import CLAIM_EXTRACTION_SYSTEM, CLAIM_EXTRACTION_USER

logger = logging.getLogger(__name__)

class LocalLLMClaimExtractor:
    """
    A 100% free, local claim extractor using Ollama.
    """
    def __init__(self, model: str = "llama3"):
        self.model = model
        self.url = "http://localhost:11434/api/generate"
        self._fallback = ClaimExtractor()

    def extract(self, answer: str) -> List[Claim]:
        payload = {
            "model": self.model,
            "prompt": f"{CLAIM_EXTRACTION_SYSTEM}\n\nContext: {answer}",
            "format": "json",  # Llama 3 is great at forcing JSON output
            "stream": False
        }

        try:
            response = httpx.post(self.url, json=payload, timeout=30.0)
            response.raise_for_status()
            
            raw_text = response.json().get("response", "{}")
            data = json.loads(raw_text)
            
            claims = []
            for i, text in enumerate(data.get("claims", [])):
                claims.append(Claim(
                    claim_id=f"c{i}",
                    text=text,
                    sentence_index=i,
                    checkable=True
                ))
            return claims

        except Exception as e:
            logger.error(f"Local LLM failed: {e}. Falling back to Regex.")
            return self._fallback.extract(answer)