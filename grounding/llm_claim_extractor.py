# ascp/grounding/local_llm_claim_extractor.py

from __future__ import annotations

import json
import importlib
import logging
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional

import httpx

if TYPE_CHECKING:
    from grounding.claim_extractor import Claim as ClaimType
else:
    ClaimType = object

def _load_claim_types() -> tuple[type, type]:
    for module_name in ("grounding.claim_extractor", "ascp.grounding.claim_extractor"):
        try:
            module = importlib.import_module(module_name)
            return module.Claim, module.ClaimExtractor
        except ModuleNotFoundError:
            continue
    raise ModuleNotFoundError("Could not import claim extractor module from known paths.")


def _load_prompts() -> tuple[str, str]:
    for module_name in ("grounding.prompts", "ascp.grounding.prompts"):
        try:
            module = importlib.import_module(module_name)
            return module.CLAIM_EXTRACTION_SYSTEM, module.CLAIM_EXTRACTION_USER
        except ModuleNotFoundError:
            continue

    fallback_system = (
        "You extract atomic factual claims from an assistant answer. "
        "Return strict JSON only, with this schema: {\"claims\": [\"...\"]}."
    )
    fallback_user = (
        "Extract factual claims from the answer below. Split compound sentences into "
        "atomic claims. Exclude opinions, requests, and questions.\n\n"
        "Answer:\n{answer}"
    )
    return fallback_system, fallback_user


ClaimClass, ClaimExtractorClass = _load_claim_types()
CLAIM_EXTRACTION_SYSTEM, CLAIM_EXTRACTION_USER = _load_prompts()

logger = logging.getLogger(__name__)


@dataclass
class ExtractionResult:
    """Full result from the extractor, including metadata for telemetry."""
    claims: List[ClaimType]
    used_fallback: bool
    raw_response: Optional[str]
    latency_ms: float
    model: str


class LocalLLMClaimExtractor:
    """
    Production-quality claim extractor using a locally running
    Ollama model. Completely free, no API key required.
    Falls back to regex extractor on timeout or server error.
    """

    def __init__(
        self,
        model: str = "llama3.2",
        ollama_url: str = "http://localhost:11434",
        timeout_seconds: float = 30.0,      # local models are slower than API
        fallback_on_error: bool = True,
    ) -> None:
        self.model = model
        self.ollama_url = ollama_url
        self.timeout_seconds = timeout_seconds
        self.fallback_on_error = fallback_on_error
        self._fallback = ClaimExtractorClass()   # your existing regex extractor

    # ------------------------------------------------------------------ #
    #  Public interface                                                    #
    # ------------------------------------------------------------------ #

    def extract(self, answer: str, answer_id: str = "") -> ExtractionResult:
        """
        Extract atomic factual claims from an AI answer.
        Automatically falls back to regex on any error.
        """
        if not answer or not answer.strip():
            return ExtractionResult(
                claims=[], used_fallback=False,
                raw_response=None, latency_ms=0.0,
                model=self.model
            )

        start = time.monotonic()
        try:
            raw = self._call_ollama(answer)
            latency_ms = (time.monotonic() - start) * 1000

            claims = self._parse_response(raw, answer_id)

            logger.info(
                "local_llm_extractor | model=%s | claims=%d | latency=%.1fms",
                self.model, len(claims), latency_ms
            )

            return ExtractionResult(
                claims=claims,
                used_fallback=False,
                raw_response=raw,
                latency_ms=latency_ms,
                model=self.model,
            )

        except Exception as exc:
            latency_ms = (time.monotonic() - start) * 1000
            logger.warning(
                "local_llm_extractor failed after %.1fms: %s — using regex fallback",
                latency_ms, exc
            )
            if self.fallback_on_error:
                return self._run_fallback(answer, latency_ms)
            raise

    def health_check(self) -> bool:
        """Returns True if the Ollama server is reachable."""
        try:
            response = httpx.get(
                f"{self.ollama_url}/api/tags",
                timeout=3.0
            )
            return response.status_code == 200
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  Internal methods                                                    #
    # ------------------------------------------------------------------ #

    def _call_ollama(self, answer: str) -> str:
        """
        Send the extraction prompt to Ollama and return the raw text response.
        Uses the /api/chat endpoint for proper system/user role separation.
        """
        payload = {
            "model": self.model,
            "stream": False,                  # wait for full response
            "format": "json",                 # tells Ollama to enforce JSON output
            "options": {
                "temperature": 0.0,           # deterministic — critical for security evals
                "num_predict": 1024,          # max output tokens
            },
            "messages": [
                {
                    "role": "system",
                    "content": CLAIM_EXTRACTION_SYSTEM
                },
                {
                    "role": "user",
                    "content": CLAIM_EXTRACTION_USER.format(answer=answer)
                }
            ]
        }

        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.post(
                f"{self.ollama_url}/api/chat",
                json=payload,
            )
            response.raise_for_status()

        data = response.json()
        return data["message"]["content"]

    def _parse_response(self, raw: str, answer_id: str) -> List[ClaimType]:
        """
        Parse the model's JSON response into Claim objects.
        Handles common formatting mistakes local models make.
        """
        # Strip markdown fences — some models add them despite format="json"
        cleaned = re.sub(r"```(?:json)?|```", "", raw).strip()

        # Attempt 1: direct JSON parse
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            # Attempt 2: find JSON object anywhere in the text
            match = re.search(
                r'\{.*?"claims"\s*:\s*\[.*?\]\s*\}',
                cleaned,
                re.DOTALL
            )
            if match:
                data = json.loads(match.group())
            else:
                logger.error(
                    "Could not parse model response as JSON.\nRaw: %s",
                    cleaned[:300]
                )
                raise ValueError(f"Unparseable response: {cleaned[:300]}")

        raw_claims: list = data.get("claims", [])

        if not isinstance(raw_claims, list):
            raise ValueError(
                f"Expected 'claims' to be a list, got {type(raw_claims)}"
            )

        claims: List[ClaimType] = []
        for i, text in enumerate(raw_claims):
            if not isinstance(text, str) or not text.strip():
                continue

            claims.append(
                ClaimClass(
                    claim_id=f"{answer_id}_c{i+1}" if answer_id else f"c{i+1}",
                    text=text.strip(),
                    sentence_index=i,
                    checkable=True,  # LLM already filtered uncheckable claims
                )
            )

        return claims

    def _run_fallback(
        self, answer: str, prior_latency_ms: float
    ) -> ExtractionResult:
        """Run the regex extractor as a safe fallback."""
        start = time.monotonic()
        claims = self._fallback.extract(answer)
        fallback_ms = (time.monotonic() - start) * 1000

        return ExtractionResult(
            claims=claims,
            used_fallback=True,
            raw_response=None,
            latency_ms=prior_latency_ms + fallback_ms,
            model="regex-fallback",
        )