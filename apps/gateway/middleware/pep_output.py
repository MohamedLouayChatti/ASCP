"""
Policy Enforcement Point — Output layer.

Applied to every model-generated response before it is returned to the user:
  - DLP scan (canaries, secrets, PII)
  - Grounding enforcement (Trust & Risk Vector gating)
  - Safe fallback generation
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from security.dlp import DLPResult, scan
from security.grounding.support_checker import TrustRiskVector, evaluate

logger = logging.getLogger(__name__)

_SAFE_FALLBACK = (
    "I cannot provide a response to this query due to a policy constraint. "
    "Please rephrase your question or contact support if you believe this is an error."
)


@dataclass
class OutputInspectionResult:
    final_text: str
    dlp_result: DLPResult
    trust_vector: TrustRiskVector
    blocked: bool
    block_reason: str | None = None


def inspect_output(
    answer: str,
    query: str,
    documents: list[dict[str, Any]],
    *,
    min_grounding_score: float = 0.6,
    max_hallucination_risk: float = 0.4,
) -> OutputInspectionResult:
    """
    Full output inspection pipeline.

    1. DLP scan — block on canary/secret leaks, redact PII
    2. Grounding evaluation — block if below thresholds
    3. Return safe text (redacted or fallback as appropriate)
    """
    # --- Step 1: DLP scan ---
    dlp_result = scan(answer)
    if dlp_result.should_block:
        logger.critical("Output BLOCKED by DLP: violations=%s", dlp_result.violations)
        return OutputInspectionResult(
            final_text=_SAFE_FALLBACK,
            dlp_result=dlp_result,
            trust_vector=TrustRiskVector(leakage_flag=True),
            blocked=True,
            block_reason=f"DLP violation: {', '.join(dlp_result.violations)}",
        )

    # Use redacted text if PII was found
    working_text = dlp_result.clean_text

    # --- Step 2: Grounding evaluation ---
    trust_vector = evaluate(
        query=query,
        documents=documents,
        answer=working_text,
        min_grounding_score=min_grounding_score,
        max_hallucination_risk=max_hallucination_risk,
    )

    if trust_vector.abstain_recommended:
        logger.warning(
            "Output BLOCKED by grounding policy: grounding=%.2f hallucination=%.2f",
            trust_vector.grounding_score,
            trust_vector.hallucination_risk,
        )
        fallback = (
            "I don't have sufficient information to answer this question confidently. "
            + " ".join(trust_vector.followup_questions)
        )
        return OutputInspectionResult(
            final_text=fallback,
            dlp_result=dlp_result,
            trust_vector=trust_vector,
            blocked=True,
            block_reason=f"grounding_score={trust_vector.grounding_score:.2f} below threshold",
        )

    # Mark leakage flag if PII was found (but not blocked, just redacted)
    if dlp_result.pii_matches:
        trust_vector.leakage_flag = True

    return OutputInspectionResult(
        final_text=working_text,
        dlp_result=dlp_result,
        trust_vector=trust_vector,
        blocked=False,
    )
