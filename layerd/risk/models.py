from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from .enums import ContextSufficiency, ContractDecision, DLPAction, RiskLevel
@dataclass
class RiskInput:
    """Aggregated inputs for risk scoring."""

    # Layer A outputs
    grounding_score: float = 1.0  # 0=ungrounded, 1=fully grounded
    hallucination_risk: float = 0.0  # 0=safe, 1=high hallucination risk
    contradiction_ratio: float = 0.0  # 0=consistent, 1=fully contradictory
    retrieval_relevance: float = 1.0  # 0=irrelevant, 1=highly relevant
    context_sufficiency: ContextSufficiency = ContextSufficiency.SUFFICIENT  # insufficient|partial|sufficient
    reason_codes: list[str] = field(default_factory=list)

    # Layer B outputs
    decision: ContractDecision = ContractDecision.ALLOW   # primary scoring signal
    violations: list[str] = field(default_factory=list)   # nature of the breach
    reason_code: str = "ALLOWED"                          # specific failure type   I1=access control, I2=constraint breach
    tool_risk_level: RiskLevel = RiskLevel.UNKNOWN

    # Layer c outputs
    should_block: bool = False                           # correct — direct boolean from EnforcementDecision
    action: DLPAction = DLPAction.ALLOW                  # should be DLPAction enum not a string
    canary_hits: bool = False                            # should be bool — presence is what matters for scoring
    secret_matches: bool = False                         # correct — presence is what matters for scoring
    pii_matches: bool = False                            # correct — presence is what matters for scoring
    fingerprint_hits: float = 0.0

    """
    Free-form context for signals not yet formally integrated.
    e.g. injection_detected, hierarchy_violation when added.
    Never feeds into the numeric scorer — for metadata and routing only.
    """
    extra: dict[str, Any] = field(default_factory=dict) 

