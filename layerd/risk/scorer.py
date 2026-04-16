"""
Layer D — Unified Risk Scorer.

Aggregates signals from Layers A (trust), B (policy), and C (security).
Returns risk score 0 (safe) to 1 (dangerous) with full audit trail.
"""

from __future__ import annotations

import logging
import math

from layerd.risk.config import DEFAULT_CONFIG, ScoringConfig
from layerd.risk.enums import (
    ContextSufficiency,
    ContractDecision,
    DLPAction,
    RiskLevel,
    Severity,
)
from layerd.risk.models import RiskInput
from layerd.risk.result import RiskResult, SignalContribution, TriggeredOverride

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def _validate_input(inp: RiskInput) -> None:
    """Ensure all float inputs are between 0 and 1. Raises ValueError if not."""
    bounded = [
        ("grounding_score", inp.grounding_score),
        ("hallucination_risk", inp.hallucination_risk),
        ("contradiction_ratio", inp.contradiction_ratio),
        ("retrieval_relevance", inp.retrieval_relevance),
        ("fingerprint_hits", inp.fingerprint_hits),
    ]
    for name, value in bounded:
        if not 0.0 <= value <= 1.0:
            raise ValueError(
                f"RiskInput.{name} must be in [0.0, 1.0], got {value!r}"
            )


# ---------------------------------------------------------------------------
# Smooth mathematical formulations
# ---------------------------------------------------------------------------

def _smooth_relevance_penalty(relevance: float, cfg: ScoringConfig) -> float:
    """
    Exponential penalty for low retrieval relevance.
    
    Formula: penalty = scale * e^(-decay * relevance)
    - relevance=1.0 (perfect) → penalty ≈ 0
    - relevance=0.0 (terrible) → penalty = scale (0.08)
    """
    penalty = (
        cfg.layer_a.relevance_penalty_scale
        * math.exp(-cfg.layer_a.relevance_decay * relevance)
    )
    return round(min(penalty, cfg.layer_a.relevance_penalty_scale), 4)


def _smooth_fingerprint_contribution(overlap: float, cfg: ScoringConfig) -> float:
    """
    Convert document overlap percentage to risk contribution.
    
    Formula: base * overlap + scale * overlap²
    - Quadratic term makes high overlap (>50%) penalized more heavily
    - At 100% overlap → contributes ~0.55 (30% base + 25% quadratic)
    """
    contribution = (
        cfg.layer_c.fingerprint_base * overlap
        + cfg.layer_c.fingerprint_scale * (overlap ** 2)
    )
    return round(min(contribution, 1.0), 4)


# ---------------------------------------------------------------------------
# Layer A — continuous trust signals
# ---------------------------------------------------------------------------

def _compute_layer_a(
    inp: RiskInput,
    cfg: ScoringConfig,
) -> tuple[float, list[SignalContribution]]:
    """
    Calculate risk from AI trustworthiness.
    
    Signals: grounding (facts vs claims), hallucinations (lies), 
    contradictions (self-conflict), retrieval quality, context completeness.
    """
    contributions: list[SignalContribution] = []
    score = 0.0

    # grounding_score: 1.0 = fully backed by documents, 0.0 = completely unbacked
    # Invert because LOW grounding = HIGH risk
    grounding_c = (1.0 - inp.grounding_score) * cfg.layer_a.grounding
    score += grounding_c
    contributions.append(SignalContribution(
        signal="grounding_score",
        layer="A",
        raw_value=inp.grounding_score,
        contribution=grounding_c,
        explanation=(
            f"Grounding {inp.grounding_score:.3f} → "
            f"(1 - {inp.grounding_score:.3f}) × {cfg.layer_a.grounding} "
            f"= {grounding_c:.4f}"
        ),
    ))

    # hallucination_risk: composite signal, highest weight because it aggregates
    # multiple trust indicators into one number
    hallucination_c = inp.hallucination_risk * cfg.layer_a.hallucination
    score += hallucination_c
    contributions.append(SignalContribution(
        signal="hallucination_risk",
        layer="A",
        raw_value=inp.hallucination_risk,
        contribution=hallucination_c,
        explanation=(
            f"Hallucination risk {inp.hallucination_risk:.3f} × "
            f"{cfg.layer_a.hallucination} = {hallucination_c:.4f}"
        ),
    ))

    # contradiction_ratio: model actively argued AGAINST evidence (worse than low grounding)
    contradiction_c = inp.contradiction_ratio * cfg.layer_a.contradiction
    score += contradiction_c
    contributions.append(SignalContribution(
        signal="contradiction_ratio",
        layer="A",
        raw_value=inp.contradiction_ratio,
        contribution=contradiction_c,
        explanation=(
            f"Contradiction ratio {inp.contradiction_ratio:.3f} × "
            f"{cfg.layer_a.contradiction} = {contradiction_c:.4f}"
        ),
    ))

    # retrieval_relevance: low relevance means trust signals computed on wrong documents
    relevance_c = _smooth_relevance_penalty(inp.retrieval_relevance, cfg)
    score += relevance_c
    contributions.append(SignalContribution(
        signal="retrieval_relevance",
        layer="A",
        raw_value=inp.retrieval_relevance,
        contribution=relevance_c,
        explanation=(
            f"Retrieval relevance {inp.retrieval_relevance:.3f} → "
            f"penalty {relevance_c:.4f}"
        ),
    ))

    # Context sufficiency: INSUFFICIENT = missing docs, PARTIAL = some docs
    if inp.context_sufficiency == ContextSufficiency.INSUFFICIENT:
        sufficiency_c = cfg.layer_a.context_insufficient
        sufficiency_explanation = "Context INSUFFICIENT → penalty"
    elif inp.context_sufficiency == ContextSufficiency.PARTIAL:
        sufficiency_c = cfg.layer_a.context_partial
        sufficiency_explanation = "Context PARTIAL → penalty"
    else:  # SUFFICIENT
        sufficiency_c = 0.0
        sufficiency_explanation = "Context SUFFICIENT → no penalty"

    score += sufficiency_c
    contributions.append(SignalContribution(
        signal="context_sufficiency",
        layer="A",
        raw_value=sufficiency_c,
        contribution=sufficiency_c,
        explanation=sufficiency_explanation,
    ))

    # Cap prevents Layer A from dominating before Layers B/C can apply overrides
    capped = min(score, cfg.layer_a.cap)
    return round(capped, 4), contributions


# ---------------------------------------------------------------------------
# Layer B — discrete policy overrides
# ---------------------------------------------------------------------------

def _compute_layer_b(
    inp: RiskInput,
    cfg: ScoringConfig,
) -> tuple[float, list[SignalContribution], list[TriggeredOverride]]:
    """
    Calculate risk from tool policies and access control violations.
    
    Uses max() for overrides (score = highest risk so far).
    I1 = access control breach, I2 = argument/constraint violation.
    """
    contributions: list[SignalContribution] = []
    overrides: list[TriggeredOverride] = []
    score = 0.0

    # Tool risk is additive baseline (independent of decision outcome)
    tool_weights = {
        RiskLevel.LOW: cfg.layer_b.tool_risk_low,
        RiskLevel.MEDIUM: cfg.layer_b.tool_risk_medium,
        RiskLevel.HIGH: cfg.layer_b.tool_risk_high,
        RiskLevel.CRITICAL: cfg.layer_b.tool_risk_critical,
        RiskLevel.UNKNOWN: cfg.layer_b.tool_risk_unknown,
    }
    tool_c = tool_weights.get(inp.tool_risk_level, cfg.layer_b.tool_risk_unknown)
    score += tool_c
    contributions.append(SignalContribution(
        signal="tool_risk_level",
        layer="B",
        raw_value=tool_c,
        contribution=tool_c,
        explanation=f"Tool risk '{inp.tool_risk_level}' → +{tool_c:.4f}",
    ))

    # BLOCK decision forces minimum score (floor)
    if inp.decision == ContractDecision.BLOCK:
        floor = cfg.layer_b.decision_block_floor
        score = max(score, floor)
        overrides.append(TriggeredOverride(
            name="decision_block",
            layer="B",
            floor=floor,
            invariant="I1",  # I1 = tool policy compliance
            explanation=f"BLOCK decision → floor {floor}",
        ))
    elif inp.decision == ContractDecision.REQUIRE_APPROVAL:
        floor = cfg.layer_b.decision_approval_floor
        score = max(score, floor)
        overrides.append(TriggeredOverride(
            name="decision_require_approval",
            layer="B",
            floor=floor,
            invariant="I1",
            explanation=f"REQUIRE_APPROVAL → floor {floor}",
        ))

    # I1 violation: access control breach (e.g., accessing unauthorized data)
    if "I1" in inp.violations:
        floor = cfg.layer_b.violation_i1_floor
        score = max(score, floor)
        overrides.append(TriggeredOverride(
            name="violation_I1",
            layer="B",
            floor=floor,
            invariant="I1",
            explanation=f"I1 access breach → floor {floor}",
        ))

    # I2 violation: argument/constraint breach (e.g., ignoring tool limits)
    if "I2" in inp.violations:
        floor = cfg.layer_b.violation_i2_floor
        score = max(score, floor)
        overrides.append(TriggeredOverride(
            name="violation_I2",
            layer="B",
            floor=floor,
            invariant="I2",
            explanation=f"I2 constraint breach → floor {floor}",
        ))

    return round(score, 4), contributions, overrides


# ---------------------------------------------------------------------------
# Layer C — hard security overrides
# ---------------------------------------------------------------------------

def _compute_layer_c(
    inp: RiskInput,
    cfg: ScoringConfig,
) -> tuple[float, list[SignalContribution], list[TriggeredOverride]]:
    """
    Calculate risk from data leakage (secrets, PII, document reproduction).
    
    Order matters: canary_hits returns immediately with 1.0 (no override possible).
    I3 = secret non-disclosure invariant.
    """
    contributions: list[SignalContribution] = []
    overrides: list[TriggeredOverride] = []
    score = 0.0

    # CANARY HITS: injected test tokens to detect leakage
    # This is definitive proof of breach → score = 1.0 unconditionally
    if inp.canary_hits:
        overrides.append(TriggeredOverride(
            name="canary_hits",
            layer="C",
            floor=1.0,
            invariant="I3",
            explanation="Canary leak → score = 1.0",
        ))
        return 1.0, contributions, overrides

    # SECRET MATCHES: real API keys, passwords, tokens
    # 0.95 (not 1.0) because regex/entropy can have false positives
    if inp.secret_matches:
        floor = cfg.layer_c.secret_matches_floor
        score = max(score, floor)
        overrides.append(TriggeredOverride(
            name="secret_matches",
            layer="C",
            floor=floor,
            invariant="I3",
            explanation=f"Secret detected → floor {floor}",
        ))

    # SHOULD BLOCK: DLP enforcer's hard block decision
    if inp.should_block:
        floor = cfg.layer_c.should_block_floor
        score = max(score, floor)
        overrides.append(TriggeredOverride(
            name="should_block",
            layer="C",
            floor=floor,
            explanation=f"Enforcer BLOCK → floor {floor}",
        ))

    # PII MATCHES: personal info (SSN, emails, phone numbers)
    if inp.pii_matches:
        floor = cfg.layer_c.pii_matches_floor
        score = max(score, floor)
        overrides.append(TriggeredOverride(
            name="pii_matches",
            layer="C",
            floor=floor,
            explanation=f"PII detected → floor {floor}",
        ))

    # FINGERPRINT HITS: document reproduction (additive, not a floor)
    # Example: copying 90% of a secret document is bad, but not as bad as canary hit
    if inp.fingerprint_hits > 0.0:
        fp_c = _smooth_fingerprint_contribution(inp.fingerprint_hits, cfg)
        score = min(score + fp_c, 1.0)
        contributions.append(SignalContribution(
            signal="fingerprint_hits",
            layer="C",
            raw_value=inp.fingerprint_hits,
            contribution=fp_c,
            explanation=f"Document overlap {inp.fingerprint_hits:.3f} → +{fp_c:.4f}",
        ))

    # DLP actions: graduated responses from the Data Loss Prevention system
    if inp.action == DLPAction.BLOCK:
        floor = cfg.layer_c.dlp_block_floor
        score = max(score, floor)
        overrides.append(TriggeredOverride(
            name="dlp_action_block",
            layer="C",
            floor=floor,
            explanation=f"DLP BLOCK → floor {floor}",
        ))
    elif inp.action == DLPAction.ESCALATE:
        floor = cfg.layer_c.dlp_escalate_floor
        score = max(score, floor)
        overrides.append(TriggeredOverride(
            name="dlp_action_escalate",
            layer="C",
            floor=floor,
            explanation=f"DLP ESCALATE → floor {floor}",
        ))
    elif inp.action == DLPAction.REDACT:
        floor = cfg.layer_c.dlp_redact_floor
        score = max(score, floor)
        overrides.append(TriggeredOverride(
            name="dlp_action_redact",
            layer="C",
            floor=floor,
            explanation=f"DLP REDACT → floor {floor}",
        ))

    return round(score, 4), contributions, overrides


# ---------------------------------------------------------------------------
# Combination and monotonicity enforcement
# ---------------------------------------------------------------------------

def _combine(
    layer_a: float,
    layer_b: float,
    layer_c: float,
    cfg: ScoringConfig,
) -> float:
    """Weighted average of three layer scores."""
    combined = (
        cfg.combination.layer_a * layer_a
        + cfg.combination.layer_b * layer_b
        + cfg.combination.layer_c * layer_c
    )
    return round(min(combined, 1.0), 4)


def _enforce_monotonicity(
    combined: float,
    layer_b: float,
    layer_c: float,
    overrides: list[TriggeredOverride],
) -> float:
    """
    Ensure adding risk never lowers score.
    
    Without this, a high Layer C score (0.95) could be diluted by low 
    Layer A/B scores in weighted average. This guarantees highest risk wins.
    """
    result = max(combined, layer_b, layer_c)
    for override in overrides:
        result = max(result, override.floor)
    return result


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

def _classify_severity(score: float, cfg: ScoringConfig) -> Severity:
    """Convert 0-1 score to severity level using configurable thresholds."""
    if score >= cfg.severity.critical:
        return Severity.CRITICAL
    if score >= cfg.severity.high:
        return Severity.HIGH
    if score >= cfg.severity.medium:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# Reasoning trace (auditability) - satisfies I5
# ---------------------------------------------------------------------------

def _build_reasoning_trace(
    layer_a: float,
    layer_b: float,
    layer_c: float,
    combined: float,
    final: float,
    overrides: list[TriggeredOverride],
    violated_invariants: list[str],
) -> list[str]:
    """Build human-readable audit log of all scoring decisions."""
    trace = [
        f"[LAYER_A] Trust signals → {layer_a:.4f}",
        f"[LAYER_B] Policy signals → {layer_b:.4f}",
        f"[LAYER_C] Security signals → {layer_c:.4f}",
        f"[COMBINE] Weighted combination → {combined:.4f}",
        f"[MONOTONICITY] Final after overrides → {final:.4f}",
    ]

    if overrides:
        trace.append(f"[OVERRIDES] {len(overrides)} triggered:")
        for o in overrides:
            inv_tag = f" [{o.invariant}]" if o.invariant else ""
            trace.append(f"  · {o.name}{inv_tag}: {o.explanation}")
    else:
        trace.append("[OVERRIDES] None")

    if violated_invariants:
        trace.append(f"[INVARIANTS] Violated: {', '.join(violated_invariants)}")
    else:
        trace.append("[INVARIANTS] None")

    return trace


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_risk_score(
    inp: RiskInput,
    config: ScoringConfig | None = None,
) -> RiskResult:
    """
    Main entry point: compute unified risk score with full audit trail.
    
    Stages: validate → Layer A (trust) → Layer B (policy) → Layer C (security)
           → combine → enforce monotonicity → classify → build trace
    """
    cfg = config or DEFAULT_CONFIG

    # Stage 1: Validate inputs
    _validate_input(inp)

    # Stage 2: Layer A (continuous trust signals)
    layer_a_score, a_contributions = _compute_layer_a(inp, cfg)

    # Stage 3: Layer B (policy overrides)
    layer_b_score, b_contributions, b_overrides = _compute_layer_b(inp, cfg)

    # Stage 4: Layer C (security overrides)
    layer_c_score, c_contributions, c_overrides = _compute_layer_c(inp, cfg)

    # Combine all contributions and overrides
    all_contributions = a_contributions + b_contributions + c_contributions
    all_overrides = b_overrides + c_overrides

    # Stage 5: Weighted combination
    combined = _combine(layer_a_score, layer_b_score, layer_c_score, cfg)

    # Stage 6: Enforce monotonicity (risk never decreases)
    final = _enforce_monotonicity(combined, layer_b_score, layer_c_score, all_overrides)
    final = round(min(final, 1.0), 4)

    # Stage 7: Classify severity level
    severity = _classify_severity(final, cfg)

    # Stage 8: Collect violated invariants (sorted by priority I3 > I1 > I2)
    _invariant_priority = {"I3": 0, "I1": 1, "I2": 2, "I4": 3, "I5": 4}
    violated_invariants = sorted(
        {o.invariant for o in all_overrides if o.invariant},
        key=lambda i: _invariant_priority.get(i, 99),
    )

    # Stage 9: Build reasoning trace for auditability
    reasoning_trace = _build_reasoning_trace(
        layer_a=layer_a_score,
        layer_b=layer_b_score,
        layer_c=layer_c_score,
        combined=combined,
        final=final,
        overrides=all_overrides,
        violated_invariants=violated_invariants,
    )

    logger.debug("risk_score=%.4f severity=%s", final, severity)

    return RiskResult(
        score=final,
        severity=severity,
        layer_scores={
            "layer_a": layer_a_score,
            "layer_b": layer_b_score,
            "layer_c": layer_c_score,
        },
        combined_score=combined,
        contributions=all_contributions,
        triggered_overrides=all_overrides,
        violated_invariants=violated_invariants,
        reasoning_trace=reasoning_trace,
    )