"""
Layer D Risk — Structured result types.

Defines the output structure of compute_risk_score() with full audit trail.
Results are immutable (frozen) for safe caching and thread passing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from layerd.risk.enums import Severity


@dataclass(frozen=True)
class SignalContribution:
    """
    One signal's contribution to the final score.
    
    Used to explain WHY the score is what it is.
    """
    signal: str          # e.g., "hallucination_risk", "tool_risk_level"
    layer: str           # Which layer: "A", "B", or "C"
    raw_value: float     # Original input value (0-1)
    contribution: float  # How much this added to the score
    explanation: str     # Human-readable description


@dataclass(frozen=True)
class TriggeredOverride:
    """
    A hard override that fired (enforces minimum score).
    
    Overrides use max(score, floor) - they can only INCREASE risk.
    Exception: canary_hits forces score = 1.0 unconditionally.
    """
    name: str            # e.g., "canary_hits", "decision_block"
    layer: str           # "B" (policy) or "C" (security)
    floor: float         # Minimum score this override enforces
    invariant: str | None = None  # ASCP invariant code (I1, I2, I3, etc.)
    explanation: str = ""


@dataclass(frozen=True)
class RiskResult:
    """
    Complete auditable output of compute_risk_score().
    
    frozen=True = immutable - safe to cache and share across threads.
    """
    score: float                     # Final risk score (0-1)
    severity: Severity               # LOW | MEDIUM | HIGH | CRITICAL
    layer_scores: dict[str, float]   # Raw scores: "layer_a", "layer_b", "layer_c"
    combined_score: float            # Weighted average before hard overrides
    contributions: list[SignalContribution]      # Per-signal breakdown
    triggered_overrides: list[TriggeredOverride] # Hard overrides that fired
    violated_invariants: list[str]   # ASCP invariants breached (I1, I2, I3, etc.)
    reasoning_trace: list[str]       # Human-readable audit log (satisfies I5)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to JSON-serializable dict.
        
        Converts enums to strings, rounds floats, flattens nested dataclasses.
        Used for telemetry, incident reports, and API responses.
        """
        return {
            "score": self.score,
            "severity": self.severity.value,  # Convert enum to string
            "layer_scores": self.layer_scores,
            "combined_score": round(self.combined_score, 4),
            "breakdown": [
                {
                    "signal": c.signal,
                    "layer": c.layer,
                    "raw_value": c.raw_value,
                    "contribution": round(c.contribution, 4),
                    "explanation": c.explanation,
                }
                for c in self.contributions
            ],
            "overrides": [
                {
                    "name": o.name,
                    "layer": o.layer,
                    "floor": o.floor,
                    "invariant": o.invariant,
                    "explanation": o.explanation,
                }
                for o in self.triggered_overrides
            ],
            "violations": self.violated_invariants,
            "reasoning_trace": self.reasoning_trace,
        }