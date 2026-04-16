"""
Layer D Risk — Scoring configuration.

All weights, thresholds, and tunable parameters live here.
Nothing is hardcoded in scorer.py — every numeric decision
can be overridden by passing a custom ScoringConfig instance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Layer weight dataclasses
# ---------------------------------------------------------------------------

@dataclass
class LayerAWeights:
    """Continuous signal weights for Layer A (trust signals)."""
    grounding: float = 0.20           # Low grounding = high risk
    hallucination: float = 0.25       # Most heavily weighted
    contradiction: float = 0.15       # Going against evidence

    # penalty = scale * exp(-decay * relevance)
    relevance_penalty_scale: float = 0.08   # Max penalty when relevance=0
    relevance_decay: float = 7.0            # How fast penalty drops

    context_insufficient: float = 0.10      # Missing docs penalty
    context_partial: float = 0.05           # Partial docs penalty

    cap: float = 0.58                # Max Layer A contribution


@dataclass
class LayerBWeights:
    """Discrete override floors for Layer B (policy enforcement)."""
    # Tool intrinsic risk (additive)
    tool_risk_low: float = 0.10
    tool_risk_medium: float = 0.25
    tool_risk_high: float = 0.45
    tool_risk_critical: float = 0.65
    tool_risk_unknown: float = 0.15

    # Contract decision floors (max semantics)
    decision_block_floor: float = 0.75
    decision_approval_floor: float = 0.50

    # Invariant violation floors (I1 = access, I2 = constraints)
    violation_i1_floor: float = 0.85
    violation_i2_floor: float = 0.65


@dataclass
class LayerCWeights:
    """Hard override floors for Layer C (security leakage)."""
    # canary_hits = 1.0 always (not configurable)
    
    secret_matches_floor: float = 0.95      # Near-absolute, small false-positive margin
    
    should_block_floor: float = 0.90        # Enforcer hard block
    
    dlp_block_floor: float = 0.90           # DLP said BLOCK
    dlp_escalate_floor: float = 0.75        # DLP said ESCALATE
    dlp_redact_floor: float = 0.45          # DLP said REDACT (sanitized)
    
    pii_matches_floor: float = 0.60         # Personal info detected
    
    # Fingerprint: contribution = base * overlap + scale * overlap²
    fingerprint_base: float = 0.30          # Linear term
    fingerprint_scale: float = 0.25         # Quadratic term (penalizes high overlap more)

# Priorité sécurité > politique > fiabilité
@dataclass
class CombinationWeights:
    layer_a: float = 0.25   # Fiabilité des réponses — important mais pas critique
    layer_b: float = 0.35   # Politique et contrôle d'accès
    layer_c: float = 0.40   # Fuites de données — priorité maximale

    def __post_init__(self) -> None:
        total = self.layer_a + self.layer_b + self.layer_c
        if abs(total - 1.0) > 0.001:
            import warnings
            warnings.warn(
                f"CombinationWeights sum to {total:.3f}, expected 1.0. "
                "combined_score scale will be non-standard.",
                UserWarning,
                stacklevel=2,
            )


@dataclass
class SeverityThresholds:
    """Configurable severity classification thresholds."""
    critical: float = 0.85    # >= critical → CRITICAL
    high: float = 0.60        # >= high → HIGH
    medium: float = 0.30      # >= medium → MEDIUM, else LOW

    def __post_init__(self) -> None:
        if not (0 < self.medium < self.high < self.critical <= 1.0):
            raise ValueError(
                f"Severity thresholds must satisfy 0 < medium < high < critical <= 1.0. "
                f"Got medium={self.medium}, high={self.high}, critical={self.critical}."
            )


# ---------------------------------------------------------------------------
# Root config
# ---------------------------------------------------------------------------

@dataclass
class ScoringConfig:
    """Root configuration object for the Layer D risk scorer."""
    layer_a: LayerAWeights = field(default_factory=LayerAWeights)
    layer_b: LayerBWeights = field(default_factory=LayerBWeights)
    layer_c: LayerCWeights = field(default_factory=LayerCWeights)
    combination: CombinationWeights = field(default_factory=CombinationWeights)
    severity: SeverityThresholds = field(default_factory=SeverityThresholds)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScoringConfig":
        """Build config from dict (e.g., from YAML/JSON)."""
        def _build(dataclass_type: type, section: dict[str, Any]) -> Any:
            import dataclasses
            known = {f.name for f in dataclasses.fields(dataclass_type)}
            filtered = {k: v for k, v in section.items() if k in known}
            return dataclass_type(**filtered)

        return cls(
            layer_a=_build(LayerAWeights, data.get("layer_a", {})),
            layer_b=_build(LayerBWeights, data.get("layer_b", {})),
            layer_c=_build(LayerCWeights, data.get("layer_c", {})),
            combination=_build(CombinationWeights, data.get("combination", {})),
            severity=_build(SeverityThresholds, data.get("severity", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise to plain dict (for logging or export)."""
        import dataclasses
        return {
            "layer_a": dataclasses.asdict(self.layer_a),
            "layer_b": dataclasses.asdict(self.layer_b),
            "layer_c": dataclasses.asdict(self.layer_c),
            "combination": dataclasses.asdict(self.combination),
            "severity": dataclasses.asdict(self.severity),
        }


# Module-level default config
DEFAULT_CONFIG = ScoringConfig()