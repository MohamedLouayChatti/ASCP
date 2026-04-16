from __future__ import annotations

import json
import pytest

from layerd.risk.config import (
    CombinationWeights,
    DEFAULT_CONFIG,
    LayerAWeights,
    LayerBWeights,
    LayerCWeights,
    ScoringConfig,
    SeverityThresholds,
)
from layerd.risk.enums import (
    ContextSufficiency,
    ContractDecision,
    DLPAction,
    RiskLevel,
    Severity,
)
from layerd.risk.models import RiskInput
from layerd.risk.scorer import (
    _classify_severity,
    _combine,
    _compute_layer_a,
    _compute_layer_b,
    _compute_layer_c,
    _smooth_fingerprint_contribution,
    _smooth_relevance_penalty,
    compute_risk_score,
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def safe_input() -> RiskInput:
    return RiskInput()


@pytest.fixture
def cfg() -> ScoringConfig:
    return DEFAULT_CONFIG

# ===========================================================================
# SECTION 1 — Input Validation
# ===========================================================================
 
class TestInputValidation:
 
    def test_valid_input_does_not_raise(self, safe_input):
        compute_risk_score(safe_input)  # should not raise
 
    @pytest.mark.parametrize("field,value", [
        ("grounding_score", -0.01),
        ("grounding_score", 1.01),
        ("hallucination_risk", -0.5),
        ("hallucination_risk", 1.5),
        ("contradiction_ratio", 2.0),
        ("retrieval_relevance", -0.1),
        ("fingerprint_hits", 1.1),
    ])
    def test_out_of_range_raises(self, field, value):
        inp = RiskInput(**{field: value})
        with pytest.raises(ValueError, match=field):
            compute_risk_score(inp)
 
    def test_boundary_values_accepted(self):
        """Exact 0.0 and 1.0 are valid boundaries."""
        inp = RiskInput(
            grounding_score=0.0,
            hallucination_risk=1.0,
            contradiction_ratio=1.0,
            retrieval_relevance=0.0,
            fingerprint_hits=1.0,
        )
        result = compute_risk_score(inp)
        assert 0.0 <= result.score <= 1.0
 
 
# ===========================================================================
# SECTION 2 — Security Invariants (non-negotiable)
# ===========================================================================
 
class TestSecurityInvariants:
    """
    These tests directly map to the five ASCP invariants.
    Any failure here is a critical security regression.
    """
 
    # --- I3: canary hits → unconditional score = 1.0 ---
 
    def test_i3_canary_hit_forces_score_1(self):
        """I3: canary leak is definitive proof of breach. Score must be 1.0."""
        result = compute_risk_score(RiskInput(canary_hits=True))
        assert result.score == 1.0
 
    def test_i3_canary_severity_is_critical(self):
        result = compute_risk_score(RiskInput(canary_hits=True))
        assert result.severity == Severity.CRITICAL
 
    def test_i3_canary_invariant_recorded(self):
        result = compute_risk_score(RiskInput(canary_hits=True))
        assert "I3" in result.violated_invariants
 
    def test_i3_canary_cannot_be_diluted_by_good_signals(self):
        """Even with perfect trust signals, canary = 1.0. No dilution possible."""
        inp = RiskInput(
            canary_hits=True,
            grounding_score=1.0,
            hallucination_risk=0.0,
            contradiction_ratio=0.0,
            retrieval_relevance=1.0,
            context_sufficiency=ContextSufficiency.SUFFICIENT,
            decision=ContractDecision.ALLOW,
        )
        result = compute_risk_score(inp)
        assert result.score == 1.0
 
    # --- I1: forbidden tool access → floor 0.85 ---
 
    def test_i1_violation_enforces_floor(self):
        """I1: access control breach must hit the 0.85 floor."""
        result = compute_risk_score(RiskInput(violations=["I1"]))
        assert result.score >= DEFAULT_CONFIG.layer_b.violation_i1_floor
 
    def test_i1_violation_recorded_in_invariants(self):
        result = compute_risk_score(RiskInput(violations=["I1"]))
        assert "I1" in result.violated_invariants
 
    def test_i1_violation_with_block_decision(self):
        """I1 + BLOCK: should pick the higher of the two floors."""
        result = compute_risk_score(
            RiskInput(violations=["I1"], decision=ContractDecision.BLOCK)
        )
        expected_floor = max(
            DEFAULT_CONFIG.layer_b.violation_i1_floor,
            DEFAULT_CONFIG.layer_b.decision_block_floor,
        )
        assert result.score >= expected_floor
 
    # --- I2: argument constraint breach → floor 0.65 ---
 
    def test_i2_violation_enforces_floor(self):
        """I2: constraint breach must hit the 0.65 floor."""
        result = compute_risk_score(RiskInput(violations=["I2"]))
        assert result.score >= DEFAULT_CONFIG.layer_b.violation_i2_floor
 
    def test_i2_violation_recorded_in_invariants(self):
        result = compute_risk_score(RiskInput(violations=["I2"]))
        assert "I2" in result.violated_invariants
 
    def test_both_i1_i2_violated(self):
        """Both invariants violated: score must respect the highest floor."""
        result = compute_risk_score(RiskInput(violations=["I1", "I2"]))
        assert result.score >= DEFAULT_CONFIG.layer_b.violation_i1_floor
        assert "I1" in result.violated_invariants
        assert "I2" in result.violated_invariants
 
    # --- I5: every decision must have a reasoning trace ---
 
    def test_i5_reasoning_trace_always_present(self, safe_input):
        result = compute_risk_score(safe_input)
        assert len(result.reasoning_trace) > 0
 
    def test_i5_reasoning_trace_contains_all_layers(self, safe_input):
        result = compute_risk_score(safe_input)
        trace = "\n".join(result.reasoning_trace)
        assert "LAYER_A" in trace
        assert "LAYER_B" in trace
        assert "LAYER_C" in trace
        assert "COMBINE" in trace
        assert "MONOTONICITY" in trace
 
    def test_i5_reasoning_trace_on_critical_event(self):
        result = compute_risk_score(RiskInput(canary_hits=True))
        trace = "\n".join(result.reasoning_trace)
        assert "canary" in trace.lower()
 
    def test_i5_violated_invariants_in_trace(self):
        result = compute_risk_score(RiskInput(violations=["I1"]))
        trace = "\n".join(result.reasoning_trace)
        assert "I1" in trace
 
 
# ===========================================================================
# SECTION 3 — Monotonicity (risk never decreases)
# ===========================================================================
 
class TestMonotonicity:
 
    def test_final_score_geq_layer_b(self):
        """Final score can never be lower than Layer B alone."""
        inp = RiskInput(decision=ContractDecision.BLOCK)
        result = compute_risk_score(inp)
        assert result.score >= result.layer_scores["layer_b"]
 
    def test_final_score_geq_layer_c(self):
        """Final score can never be lower than Layer C alone."""
        inp = RiskInput(secret_matches=True)
        result = compute_risk_score(inp)
        assert result.score >= result.layer_scores["layer_c"]
 
    def test_adding_violation_never_lowers_score(self):
        """Adding a violation to a safe input must increase or maintain score."""
        base = compute_risk_score(RiskInput())
        with_violation = compute_risk_score(RiskInput(violations=["I2"]))
        assert with_violation.score >= base.score
 
    def test_canary_dominates_everything(self):
        """Canary hit must always produce score=1.0, overriding all other signals."""
        # Start with low-risk input, add canary
        without_canary = compute_risk_score(RiskInput(grounding_score=0.99))
        with_canary = compute_risk_score(RiskInput(grounding_score=0.99, canary_hits=True))
        assert with_canary.score > without_canary.score
        assert with_canary.score == 1.0
 
    def test_score_always_in_unit_interval(self):
        """score must always be in [0.0, 1.0]."""
        cases = [
            RiskInput(),
            RiskInput(canary_hits=True),
            RiskInput(violations=["I1", "I2"]),
            RiskInput(hallucination_risk=1.0, contradiction_ratio=1.0),
            RiskInput(secret_matches=True, pii_matches=True, fingerprint_hits=1.0),
        ]
        for inp in cases:
            result = compute_risk_score(inp)
            assert 0.0 <= result.score <= 1.0, f"Out of range: {result.score}"
 
 
# ===========================================================================
# SECTION 4 — Layer A: Trust Signals
# ===========================================================================
 
class TestLayerA:
 
    def test_perfect_trust_minimal_contribution(self, cfg):
        """Perfect grounding/relevance should produce near-zero Layer A score."""
        inp = RiskInput(
            grounding_score=1.0,
            hallucination_risk=0.0,
            contradiction_ratio=0.0,
            retrieval_relevance=1.0,
            context_sufficiency=ContextSufficiency.SUFFICIENT,
        )
        score, _ = _compute_layer_a(inp, cfg)
        assert score < 0.05
 
    def test_worst_trust_hits_cap(self, cfg):
        """Worst-case trust signals should hit the Layer A cap."""
        inp = RiskInput(
            grounding_score=0.0,
            hallucination_risk=1.0,
            contradiction_ratio=1.0,
            retrieval_relevance=0.0,
            context_sufficiency=ContextSufficiency.INSUFFICIENT,
        )
        score, _ = _compute_layer_a(inp, cfg)
        assert score == cfg.layer_a.cap
 
    def test_insufficient_context_adds_penalty(self, cfg):
        base = RiskInput(context_sufficiency=ContextSufficiency.SUFFICIENT)
        bad = RiskInput(context_sufficiency=ContextSufficiency.INSUFFICIENT)
        s_base, _ = _compute_layer_a(base, cfg)
        s_bad, _ = _compute_layer_a(bad, cfg)
        assert s_bad > s_base
 
    def test_partial_context_between_sufficient_and_insufficient(self, cfg):
        s_suff, _ = _compute_layer_a(
            RiskInput(context_sufficiency=ContextSufficiency.SUFFICIENT), cfg
        )
        s_part, _ = _compute_layer_a(
            RiskInput(context_sufficiency=ContextSufficiency.PARTIAL), cfg
        )
        s_insuff, _ = _compute_layer_a(
            RiskInput(context_sufficiency=ContextSufficiency.INSUFFICIENT), cfg
        )
        assert s_suff <= s_part <= s_insuff
 
    def test_layer_a_contributions_list_has_five_entries(self, cfg):
        _, contributions = _compute_layer_a(RiskInput(), cfg)
        signals = {c.signal for c in contributions}
        expected = {
            "grounding_score",
            "hallucination_risk",
            "contradiction_ratio",
            "retrieval_relevance",
            "context_sufficiency",
        }
        assert signals == expected
 
    def test_relevance_penalty_is_exponential(self, cfg):
        """Penalty at relevance=0 must be higher than at relevance=0.5 (exponential)."""
        p0 = _smooth_relevance_penalty(0.0, cfg)
        p05 = _smooth_relevance_penalty(0.5, cfg)
        p1 = _smooth_relevance_penalty(1.0, cfg)
        assert p0 > p05 > p1
 
    def test_relevance_penalty_max_is_scale(self, cfg):
        """Max penalty (relevance=0) should not exceed the configured scale."""
        p = _smooth_relevance_penalty(0.0, cfg)
        assert p <= cfg.layer_a.relevance_penalty_scale + 1e-9
 
 
# ===========================================================================
# SECTION 5 — Layer B: Policy Enforcement
# ===========================================================================
 
class TestLayerB:
 
    def test_allow_decision_no_override(self, cfg):
        inp = RiskInput(decision=ContractDecision.ALLOW, tool_risk_level=RiskLevel.LOW)
        score, _, overrides = _compute_layer_b(inp, cfg)
        override_names = [o.name for o in overrides]
        assert "decision_block" not in override_names
        assert "decision_require_approval" not in override_names
 
    def test_block_decision_enforces_floor(self, cfg):
        inp = RiskInput(decision=ContractDecision.BLOCK)
        score, _, _ = _compute_layer_b(inp, cfg)
        assert score >= cfg.layer_b.decision_block_floor
 
    def test_require_approval_enforces_floor(self, cfg):
        inp = RiskInput(decision=ContractDecision.REQUIRE_APPROVAL)
        score, _, _ = _compute_layer_b(inp, cfg)
        assert score >= cfg.layer_b.decision_approval_floor
 
    def test_block_floor_higher_than_approval_floor(self, cfg):
        """BLOCK is more severe than REQUIRE_APPROVAL."""
        assert cfg.layer_b.decision_block_floor > cfg.layer_b.decision_approval_floor
 
    @pytest.mark.parametrize("level,attr", [
        (RiskLevel.LOW, "tool_risk_low"),
        (RiskLevel.MEDIUM, "tool_risk_medium"),
        (RiskLevel.HIGH, "tool_risk_high"),
        (RiskLevel.CRITICAL, "tool_risk_critical"),
        (RiskLevel.UNKNOWN, "tool_risk_unknown"),
    ])
    def test_tool_risk_level_maps_to_weight(self, cfg, level, attr):
        inp = RiskInput(tool_risk_level=level)
        score, contributions, _ = _compute_layer_b(inp, cfg)
        expected = getattr(cfg.layer_b, attr)
        tool_contrib = next(c for c in contributions if c.signal == "tool_risk_level")
        assert tool_contrib.contribution == pytest.approx(expected)
 
    def test_tool_risk_levels_are_ordered(self, cfg):
        """LOW < MEDIUM < HIGH < CRITICAL in terms of score contribution."""
        scores = []
        for level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]:
            s, _, _ = _compute_layer_b(RiskInput(tool_risk_level=level), cfg)
            scores.append(s)
        assert scores == sorted(scores)
 
 
# ===========================================================================
# SECTION 6 — Layer C: Data Leakage
# ===========================================================================
 
class TestLayerC:
 
    def test_canary_returns_1_immediately(self, cfg):
        score, _, overrides = _compute_layer_c(RiskInput(canary_hits=True), cfg)
        assert score == 1.0
        assert any(o.name == "canary_hits" for o in overrides)
 
    def test_canary_skips_other_signals(self, cfg):
        """After canary hit, contributions list should be empty (early return)."""
        _, contributions, _ = _compute_layer_c(RiskInput(canary_hits=True), cfg)
        assert contributions == []
 
    def test_secret_matches_floor(self, cfg):
        score, _, _ = _compute_layer_c(RiskInput(secret_matches=True), cfg)
        assert score >= cfg.layer_c.secret_matches_floor
 
    def test_pii_matches_floor(self, cfg):
        score, _, _ = _compute_layer_c(RiskInput(pii_matches=True), cfg)
        assert score >= cfg.layer_c.pii_matches_floor
 
    def test_should_block_floor(self, cfg):
        score, _, _ = _compute_layer_c(RiskInput(should_block=True), cfg)
        assert score >= cfg.layer_c.should_block_floor
 
    def test_dlp_block_floor(self, cfg):
        score, _, _ = _compute_layer_c(RiskInput(action=DLPAction.BLOCK), cfg)
        assert score >= cfg.layer_c.dlp_block_floor
 
    def test_dlp_escalate_floor(self, cfg):
        score, _, _ = _compute_layer_c(RiskInput(action=DLPAction.ESCALATE), cfg)
        assert score >= cfg.layer_c.dlp_escalate_floor
 
    def test_dlp_redact_floor(self, cfg):
        score, _, _ = _compute_layer_c(RiskInput(action=DLPAction.REDACT), cfg)
        assert score >= cfg.layer_c.dlp_redact_floor
 
    def test_dlp_severity_ordering(self, cfg):
        """BLOCK > ESCALATE > REDACT > ALLOW in terms of DLP floors."""
        s_block, _, _ = _compute_layer_c(RiskInput(action=DLPAction.BLOCK), cfg)
        s_esc, _, _ = _compute_layer_c(RiskInput(action=DLPAction.ESCALATE), cfg)
        s_red, _, _ = _compute_layer_c(RiskInput(action=DLPAction.REDACT), cfg)
        s_allow, _, _ = _compute_layer_c(RiskInput(action=DLPAction.ALLOW), cfg)
        assert s_block >= s_esc >= s_red >= s_allow
 
    def test_fingerprint_hits_additive(self, cfg):
        """Fingerprint overlap adds to score additively."""
        s_zero, _, _ = _compute_layer_c(RiskInput(fingerprint_hits=0.0), cfg)
        s_half, _, _ = _compute_layer_c(RiskInput(fingerprint_hits=0.5), cfg)
        s_full, _, _ = _compute_layer_c(RiskInput(fingerprint_hits=1.0), cfg)
        assert s_full > s_half > s_zero
 
    def test_fingerprint_contribution_quadratic(self, cfg):
        """High overlap penalized more per unit (quadratic term)."""
        c_low = _smooth_fingerprint_contribution(0.1, cfg)
        c_high = _smooth_fingerprint_contribution(0.9, cfg)
        # quadratic: contribution/overlap should be higher at 0.9 than 0.1
        assert (c_high / 0.9) > (c_low / 0.1)
 
    def test_secret_higher_than_pii(self, cfg):
        """Secrets are more critical than PII."""
        assert cfg.layer_c.secret_matches_floor > cfg.layer_c.pii_matches_floor
 
    def test_no_leakage_signals_zero(self, cfg):
        """No leakage signals → Layer C score = 0."""
        score, _, _ = _compute_layer_c(RiskInput(), cfg)
        assert score == 0.0
 
 
# ===========================================================================
# SECTION 7 — Combination & Severity Classification
# ===========================================================================
 
class TestCombinationAndSeverity:
 
    def test_combination_weights_sum_to_1(self, cfg):
        total = cfg.combination.layer_a + cfg.combination.layer_b + cfg.combination.layer_c
        assert abs(total - 1.0) < 0.001
 
    def test_combination_weights_reflect_security_priority(self, cfg):
        """Layer C (security) >= Layer B (policy) >= Layer A (trust)."""
        assert cfg.combination.layer_c >= cfg.combination.layer_b >= cfg.combination.layer_a
 
    def test_combine_pure_math(self, cfg):
        result = _combine(0.4, 0.6, 0.8, cfg)
        expected = (
            cfg.combination.layer_a * 0.4
            + cfg.combination.layer_b * 0.6
            + cfg.combination.layer_c * 0.8
        )
        assert result == pytest.approx(round(min(expected, 1.0), 4))
 
    def test_combine_capped_at_1(self, cfg):
        result = _combine(1.0, 1.0, 1.0, cfg)
        assert result <= 1.0
 
    @pytest.mark.parametrize("score,expected_severity", [
        (0.00, Severity.LOW),
        (0.29, Severity.LOW),
        (0.30, Severity.MEDIUM),
        (0.59, Severity.MEDIUM),
        (0.60, Severity.HIGH),
        (0.84, Severity.HIGH),
        (0.85, Severity.CRITICAL),
        (1.00, Severity.CRITICAL),
    ])
    def test_severity_thresholds(self, cfg, score, expected_severity):
        result = _classify_severity(score, cfg)
        assert result == expected_severity
 
    def test_invalid_severity_thresholds_raise(self):
        with pytest.raises(ValueError):
            SeverityThresholds(critical=0.3, high=0.6, medium=0.1)  # not ordered
 
    def test_invalid_combination_weights_warn(self):
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            CombinationWeights(layer_a=0.5, layer_b=0.5, layer_c=0.5)
            assert any("sum" in str(warning.message).lower() for warning in w)
 
 
# ===========================================================================
# SECTION 8 — RiskResult Structure
# ===========================================================================
 
class TestRiskResultStructure:
 
    def test_result_has_layer_scores(self, safe_input):
        result = compute_risk_score(safe_input)
        assert "layer_a" in result.layer_scores
        assert "layer_b" in result.layer_scores
        assert "layer_c" in result.layer_scores
 
    def test_result_scores_in_unit_interval(self, safe_input):
        result = compute_risk_score(safe_input)
        for key, s in result.layer_scores.items():
            assert 0.0 <= s <= 1.0, f"{key} out of range: {s}"
 
    def test_combined_score_leq_final_score(self, safe_input):
        """combined_score can only be raised by overrides, never lowered."""
        result = compute_risk_score(safe_input)
        assert result.score >= result.combined_score
 
    def test_to_dict_is_json_serializable(self, safe_input):
        result = compute_risk_score(safe_input)
        d = result.to_dict()
        json.dumps(d)  # should not raise
 
    def test_to_dict_contains_required_keys(self, safe_input):
        d = compute_risk_score(safe_input).to_dict()
        for key in ("score", "severity", "layer_scores", "breakdown",
                    "overrides", "violations", "reasoning_trace"):
            assert key in d, f"Missing key: {key}"
 
    def test_result_is_immutable(self, safe_input):
        result = compute_risk_score(safe_input)
        with pytest.raises((AttributeError, TypeError)):
            result.score = 0.5  # frozen dataclass
 
    def test_contributions_all_have_explanations(self, safe_input):
        result = compute_risk_score(safe_input)
        for c in result.contributions:
            assert c.explanation, f"Empty explanation for signal: {c.signal}"
 
    def test_invariant_priority_order(self):
        """I3 must appear before I1 before I2 in violated_invariants."""
        result = compute_risk_score(
            RiskInput(canary_hits=True, violations=["I1", "I2"])
        )
        assert result.violated_invariants[0] == "I3"
 
 
# ===========================================================================
# SECTION 9 — ScoringConfig
# ===========================================================================
 
class TestScoringConfig:
 
    def test_default_config_instantiates(self):
        cfg = ScoringConfig()
        assert cfg.layer_a is not None
        assert cfg.layer_b is not None
        assert cfg.layer_c is not None
 
    def test_from_dict_roundtrip(self):
        original = ScoringConfig()
        d = original.to_dict()
        restored = ScoringConfig.from_dict(d)
        assert restored.layer_a.grounding == original.layer_a.grounding
        assert restored.combination.layer_c == original.combination.layer_c
 
    def test_from_dict_ignores_unknown_keys(self):
        """Extra keys in dict should not crash from_dict."""
        d = DEFAULT_CONFIG.to_dict()
        d["layer_a"]["nonexistent_key"] = 999
        ScoringConfig.from_dict(d)  # should not raise
 
    def test_custom_config_changes_score(self):
        """Passing a stricter config should change the output score."""
        strict_cfg = ScoringConfig(
            layer_b=LayerBWeights(decision_block_floor=0.99)
        )
        inp = RiskInput(decision=ContractDecision.BLOCK)
        default_result = compute_risk_score(inp)
        strict_result = compute_risk_score(inp, config=strict_cfg)
        assert strict_result.score >= default_result.score
 
    def test_layer_a_cap_is_respected(self):
        low_cap_cfg = ScoringConfig(layer_a=LayerAWeights(cap=0.10))
        inp = RiskInput(
            grounding_score=0.0,
            hallucination_risk=1.0,
            contradiction_ratio=1.0,
        )
        result = compute_risk_score(inp, config=low_cap_cfg)
        assert result.layer_scores["layer_a"] <= 0.10