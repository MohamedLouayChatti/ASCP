"""
Test suite for models.py - Testing DLPResult properties, DLPAction comparisons, and data structure correctness.
Focus: Deep path exploration and edge case handling for core data structures.
"""

import pytest
from dlp.models import (
    DLPAction, DLPResult, DLPMatch, CanaryHit, ScanSurface
)


class TestDLPActionComparison:
    """Test DLPAction enum comparison operators for priority-based logic."""

    def test_action_priority_values(self):
        """Verify that action priority values are correct and ordered."""
        assert DLPAction.ALLOW.priority == 0
        assert DLPAction.PASS_TO_ML.priority == 1
        assert DLPAction.REDACT.priority == 2
        assert DLPAction.ESCALATE.priority == 3
        assert DLPAction.BLOCK.priority == 4

    def test_action_less_than_operator(self):
        """Test __lt__ operator for priority ordering."""
        assert DLPAction.ALLOW < DLPAction.REDACT
        assert DLPAction.REDACT < DLPAction.ESCALATE
        assert DLPAction.ESCALATE < DLPAction.BLOCK
        assert not (DLPAction.BLOCK < DLPAction.ALLOW)
        assert not (DLPAction.ALLOW < DLPAction.ALLOW)

    def test_action_greater_than_operator(self):
        """Test __gt__ operator for priority ordering."""
        assert DLPAction.BLOCK > DLPAction.ESCALATE
        assert DLPAction.ESCALATE > DLPAction.REDACT
        assert DLPAction.REDACT > DLPAction.ALLOW
        assert not (DLPAction.ALLOW > DLPAction.BLOCK)
        assert not (DLPAction.ALLOW > DLPAction.ALLOW)

    def test_action_less_than_or_equal_operator(self):
        """Test __le__ operator - critical for policy enforcement."""
        # Equal cases
        assert DLPAction.ALLOW <= DLPAction.ALLOW
        assert DLPAction.BLOCK <= DLPAction.BLOCK
        
        # Less than cases
        assert DLPAction.ALLOW <= DLPAction.REDACT
        assert DLPAction.ALLOW <= DLPAction.BLOCK
        assert DLPAction.REDACT <= DLPAction.ESCALATE
        
        # Greater than (False)
        assert not (DLPAction.BLOCK <= DLPAction.ALLOW)
        assert not (DLPAction.ESCALATE <= DLPAction.REDACT)

    def test_action_greater_than_or_equal_operator(self):
        """Test __ge__ operator - critical for priority-based action selection."""
        # Equal cases
        assert DLPAction.ALLOW >= DLPAction.ALLOW
        assert DLPAction.BLOCK >= DLPAction.BLOCK
        
        # Greater than cases
        assert DLPAction.BLOCK >= DLPAction.ALLOW
        assert DLPAction.BLOCK >= DLPAction.REDACT
        assert DLPAction.ESCALATE >= DLPAction.REDACT
        
        # Less than (False)
        assert not (DLPAction.ALLOW >= DLPAction.BLOCK)
        assert not (DLPAction.REDACT >= DLPAction.ESCALATE)

    def test_action_priority_comparison_chain(self):
        """Test that priority comparisons work in chains for enforcement logic."""
        actions = [DLPAction.ALLOW, DLPAction.REDACT, DLPAction.ESCALATE, DLPAction.BLOCK]
        
        # Ascending order check
        for i in range(len(actions) - 1):
            assert actions[i] < actions[i + 1]
            assert actions[i] <= actions[i + 1]
            assert actions[i + 1] > actions[i]
            assert actions[i + 1] >= actions[i]

    def test_action_max_priority_selection(self):
        """Test that max() works correctly with DLPAction comparisons."""
        # Should select BLOCK as the highest priority
        assert max(DLPAction.ALLOW, DLPAction.BLOCK) == DLPAction.BLOCK
        assert max(DLPAction.REDACT, DLPAction.ESCALATE, DLPAction.ALLOW) == DLPAction.ESCALATE
        assert max([DLPAction.ALLOW, DLPAction.REDACT, DLPAction.BLOCK]) == DLPAction.BLOCK


class TestDLPResultProperties:
    """Test DLPResult properties for correctness across different violation states."""

    def test_has_violations_empty(self):
        """Test has_violations returns False when no violations present."""
        result = DLPResult(
            original_text="This is safe text",
            clean_text="This is safe text",
            action=DLPAction.ALLOW,
            surface=ScanSurface.OUTPUT,
            canary_hits=[],
            secret_matches=[],
            pii_matches=[]
        )
        assert result.has_violations is False

    def test_has_violations_with_canary_hits(self):
        """Test has_violations returns True with canary hits."""
        canary = CanaryHit(
            token="CANARY-test",
            label="api_credential_mock",
            context_excerpt="Found here",
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="Text with CANARY-test",
            clean_text="Text with [REDACTED]",
            action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT,
            canary_hits=[canary]
        )
        assert result.has_violations is True

    def test_has_violations_with_secret_matches(self):
        """Test has_violations returns True with secret matches."""
        secret = DLPMatch(
            pattern_name="openai_key",
            category="secret",
            action=DLPAction.BLOCK,
            value="sk-" + "A" * 48,
            spans=[(10, 58)],
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="My key is sk-" + "A" * 48,
            clean_text="My key is [REDACTED]",
            action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT,
            secret_matches=[secret]
        )
        assert result.has_violations is True

    def test_has_violations_with_pii_matches(self):
        """Test has_violations returns True with PII matches."""
        pii = DLPMatch(
            pattern_name="email",
            category="pii",
            action=DLPAction.REDACT,
            value="user@example.com",
            spans=[(5, 22)],
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="Email: user@example.com",
            clean_text="Email: [REDACTED]",
            action=DLPAction.REDACT,
            surface=ScanSurface.OUTPUT,
            pii_matches=[pii]
        )
        assert result.has_violations is True

    def test_has_violations_with_multiple_violations(self):
        """Test has_violations with multiple different violation types."""
        canary = CanaryHit(
            token="CANARY-x",
            label="db_password",
            context_excerpt="excerpt",
            surface=ScanSurface.OUTPUT
        )
        secret = DLPMatch(
            pattern_name="aws_key",
            category="secret",
            action=DLPAction.BLOCK,
            value="AKIA" + "A" * 16,
            spans=[(0, 20)],
            surface=ScanSurface.OUTPUT
        )
        pii = DLPMatch(
            pattern_name="email",
            category="pii",
            action=DLPAction.REDACT,
            value="test@test.com",
            spans=[(25, 38)],
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="Original",
            clean_text="Cleaned",
            action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT,
            canary_hits=[canary],
            secret_matches=[secret],
            pii_matches=[pii]
        )
        assert result.has_violations is True

    def test_should_block_true(self):
        """Test should_block returns True only when action is BLOCK."""
        result = DLPResult(
            original_text="text",
            clean_text="text",
            action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT
        )
        assert result.should_block is True

    def test_should_block_false_for_other_actions(self):
        """Test should_block returns False for non-BLOCK actions."""
        for action in [DLPAction.ALLOW, DLPAction.REDACT, DLPAction.ESCALATE]:
            result = DLPResult(
                original_text="text",
                clean_text="text",
                action=action,
                surface=ScanSurface.OUTPUT
            )
            assert result.should_block is False, f"should_block should be False for {action}"

    def test_invariant_violated_with_canary_hit(self):
        """Test invariant_violated returns 'I3' when canary detected."""
        canary = CanaryHit(
            token="CANARY-abc",
            label="api_credential_mock",
            context_excerpt="context",
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="text with canary",
            clean_text="text",
            action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT,
            canary_hits=[canary]
        )
        assert result.invariant_violated == "I3"

    def test_invariant_violated_with_secret_match(self):
        """Test invariant_violated returns 'I3' when secret detected."""
        secret = DLPMatch(
            pattern_name="github_token",
            category="secret",
            action=DLPAction.BLOCK,
            value="ghp_" + "x" * 36,
            spans=[(0, 40)],
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="secret here",
            clean_text="redacted",
            action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT,
            secret_matches=[secret]
        )
        assert result.invariant_violated == "I3"

    def test_invariant_violated_with_both_canary_and_secret(self):
        """Test invariant_violated with multiple critical violations."""
        canary = CanaryHit(
            token="CANARY-123",
            label="sys_admin_token",
            context_excerpt="ctx",
            surface=ScanSurface.OUTPUT
        )
        secret = DLPMatch(
            pattern_name="openai_key",
            category="secret",
            action=DLPAction.BLOCK,
            value="sk-" + "a" * 48,
            spans=[(50, 98)],
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="text",
            clean_text="cleaned",
            action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT,
            canary_hits=[canary],
            secret_matches=[secret]
        )
        assert result.invariant_violated == "I3"

    def test_invariant_violated_none_for_pii_only(self):
        """Test invariant_violated returns None when only PII detected (not critical)."""
        pii = DLPMatch(
            pattern_name="email",
            category="pii",
            action=DLPAction.REDACT,
            value="user@example.com",
            spans=[(0, 16)],
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="user@example.com",
            clean_text="[REDACTED]",
            action=DLPAction.REDACT,
            surface=ScanSurface.OUTPUT,
            pii_matches=[pii]
        )
        assert result.invariant_violated is None

    def test_invariant_violated_none_for_no_violations(self):
        """Test invariant_violated returns None when no violations."""
        result = DLPResult(
            original_text="safe text",
            clean_text="safe text",
            action=DLPAction.ALLOW,
            surface=ScanSurface.OUTPUT
        )
        assert result.invariant_violated is None

    def test_invariant_violated_with_escalate_action(self):
        """Test invariant_violated correctly identifies critical violations even with ESCALATE action."""
        secret = DLPMatch(
            pattern_name="aws_access_key",
            category="secret",
            action=DLPAction.ESCALATE,
            value="AKIA1234567890123456",
            spans=[(5, 25)],
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="Key: AKIA1234567890123456",
            clean_text="Key: [REDACTED]",
            action=DLPAction.ESCALATE,
            surface=ScanSurface.OUTPUT,
            secret_matches=[secret]
        )
        # Even with ESCALATE action, I3 should be triggered by secret presence
        assert result.invariant_violated == "I3"

    def test_dlp_result_surface_awareness(self):
        """Test DLPResult correctly stores surface information for different scanning contexts."""
        for surface in [ScanSurface.OUTPUT, ScanSurface.TOOL_ARGS, ScanSurface.TOOL_RESULT]:
            result = DLPResult(
                original_text="test",
                clean_text="test",
                action=DLPAction.ALLOW,
                surface=surface
            )
            assert result.surface == surface

    def test_dlp_result_violations_list(self):
        """Test DLPResult violations list is properly tracked."""
        violations = ["secret_detected", "pii_detected"]
        result = DLPResult(
            original_text="text",
            clean_text="text",
            action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT,
            violations=violations
        )
        assert result.violations == violations
        assert len(result.violations) == 2

    def test_dlp_match_span_correctness(self):
        """Test DLPMatch stores span positions correctly for multiple matches."""
        match = DLPMatch(
            pattern_name="email",
            category="pii",
            action=DLPAction.REDACT,
            value="user@example.com",
            spans=[(5, 21), (50, 66)],  # Multiple occurrences
            surface=ScanSurface.OUTPUT
        )
        assert len(match.spans) == 2
        assert match.spans[0] == (5, 21)
        assert match.spans[1] == (50, 66)
        assert match.category == "pii"
        assert match.pattern_name == "email"
