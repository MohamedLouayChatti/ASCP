import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.models import DLPResult, DLPAction, ScanSurface, CanaryHit, DLPMatch
from dlp.messenger import SafeMessenger

class TestSafeMessenger(unittest.TestCase):
    def setUp(self):
        self.messenger = SafeMessenger()

    def test_output_surface_messages(self):
        # Canary
        canary_hit = CanaryHit(token="CANARY-XXX", label="test", context_excerpt="leak", surface=ScanSurface.OUTPUT)
        res = DLPResult(
            original_text="leak CANARY-XXX", clean_text="", action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT, canary_hits=[canary_hit]
        )
        msg = self.messenger.get_message(res)
        self.assertNotIn("CANARY-XXX", msg)
        self.assertEqual(msg, "I cannot share this information.")
        
        # Secret
        secret_hit = DLPMatch(
            pattern_name="openai_key", category="secret", action=DLPAction.BLOCK,
            value="sk-XXX", spans=[(0, 5)], surface=ScanSurface.OUTPUT
        )
        res2 = DLPResult(
            original_text="sk-XXX", clean_text="", action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT, secret_matches=[secret_hit]
        )
        msg2 = self.messenger.get_message(res2)
        self.assertEqual(msg2, "I cannot share this information.")

    def test_tool_surface_messages(self):
        # Tool args don't have polite strings
        secret_hit = DLPMatch(
            pattern_name="openai_key", category="secret", action=DLPAction.BLOCK,
            value="sk-XXX", spans=[(0, 5)], surface=ScanSurface.TOOL_ARGS
        )
        res = DLPResult(
            original_text="sk-XXX", clean_text="", action=DLPAction.BLOCK,
            surface=ScanSurface.TOOL_ARGS, secret_matches=[secret_hit]
        )
        msg = self.messenger.get_message(res)
        self.assertEqual(msg, "TOOL_BLOCKED_SECRET_VIOLATION")

    def test_pii_only_message(self):
        pii_hit = DLPMatch(
            pattern_name="email", category="pii", action=DLPAction.REDACT,
            value="test@example.com", spans=[(0, 16)], surface=ScanSurface.OUTPUT
        )
        res = DLPResult(
            original_text="test@example.com", clean_text="[REDACTED_pii_email]", action=DLPAction.REDACT,
            surface=ScanSurface.OUTPUT, pii_matches=[pii_hit]
        )
        msg = self.messenger.get_message(res)
        self.assertEqual(msg, "Some personal information was removed from this response.")

    def test_escalate_message(self):
        secret_hit = DLPMatch(
            pattern_name="openai_key", category="secret", action=DLPAction.ESCALATE,
            value="sk-XXX", spans=[(0, 5)], surface=ScanSurface.OUTPUT
        )
        res = DLPResult(
            original_text="sk-XXX", clean_text="", action=DLPAction.ESCALATE,
            surface=ScanSurface.OUTPUT, secret_matches=[secret_hit]
        )
        msg = self.messenger.get_message(res)
        self.assertEqual(msg, "This request has been blocked and flagged for review.")


class TestSafeMessengerComprehensive(unittest.TestCase):
    """Comprehensive testing for all message combinations and edge cases."""

    def setUp(self):
        self.messenger = SafeMessenger()

    # ===== OUTPUT Surface Tests =====
    def test_output_surface_with_escalate_action(self):
        """Test ESCALATE action on OUTPUT surface returns escalation message."""
        secret_hit = DLPMatch(
            pattern_name="aws_key", category="secret", action=DLPAction.ESCALATE,
            value="AKIA1234567890", spans=[(0, 14)], surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="Key: AKIA1234567890",
            clean_text="Key: [REDACTED]",
            action=DLPAction.ESCALATE,
            surface=ScanSurface.OUTPUT,
            secret_matches=[secret_hit]
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "This request has been blocked and flagged for review.")
        self.assertNotIn("AKIA", msg)

    def test_output_surface_canary_takes_precedence_over_secret(self):
        """Test that canary message takes precedence over secret message."""
        canary = CanaryHit(
            token="CANARY-test",
            label="api_credential_mock",
            context_excerpt="ctx",
            surface=ScanSurface.OUTPUT
        )
        secret = DLPMatch(
            pattern_name="openai_key", category="secret", action=DLPAction.BLOCK,
            value="sk-test",
            spans=[(0, 7)],
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
        msg = self.messenger.get_message(result)
        # Canary should take precedence
        self.assertEqual(msg, "I cannot share this information.")

    def test_output_surface_canary_with_escalate(self):
        """Test ESCALATE action with canary hit on OUTPUT."""
        canary = CanaryHit(
            token="CANARY-xyz",
            label="db_password",
            context_excerpt="excerpt",
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="text with CANARY-xyz",
            clean_text="text with [REDACTED]",
            action=DLPAction.ESCALATE,
            surface=ScanSurface.OUTPUT,
            canary_hits=[canary]
        )
        msg = self.messenger.get_message(result)
        # ESCALATE action takes precedence for message
        self.assertEqual(msg, "This request has been blocked and flagged for review.")

    def test_output_surface_secret_takes_precedence_over_pii(self):
        """Test that secret message takes precedence over PII message."""
        secret = DLPMatch(
            pattern_name="github_token", category="secret", action=DLPAction.BLOCK,
            value="ghp_abc",
            spans=[(0, 7)],
            surface=ScanSurface.OUTPUT
        )
        pii = DLPMatch(
            pattern_name="email", category="pii", action=DLPAction.REDACT,
            value="user@example.com",
            spans=[(10, 26)],
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="ghp_abc user@example.com",
            clean_text="[REDACTED] [REDACTED]",
            action=DLPAction.BLOCK,
            surface=ScanSurface.OUTPUT,
            secret_matches=[secret],
            pii_matches=[pii]
        )
        msg = self.messenger.get_message(result)
        # Secret should take precedence
        self.assertEqual(msg, "I cannot share this information.")

    def test_output_surface_pii_only(self):
        """Test PII-only message on OUTPUT surface."""
        pii = DLPMatch(
            pattern_name="ipv4", category="pii", action=DLPAction.REDACT,
            value="192.168.1.1",
            spans=[(0, 11)],
            surface=ScanSurface.OUTPUT
        )
        result = DLPResult(
            original_text="192.168.1.1",
            clean_text="[REDACTED]",
            action=DLPAction.REDACT,
            surface=ScanSurface.OUTPUT,
            pii_matches=[pii]
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "Some personal information was removed from this response.")

    def test_output_surface_no_violations(self):
        """Test default message when no violations on OUTPUT."""
        result = DLPResult(
            original_text="safe text",
            clean_text="safe text",
            action=DLPAction.ALLOW,
            surface=ScanSurface.OUTPUT
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "I cannot complete this request due to a policy constraint.")

    # ===== TOOL_ARGS Surface Tests =====
    def test_tool_args_canary_violation(self):
        """Test TOOL_ARGS surface with canary violation returns code."""
        canary = CanaryHit(
            token="CANARY-test",
            label="api_credential_mock",
            context_excerpt="ctx",
            surface=ScanSurface.TOOL_ARGS
        )
        result = DLPResult(
            original_text="arg: CANARY-test",
            clean_text="arg: [REDACTED]",
            action=DLPAction.BLOCK,
            surface=ScanSurface.TOOL_ARGS,
            canary_hits=[canary]
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "TOOL_BLOCKED_CANARY_VIOLATION")
        # Verify the actual token is NOT leaked
        self.assertNotIn("CANARY-test", msg)

    def test_tool_args_secret_violation(self):
        """Test TOOL_ARGS surface with secret violation."""
        secret = DLPMatch(
            pattern_name="openai_key", category="secret", action=DLPAction.BLOCK,
            value="sk-abc",
            spans=[(0, 6)],
            surface=ScanSurface.TOOL_ARGS
        )
        result = DLPResult(
            original_text="sk-abc",
            clean_text="[REDACTED]",
            action=DLPAction.BLOCK,
            surface=ScanSurface.TOOL_ARGS,
            secret_matches=[secret]
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "TOOL_BLOCKED_SECRET_VIOLATION")

    def test_tool_args_pii_violation(self):
        """Test TOOL_ARGS surface with PII violation."""
        pii = DLPMatch(
            pattern_name="email", category="pii", action=DLPAction.REDACT,
            value="test@example.com",
            spans=[(0, 16)],
            surface=ScanSurface.TOOL_ARGS
        )
        result = DLPResult(
            original_text="test@example.com",
            clean_text="[REDACTED]",
            action=DLPAction.REDACT,
            surface=ScanSurface.TOOL_ARGS,
            pii_matches=[pii]
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "TOOL_BLOCKED_PII_VIOLATION")

    def test_tool_args_escalate_action(self):
        """Test TOOL_ARGS surface with ESCALATE action."""
        secret = DLPMatch(
            pattern_name="aws_key", category="secret", action=DLPAction.ESCALATE,
            value="AKIA1234567890",
            spans=[(0, 14)],
            surface=ScanSurface.TOOL_ARGS
        )
        result = DLPResult(
            original_text="AKIA1234567890",
            clean_text="[REDACTED]",
            action=DLPAction.ESCALATE,
            surface=ScanSurface.TOOL_ARGS,
            secret_matches=[secret]
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "TOOL_ESCALATED_POLICY_VIOLATION")

    def test_tool_args_no_violations(self):
        """Test TOOL_ARGS with no violations returns default code."""
        result = DLPResult(
            original_text="safe_arg",
            clean_text="safe_arg",
            action=DLPAction.ALLOW,
            surface=ScanSurface.TOOL_ARGS
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "TOOL_BLOCKED_POLICY_VIOLATION")

    # ===== TOOL_RESULT Surface Tests =====
    def test_tool_result_canary_violation(self):
        """Test TOOL_RESULT surface with canary violation."""
        canary = CanaryHit(
            token="CANARY-test",
            label="sys_admin_token",
            context_excerpt="returned_data",
            surface=ScanSurface.TOOL_RESULT
        )
        result = DLPResult(
            original_text='{"data": "CANARY-test"}',
            clean_text='{"data": "[REDACTED]"}',
            action=DLPAction.BLOCK,
            surface=ScanSurface.TOOL_RESULT,
            canary_hits=[canary]
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "TOOL_BLOCKED_CANARY_VIOLATION")

    def test_tool_result_secret_violation(self):
        """Test TOOL_RESULT surface with secret violation."""
        secret = DLPMatch(
            pattern_name="github_token", category="secret", action=DLPAction.BLOCK,
            value="ghp_abc",
            spans=[(0, 7)],
            surface=ScanSurface.TOOL_RESULT
        )
        result = DLPResult(
            original_text="ghp_abc",
            clean_text="[REDACTED]",
            action=DLPAction.BLOCK,
            surface=ScanSurface.TOOL_RESULT,
            secret_matches=[secret]
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "TOOL_BLOCKED_SECRET_VIOLATION")

    def test_tool_result_escalate_action(self):
        """Test TOOL_RESULT surface with ESCALATE action."""
        pii = DLPMatch(
            pattern_name="email", category="pii", action=DLPAction.ESCALATE,
            value="sensitive@corp.com",
            spans=[(0, 19)],
            surface=ScanSurface.TOOL_RESULT
        )
        result = DLPResult(
            original_text="sensitive@corp.com",
            clean_text="[REDACTED]",
            action=DLPAction.ESCALATE,
            surface=ScanSurface.TOOL_RESULT,
            pii_matches=[pii]
        )
        msg = self.messenger.get_message(result)
        self.assertEqual(msg, "TOOL_ESCALATED_POLICY_VIOLATION")

    # ===== Security Tests: No Information Leakage =====
    def test_all_messages_contain_no_matched_values(self):
        """Verify that no message ever contains actual matched values."""
        matched_values = [
            "sk-" + "A" * 48,
            "AKIA1234567890AB",
            "ghp_" + "B" * 36,
            "test@example.com",
            "192.168.1.1",
            "CANARY-leaked"
        ]
        
        for value in matched_values:
            # Test with SECRET violation
            if value.startswith("sk-") or value.startswith("AKIA") or value.startswith("ghp_"):
                secret = DLPMatch(
                    pattern_name="test", category="secret", action=DLPAction.BLOCK,
                    value=value, spans=[(0, len(value))],
                    surface=ScanSurface.OUTPUT
                )
                result = DLPResult(
                    original_text=value,
                    clean_text="[REDACTED]",
                    action=DLPAction.BLOCK,
                    surface=ScanSurface.OUTPUT,
                    secret_matches=[secret]
                )
                msg = self.messenger.get_message(result)
                self.assertNotIn(value, msg)
            
            # Test with PII violation
            if "@" in value or "." in value and not value.startswith("CANARY"):
                pii = DLPMatch(
                    pattern_name="test", category="pii", action=DLPAction.REDACT,
                    value=value, spans=[(0, len(value))],
                    surface=ScanSurface.OUTPUT
                )
                result = DLPResult(
                    original_text=value,
                    clean_text="[REDACTED]",
                    action=DLPAction.REDACT,
                    surface=ScanSurface.OUTPUT,
                    pii_matches=[pii]
                )
                msg = self.messenger.get_message(result)
                self.assertNotIn(value, msg)


if __name__ == '__main__':
    unittest.main()
