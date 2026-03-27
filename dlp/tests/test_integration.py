import os
import sys
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

# Add the parent directory to the path so we can import dlp
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import dlp
from dlp.models import DLPAction, ScanSurface, DLPMatch
from dlp.config import DLPConfig

class TestIntegration(unittest.TestCase):
    def setUp(self):
        # Re-init before each test just in case it was modified
        dlp.init(Path("no_such_file.yaml"))

    def test_canary_injection_and_detection(self):
        # Inject standard docs
        docs = [{"title": "doc1", "text": "This is public info."}]
        injected, token, label = dlp.inject_canaries_into_context(docs)
        
        self.assertEqual(len(injected), 1)
        self.assertIn("Note: Session reference [CANARY-", injected[0]["text"])
        self.assertIsNotNone(token)
        self.assertIsNotNone(label)

        # Simulate model echoing it
        bad_model_output = f"Hello the secret is {token}"
        decision = dlp.scan_output(bad_model_output)

        self.assertEqual(decision.action, DLPAction.BLOCK)
        self.assertTrue(decision.should_block)
        # Verify safe messages
        self.assertEqual(decision.safe_message, "I cannot share this information.")
        self.assertNotIn(token, decision.safe_message)
        self.assertEqual(decision.clean_text, decision.safe_message)
        self.assertTrue(any("canary_leak" in v for v in decision.violations))
        self.assertFalse(decision.should_escalate)
        self.assertIsNone(decision.escalation_event)

    def test_tool_argument_secret_blocked(self):
        # A tool argument containing sk-AAAA...48chars must be caught by scan_tool_args().
        fake_key = "sk-012345678901234567890123456789012345678901234567"
        args = {"body": f"Here is my key: {fake_key}"}

        decision = dlp.scan_tool_args("send_email", args)
        
        self.assertTrue(decision.should_block)
        # Should be blocked
        self.assertEqual(decision.safe_message, "TOOL_BLOCKED_SECRET_VIOLATION")
        self.assertNotIn("sk-", decision.safe_message)

    def test_tool_result_pii_redacted(self):
        # A tool result containing user@email.com must be redacted by scan_tool_result().
        # PII action default is REDACT, so on TOOL_RESULT we expect it to be redacted, not BLOCKED.
        tool_result = {"user_info": {"email": "user@email.com", "name": "Test"}}
        decision = dlp.scan_tool_result("get_user", tool_result)
        
        self.assertEqual(decision.action, DLPAction.REDACT)
        self.assertFalse(decision.should_block)
        self.assertIn("[REDACTED_pii_email]", decision.clean_text)
        self.assertNotIn("user@email.com", decision.clean_text)

    def test_block_path_produces_decision(self):
        # Trigger an override that forces block
        fake_key = "sk-012345678901234567890123456789012345678901234567"
        args = {"body": f"Here is my key: {fake_key}"}
        
        decision = dlp.scan_tool_args("test", args)
        
        self.assertTrue(decision.should_block)
        self.assertFalse(decision.should_escalate)
        self.assertIsNotNone(decision.safe_message)

    def test_ner_redaction(self):
        # We need to configure with enable_ner=True. We can write a temporary policy.
        content = """
dlp:
  enable_ner: true
  pii_action: REDACT
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
        
        try:
            dlp.init(Path(temp_path))
            
            with patch.object(dlp._scanner.ner_detector, 'detect') as mock_detect:
                mock_detect.return_value = [
                    DLPMatch(pattern_name="PERSON", category="pii", action=DLPAction.REDACT, value="John Doe", spans=[(11, 19)], surface=ScanSurface.OUTPUT)
                ]
                text = "My name is John Doe and I work at OpenAI."
                decision = dlp.scan_output(text)
                
                self.assertEqual(decision.action, DLPAction.REDACT)
                self.assertIn("[REDACTED_pii_PERSON]", decision.clean_text)
                self.assertNotIn("John Doe", decision.clean_text)
        finally:
            os.remove(temp_path)
            # Re-init safely
            dlp._scanner = None
            dlp._enforcer = None
            dlp._canary_engine = None


class TestIntegrationFallbackAndEdgeCases(unittest.TestCase):
    """Test integration error paths, fallback behavior, and edge cases."""

    def tearDown(self):
        # Reset global state after each test
        dlp._scanner = None
        dlp._enforcer = None
        dlp._canary_engine = None

    def test_scan_without_init_uses_fallback(self):
        """Test that scanning without calling init() uses safe defaults."""
        # Reset global state to simulate not calling init()
        dlp._scanner = None
        dlp._enforcer = None
        dlp._canary_engine = None
        
        # Should still work with defaults
        decision = dlp.scan_output("test input with email@example.com")
        
        # Should have completed scan with defaults
        self.assertIsNotNone(decision)
        self.assertIsNotNone(decision.action)

    def test_reinit_with_different_policy(self):
        """Test that re-initializing with a different policy works correctly."""
        # First init with defaults
        dlp.init(Path("nonexistent1.yaml"))
        
        # Verify first config
        decision1 = dlp.scan_output("sk-" + "A" * 48)
        self.assertEqual(decision1.action, DLPAction.BLOCK)
        
        # Re-init with different policy
        dlp.init(Path("nonexistent2.yaml"))
        
        # Verify second init also works
        decision2 = dlp.scan_output("sk-" + "B" * 48)
        self.assertEqual(decision2.action, DLPAction.BLOCK)

    def test_multiple_reinits_consistent_state(self):
        """Test that multiple re-initializations maintain consistent state."""
        for i in range(3):
            dlp.init(Path(f"fake_policy_{i}.yaml"))
            token = dlp.inject_canaries_into_context([{"text": "test"}])[1]
            self.assertIsNotNone(token)

    def test_scan_tool_result_with_nested_dict(self):
        """Test scan_tool_result with deeply nested dictionary structures."""
        dlp.init(Path("no_file.yaml"))
        
        nested_result = {
            "level1": {
                "level2": {
                    "level3": {
                        "email": "user@example.com",
                        "secret": "sk-" + "C" * 48
                    }
                }
            }
        }
        
        decision = dlp.scan_tool_result("nested_tool", nested_result)
        
        # Should detect both secret and PII
        # Secret takes precedence and blocks, so clean_text is a safe message code
        self.assertTrue(decision.should_block)  # Secret takes precedence
        self.assertEqual(decision.action, DLPAction.BLOCK)

    def test_scan_tool_result_with_list_of_dicts(self):
        """Test scan_tool_result with list structures."""
        dlp.init(Path("no_file.yaml"))
        
        result_with_list = {
            "records": [
                {"email": "user1@test.com", "name": "User 1"},
                {"email": "user2@test.com", "name": "User 2"}
            ]
        }
        
        decision = dlp.scan_tool_result("list_tool", result_with_list)
        
        # Both emails should be redacted
        self.assertEqual(decision.action, DLPAction.REDACT)
        self.assertFalse(decision.should_block)
        count = decision.clean_text.count("[REDACTED")
        self.assertGreaterEqual(count, 2)

    def test_all_three_surfaces_with_different_violations(self):
        """Test that all three surfaces properly handle violations."""
        dlp.init(Path("no_file.yaml"))
        fake_key = "sk-" + "D" * 48
        fake_email = "test@example.com"
        
        # OUTPUT surface with secret
        output_decision = dlp.scan_output(f"Key: {fake_key}")
        self.assertEqual(output_decision.action, DLPAction.BLOCK)
        self.assertEqual(output_decision.dlp_result.surface, ScanSurface.OUTPUT)
        
        # TOOL_ARGS surface with secret
        args_decision = dlp.scan_tool_args("test", {"arg": fake_key})
        self.assertEqual(args_decision.action, DLPAction.BLOCK)
        self.assertEqual(args_decision.dlp_result.surface, ScanSurface.TOOL_ARGS)
        
        # TOOL_RESULT surface with PII
        result_decision = dlp.scan_tool_result("test", {"result": fake_email})
        self.assertEqual(result_decision.action, DLPAction.REDACT)
        self.assertEqual(result_decision.dlp_result.surface, ScanSurface.TOOL_RESULT)

    def test_escalation_decision_with_dlp_result_populated(self):
        """Test that escalation decision includes dlp_result for telemetry."""
        content = """
dlp:
  canary_action: BLOCK
  canary_salt: "salt"
  secrets_action: ESCALATE
  pii_action: REDACT
  enable_ner: false
  secret_patterns:
    - name: test_secret
      regex: "secret_[0-9]+"
  pii_patterns:
    - name: test_pii
      regex: "pii_[0-9]+"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
        
        try:
            dlp.init(Path(temp_path))
            
            # Trigger escalation
            decision = dlp.scan_output("Found secret_12345")
            
            # Verify escalation
            self.assertEqual(decision.action, DLPAction.ESCALATE)
            self.assertTrue(decision.should_escalate)
            
            # Verify dlp_result is populated for telemetry
            self.assertIsNotNone(decision.dlp_result)
            self.assertGreater(len(decision.dlp_result.secret_matches), 0)
            self.assertIn("secret_12345", decision.dlp_result.secret_matches[0].value)
            
            # Verify escalation_event is created
            self.assertIsNotNone(decision.escalation_event)
        finally:
            os.remove(temp_path)
            dlp._scanner = None
            dlp._enforcer = None
            dlp._canary_engine = None

    def test_safe_redaction_preserves_text_integrity(self):
        """Test that redaction maintains text integrity and position correctness."""
        dlp.init(Path("no_file.yaml"))
        
        text = "Contact us at user@example.com or admin@company.com"
        decision = dlp.scan_output(text)
        
        # Both emails should be redacted
        self.assertEqual(decision.action, DLPAction.REDACT)
        redacted = decision.clean_text
        
        # Verify legitimate text is preserved
        self.assertIn("Contact us at", redacted)
        self.assertIn("or", redacted)
        
        # Verify emails are redacted
        self.assertNotIn("user@example.com", redacted)
        self.assertNotIn("admin@company.com", redacted)

    def test_multiple_scans_per_session(self):
        """Test that multiple consecutive scans work correctly with canary state."""
        dlp.init(Path("no_file.yaml"))
        
        # Inject canary once
        docs, token, label = dlp.inject_canaries_into_context([{"text": "doc"}])
        
        # First scan - clean
        decision1 = dlp.scan_output("I will not leak the token")
        self.assertEqual(decision1.action, DLPAction.ALLOW)
        
        # Second scan - leak the canary
        decision2 = dlp.scan_output(f"Actually here is: {token}")
        self.assertEqual(decision2.action, DLPAction.BLOCK)
        self.assertTrue(decision2.should_block)
        
        # Third scan - clean again
        decision3 = dlp.scan_output("Just regular text now")
        self.assertEqual(decision3.action, DLPAction.ALLOW)

    def test_tool_args_secret_always_blocks(self):
        """Test that secrets in TOOL_ARGS always block correctly regardless of policy."""
        content = """
dlp:
  canary_action: ALLOW
  canary_salt: "salt"
  secrets_action: ALLOW
  pii_action: ALLOW
  enable_ner: false
  secret_patterns:
    - name: api_key
      regex: "sk-[A-Za-z0-9]{48}"
  pii_patterns:
    - name: email
      regex: "[a-z]+@[a-z]+\\\\.[a-z]+"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
        
        try:
            dlp.init(Path(temp_path))
            
            # Even though secrets_action is ALLOW, tool args should still block
            fake_key = "sk-" + "E" * 48
            decision = dlp.scan_tool_args("api_call", {"token": fake_key})
            
            # Should BLOCK due to tool args override
            self.assertTrue(decision.should_block)
        finally:
            os.remove(temp_path)
            dlp._scanner = None
            dlp._enforcer = None
            dlp._canary_engine = None

    def test_violations_list_properly_populated(self):
        """Test that violations list is properly populated with violation types."""
        dlp.init(Path("no_file.yaml"))
        
        fake_key = "sk-" + "F" * 48
        decision = dlp.scan_output(f"Secret: {fake_key}")
        
        # Should have violation tracking
        self.assertGreater(len(decision.violations), 0)
        self.assertTrue(any("secret" in v.lower() for v in decision.violations))

    def test_action_prevents_information_leakage_in_decision(self):
        """Test that safe_message and clean_text never leak actual matched values."""
        dlp.init(Path("no_file.yaml"))
        
        sensitive_values = [
            "sk-" + "G" * 48,
            "AKIA" + "H" * 16,
            "ghp_" + "I" * 36,
            "sensitive@company.com"
        ]
        
        for value in sensitive_values:
            decision = dlp.scan_output(f"Found: {value}")
            
            # Never leak original value in clean_text
            self.assertNotIn(value, decision.clean_text)
            
            # For blocked/escalated, never leak in safe_message
            if decision.action in [DLPAction.BLOCK, DLPAction.ESCALATE]:
                self.assertNotIn(value, decision.safe_message)


if __name__ == '__main__':
    unittest.main()
