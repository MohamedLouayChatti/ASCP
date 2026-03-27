import os
import sys
import unittest
from pathlib import Path

# Add the parent directory to the path so we can import dlp
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import dlp
from dlp.models import DLPAction, ScanSurface
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
        import tempfile
        from unittest.mock import patch
        from dlp.models import DLPMatch
        
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
            import os
            os.remove(temp_path)
            # Re-init safely
            dlp._scanner = None
            dlp._enforcer = None
            dlp._canary_engine = None

if __name__ == '__main__':
    unittest.main()
