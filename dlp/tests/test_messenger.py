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

if __name__ == '__main__':
    unittest.main()
