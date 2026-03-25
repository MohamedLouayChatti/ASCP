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

if __name__ == '__main__':
    unittest.main()
