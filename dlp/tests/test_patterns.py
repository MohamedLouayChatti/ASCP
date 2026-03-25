import unittest
import sys
from pathlib import Path

# Add the parent directory to the path so we can import dlp
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.models import ScanSurface, DLPAction
from dlp.config import DLPConfig
from dlp.patterns import PatternEngine

class TestPatternEngine(unittest.TestCase):
    def setUp(self):
        self.config = DLPConfig.defaults()
        self.engine = PatternEngine(self.config)

    def test_single_pass_redaction(self):
        text = "Contact me at bob@example.com or alice@example.com."
        matches, redacted = self.engine.scan_text(text, ScanSurface.OUTPUT)
        
        # PII action is REDACT by default
        self.assertEqual(len(matches), 2)
        self.assertIn("[REDACTED_pii_email]", redacted)
        self.assertNotIn("bob@example.com", redacted)
        self.assertNotIn("alice@example.com", redacted)
        
        # Ensure full sentence is mostly intact
        self.assertEqual(
            redacted,
            "Contact me at [REDACTED_pii_email] or [REDACTED_pii_email]."
        )

    def test_scan_args_serializes_dict(self):
        args = {
            "metadata": {
                "key_val": "sk-012345678901234567890123456789012345678901234567"
            }
        }
        matches = self.engine.scan_args("dummy_tool", args)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].category, "secret")
        # Action should be BLOCK based on defaults
        self.assertEqual(matches[0].action, DLPAction.BLOCK)

    def test_no_matches(self):
        text = "This is a clean text with no secrets."
        matches, redacted = self.engine.scan_text(text, ScanSurface.OUTPUT)
        self.assertEqual(len(matches), 0)
        self.assertEqual(redacted, text)

if __name__ == '__main__':
    unittest.main()
