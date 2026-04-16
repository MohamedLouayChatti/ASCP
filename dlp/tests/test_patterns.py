import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.models import ScanSurface, DLPAction
from dlp.config import DLPConfig
from dlp.patterns import PatternEngine
import dlp


class TestPatternEngine(unittest.TestCase):
    def setUp(self):
        self.config = DLPConfig.defaults()
        for p in self.config.pii_patterns:
            if p.name == "email":
                p.action = DLPAction.REDACT
        self.engine = PatternEngine(self.config)

    def test_single_pass_redaction(self):
        text = "Contact me at bob@example.com or alice@example.com."
        result = self.engine.scan(text, ScanSurface.OUTPUT)
        matches = result.pii
        redacted = result.redacted_text

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

    def test_scan_tool_args_via_public_api_catches_nested_secret(self):
        """
        scan_tool_args() must detect secrets embedded in nested dict structures.
        This replaces the former test_scan_args_serializes_dict which tested a
        now-deleted PatternEngine.scan_args() method. The serialization is the
        responsibility of the public API (dlp.scan_tool_args), not PatternEngine.
        """
        dlp.init(Path("nonexistent_default.yaml"))

        args = {
            "metadata": {
                "key_val": "sk-012345678901234567890123456789012345678901234567"
            }
        }
        decision = dlp.scan_tool_args("dummy_tool", args)

        # The secret must be detected regardless of nesting depth
        self.assertTrue(decision.should_block)
        self.assertEqual(decision.action, DLPAction.BLOCK)
        self.assertTrue(any("secret" in v for v in decision.violations))

    def test_no_matches(self):
        text = "This is a clean text with no secrets."
        result = self.engine.scan(text, ScanSurface.OUTPUT)
        matches = result.secrets + result.pii
        redacted = result.redacted_text
        self.assertEqual(len(matches), 0)
        self.assertEqual(redacted, text)

    def test_overlapping_matches_produce_single_redacted_placeholder(self):
        """Overlapping redaction spans must collapse to a single [REDACTED] placeholder."""
        redactions = [(0, 10, "[REDACTED_a]"), (5, 15, "[REDACTED_b]")]
        result = PatternEngine.apply_redactions("Hello world text", redactions)
        self.assertIn("[REDACTED]", result)
        # Only one placeholder should appear for the merged span
        self.assertEqual(result.count("[REDACTED"), 1)


if __name__ == '__main__':
    unittest.main()
