"""Tests for format-preserving redaction (dlp/patterns.py PatternEngine.format_preserve)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.patterns import PatternEngine


class TestFormatPreserve(unittest.TestCase):
    def test_email_shape_preserved(self):
        result = PatternEngine.format_preserve("user@example.com", "email")
        self.assertIn("@", result)
        self.assertNotIn("user", result)
        self.assertNotIn("example", result)
        # Should have structure: local@domain.tld
        local, _, rest = result.partition("@")
        self.assertTrue(len(local) > 0)
        self.assertIn(".", rest)

    def test_email_local_masked(self):
        result = PatternEngine.format_preserve("alice@company.co.uk", "email")
        self.assertNotIn("alice", result)
        self.assertIn("@", result)

    def test_ipv4_structure_preserved(self):
        result = PatternEngine.format_preserve("192.168.1.1", "ipv4")
        parts = result.split(".")
        self.assertEqual(len(parts), 4)
        for part in parts:
            self.assertTrue(all(c == "x" for c in part), f"Unexpected chars in octet: {part}")

    def test_credit_card_last_four_visible(self):
        result = PatternEngine.format_preserve("4111111111111111", "credit_card")
        self.assertTrue(result.endswith("1111"))
        self.assertNotIn("4111111111111111", result)
        self.assertEqual(len(result), 16)

    def test_openai_key_prefix_preserved(self):
        key = "sk-" + "A" * 48
        result = PatternEngine.format_preserve(key, "openai_key")
        self.assertTrue(result.startswith("sk-"))
        self.assertNotIn("A" * 48, result)
        # Suffix should be all X (uppercase)
        suffix = result[3:]
        self.assertTrue(all(c == "X" for c in suffix))

    def test_aws_key_prefix_preserved(self):
        key = "AKIA" + "A" * 16
        result = PatternEngine.format_preserve(key, "aws_access_key")
        self.assertTrue(result.startswith("AKIA"))
        suffix = result[4:]
        self.assertTrue(all(c == "X" for c in suffix))

    def test_github_token_prefix_preserved(self):
        token = "ghp_" + "a" * 36
        result = PatternEngine.format_preserve(token, "github_token")
        self.assertTrue(result.startswith("ghp_"))
        suffix = result[4:]
        self.assertTrue(all(c == "x" for c in suffix))

    def test_generic_fallback_preserves_structure(self):
        result = PatternEngine.format_preserve("MyToken123", "some_unknown_pattern")
        # Letters → X/x, digits → 0
        self.assertEqual(result[0], "X")   # M → uppercase → X
        self.assertEqual(result[1], "x")   # y → lowercase → x
        self.assertNotIn("1", result)
        self.assertNotIn("2", result)
        self.assertNotIn("3", result)

    def test_format_preserving_scan_text(self):
        """Integration: scan_text uses format_preserve when config flag is on."""
        from dlp.config import DLPConfig
        from dlp.models import ScanSurface, DLPAction

        cfg = DLPConfig.defaults()
        cfg.format_preserving_redaction = True
        for p in cfg.pii_patterns:
            if p.name == "email":
                p.action = DLPAction.REDACT
        engine = PatternEngine(cfg)

        result = engine.scan("Contact: user@company.com", ScanSurface.OUTPUT)
        redacted = result.redacted_text
        self.assertIn("@", redacted)
        self.assertNotIn("user@company.com", redacted)
        self.assertNotIn("[REDACTED", redacted)


if __name__ == "__main__":
    unittest.main()
