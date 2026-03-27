"""Tests for structured data scanner (dlp/structured.py)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.config import DLPConfig
from dlp.patterns import PatternEngine
from dlp.models import ScanSurface, DLPAction
from dlp.structured import scan_dict, redact_dict


def _engine(format_preserving: bool = False) -> PatternEngine:
    cfg = DLPConfig.defaults()
    cfg.format_preserving_redaction = format_preserving
    return PatternEngine(cfg)


def _config(format_preserving: bool = False) -> DLPConfig:
    cfg = DLPConfig.defaults()
    cfg.format_preserving_redaction = format_preserving
    return cfg


class TestScanDict(unittest.TestCase):
    def test_flat_dict_detects_email(self):
        data = {"email": "user@example.com", "name": "Alice"}
        matches = scan_dict(data, ScanSurface.TOOL_ARGS, _engine(), _config())
        self.assertTrue(any(m.pattern_name == "email" for m in matches))

    def test_flat_dict_source_path(self):
        data = {"contact": "user@example.com"}
        matches = scan_dict(data, ScanSurface.TOOL_ARGS, _engine(), _config())
        email_match = next(m for m in matches if m.pattern_name == "email")
        self.assertEqual(email_match.source_path, "contact")

    def test_nested_dict_source_path(self):
        data = {"user": {"profile": {"email": "user@example.com"}}}
        matches = scan_dict(data, ScanSurface.TOOL_ARGS, _engine(), _config())
        email_match = next(m for m in matches if m.pattern_name == "email")
        self.assertEqual(email_match.source_path, "user.profile.email")

    def test_list_index_in_source_path(self):
        data = {"records": [{"email": "a@b.com"}, {"email": "c@d.com"}]}
        matches = scan_dict(data, ScanSurface.TOOL_ARGS, _engine(), _config())
        paths = {m.source_path for m in matches if m.pattern_name == "email"}
        self.assertIn("records[0].email", paths)
        self.assertIn("records[1].email", paths)

    def test_non_string_scalars_skipped(self):
        data = {"count": 42, "active": True, "score": 3.14, "null": None}
        matches = scan_dict(data, ScanSurface.TOOL_ARGS, _engine(), _config())
        self.assertEqual(matches, [])

    def test_deeply_nested_secret_detected(self):
        data = {"a": {"b": {"c": {"token": "sk-" + "A" * 48}}}}
        matches = scan_dict(data, ScanSurface.TOOL_ARGS, _engine(), _config())
        secret = next((m for m in matches if m.pattern_name == "openai_key"), None)
        self.assertIsNotNone(secret)
        self.assertEqual(secret.source_path, "a.b.c.token")
        self.assertEqual(secret.action, DLPAction.BLOCK)

    def test_empty_dict_returns_no_matches(self):
        self.assertEqual(scan_dict({}, ScanSurface.TOOL_ARGS, _engine(), _config()), [])

    def test_list_of_strings(self):
        data = ["user@example.com", "clean text", "admin@corp.com"]
        matches = scan_dict(data, ScanSurface.TOOL_RESULT, _engine(), _config())
        paths = {m.source_path for m in matches if m.pattern_name == "email"}
        self.assertIn("[0]", paths)
        self.assertIn("[2]", paths)


class TestRedactDict(unittest.TestCase):
    def test_flat_dict_email_redacted(self):
        data = {"email": "user@example.com"}
        engine = _engine()
        config = _config()
        matches = scan_dict(data, ScanSurface.OUTPUT, engine, config)
        result = redact_dict(data, matches, config, engine)
        self.assertNotIn("user@example.com", result["email"])
        self.assertIn("[REDACTED", result["email"])

    def test_nested_dict_email_redacted(self):
        data = {"user": {"contact": "user@example.com"}}
        engine = _engine()
        config = _config()
        matches = scan_dict(data, ScanSurface.OUTPUT, engine, config)
        result = redact_dict(data, matches, config, engine)
        self.assertNotIn("user@example.com", result["user"]["contact"])

    def test_non_redact_action_not_replaced(self):
        """BLOCK action matches should not be replaced in the dict (clean_text handles that)."""
        data = {"token": "sk-" + "A" * 48}
        engine = _engine()
        config = _config()
        matches = scan_dict(data, ScanSurface.OUTPUT, engine, config)
        # BLOCK matches have non-REDACT action → redact_dict won't touch them
        result = redact_dict(data, matches, config, engine)
        # Original value should remain (block is handled at DLPResult level)
        self.assertIn("sk-", result["token"])

    def test_non_string_scalar_preserved(self):
        data = {"count": 42, "email": "user@example.com"}
        engine = _engine()
        config = _config()
        matches = scan_dict(data, ScanSurface.OUTPUT, engine, config)
        result = redact_dict(data, matches, config, engine)
        self.assertEqual(result["count"], 42)

    def test_format_preserving_in_redact_dict(self):
        data = {"email": "user@example.com"}
        engine = _engine(format_preserving=True)
        config = _config(format_preserving=True)
        matches = scan_dict(data, ScanSurface.OUTPUT, engine, config)
        result = redact_dict(data, matches, config, engine)
        # Should not contain original, should contain @
        self.assertNotIn("user@example.com", result["email"])
        self.assertIn("@", result["email"])


if __name__ == "__main__":
    unittest.main()
