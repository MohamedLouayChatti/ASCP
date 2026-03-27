"""
Tests for NER deduplication logic in DLPScanner.

scanner.py deduplicates NER matches against regex PII matches: if any span of a
NER match overlaps any regex PII span the entire NER match is dropped.  These
tests exercise that path directly using a mocked NER detector.

Coverage targets:
  - NER match dropped when its span overlaps a regex PII match (same position)
  - NER match kept when its span does NOT overlap any regex PII span
  - NER match with multiple spans: dropped if ANY span overlaps (not just spans[0])
  - NER match with multiple non-overlapping spans: kept, all spans redacted
"""

import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.config import DLPConfig, PatternDef
from dlp.canary import CanaryEngine
from dlp.scanner import DLPScanner
from dlp.models import DLPAction, DLPMatch, ScanSurface


def _make_scanner(
    pii_regex: str = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]",
    pii_action: DLPAction = DLPAction.REDACT,
) -> DLPScanner:
    """Build a DLPScanner with NER enabled and a single configurable PII pattern."""
    config = DLPConfig(
        canary_action=DLPAction.BLOCK,
        canary_salt="test_salt_dedup",
        secrets_action=DLPAction.BLOCK,
        pii_action=pii_action,
        enable_ner=True,
        secret_patterns=[],
        pii_patterns=[PatternDef(name="email", regex=pii_regex)],
        canary_labels=["test_canary"],
        content_keys=["text"],
        surface_overrides={},
    )
    canary_engine = CanaryEngine(config)
    return DLPScanner(config, canary_engine)


def _email_span(text: str) -> tuple[int, int]:
    """Return (start, end) of the first email address found in text."""
    m = re.search(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]", text
    )
    assert m is not None, f"No email found in: {text!r}"
    return m.start(), m.end()


class TestNERDeduplication(unittest.TestCase):
    """Unit tests for the NER-vs-regex deduplication logic in DLPScanner.scan()."""

    # ------------------------------------------------------------------
    # Test 1: overlap → NER match dropped
    # ------------------------------------------------------------------
    def test_ner_overlap_with_regex_is_dropped(self):
        """
        A NER match whose span exactly coincides with a regex PII match must be
        dropped.  The result should contain exactly one pii_match (the regex one).
        """
        scanner = _make_scanner()
        text = "Contact user@example.com for info."
        start, end = _email_span(text)

        ner_match = DLPMatch(
            pattern_name="EMAIL",
            category="pii",
            action=DLPAction.REDACT,
            value="user@example.com",
            spans=[(start, end)],  # Same span as the regex match
            surface=ScanSurface.OUTPUT,
        )

        with patch.object(scanner.ner_detector, "detect", return_value=[ner_match]):
            result = scanner.scan(text, ScanSurface.OUTPUT)

        # Exactly one pii_match: the regex one. NER duplicate dropped.
        self.assertEqual(len(result.pii_matches), 1)
        self.assertEqual(result.pii_matches[0].pattern_name, "email")

    # ------------------------------------------------------------------
    # Test 2: no overlap → NER match kept
    # ------------------------------------------------------------------
    def test_ner_non_overlap_with_regex_is_kept(self):
        """
        A NER match at a position that does not overlap any regex PII span must
        be kept alongside the regex match.
        """
        scanner = _make_scanner()
        text = "Email: user@example.com and John Smith works here."

        # Locate the email span so the NER match can sit safely after it.
        email_start, email_end = _email_span(text)
        # "John Smith" comes after the email — compute its position dynamically.
        person_start = text.index("John Smith")
        person_end = person_start + len("John Smith")
        # Sanity: spans must NOT overlap.
        self.assertGreaterEqual(person_start, email_end)

        ner_match = DLPMatch(
            pattern_name="PERSON",
            category="pii",
            action=DLPAction.REDACT,
            value="John Smith",
            spans=[(person_start, person_end)],
            surface=ScanSurface.OUTPUT,
        )

        with patch.object(scanner.ner_detector, "detect", return_value=[ner_match]):
            result = scanner.scan(text, ScanSurface.OUTPUT)

        # Two pii_matches: regex email + NER PERSON
        self.assertEqual(len(result.pii_matches), 2)
        pattern_names = {m.pattern_name for m in result.pii_matches}
        self.assertIn("email", pattern_names)
        self.assertIn("PERSON", pattern_names)

        # Both must be redacted in the output
        self.assertNotIn("user@example.com", result.clean_text)
        self.assertNotIn("John Smith", result.clean_text)

    # ------------------------------------------------------------------
    # Test 3: multi-span — one span overlaps → whole NER match dropped
    # ------------------------------------------------------------------
    def test_ner_multiple_spans_partial_overlap_drops_whole_match(self):
        """
        A NER match with multiple spans must be dropped entirely if ANY of its
        spans overlaps a regex PII span — even if spans[0] is clean.

        This is the key regression test for the old bug where only spans[0]
        was checked.
        """
        scanner = _make_scanner()
        text = "Call John then user@example.com is the contact."
        email_start, email_end = _email_span(text)
        john_start = text.index("John")
        john_end = john_start + len("John")

        # spans[0] = "John" (no overlap), spans[1] = exact email span (overlap)
        ner_match = DLPMatch(
            pattern_name="MULTI_ENTITY",
            category="pii",
            action=DLPAction.REDACT,
            value="John … user@example.com",
            spans=[(john_start, john_end), (email_start, email_end)],
            surface=ScanSurface.OUTPUT,
        )

        with patch.object(scanner.ner_detector, "detect", return_value=[ner_match]):
            result = scanner.scan(text, ScanSurface.OUTPUT)

        # The NER match must be dropped entirely — only the regex email match remains.
        self.assertEqual(len(result.pii_matches), 1)
        self.assertEqual(result.pii_matches[0].pattern_name, "email")

    # ------------------------------------------------------------------
    # Test 4: multi-span — all spans clean → NER match fully kept + all spans redacted
    # ------------------------------------------------------------------
    def test_ner_multiple_non_overlapping_spans_all_redacted(self):
        """
        A NER match with multiple spans, none overlapping any regex PII span,
        must be kept and all its spans must appear in the redaction output.
        """
        scanner = _make_scanner()
        # No email address in this text → no regex PII match → empty regex_pii_spans
        text = "John Smith and Jane Doe are the contacts."

        john_start = text.index("John Smith")
        john_end = john_start + len("John Smith")
        jane_start = text.index("Jane Doe")
        jane_end = jane_start + len("Jane Doe")

        ner_match = DLPMatch(
            pattern_name="PERSON",
            category="pii",
            action=DLPAction.REDACT,
            value="John Smith … Jane Doe",
            spans=[(john_start, john_end), (jane_start, jane_end)],
            surface=ScanSurface.OUTPUT,
        )

        with patch.object(scanner.ner_detector, "detect", return_value=[ner_match]):
            result = scanner.scan(text, ScanSurface.OUTPUT)

        # NER match kept
        self.assertEqual(len(result.pii_matches), 1)
        self.assertEqual(result.pii_matches[0].pattern_name, "PERSON")

        # Both spans must be redacted
        self.assertNotIn("John Smith", result.clean_text)
        self.assertNotIn("Jane Doe", result.clean_text)

        # Two separate [REDACTED_pii_PERSON] markers expected
        self.assertEqual(result.clean_text.count("[REDACTED_pii_PERSON]"), 2)

    # ------------------------------------------------------------------
    # Test 5: NER short-circuits when current_action is already BLOCK
    # ------------------------------------------------------------------
    def test_ner_skipped_when_already_blocking(self):
        """
        NER must not be called when the scanner has already reached DLPAction.BLOCK
        (e.g. a secret was found), to avoid expensive model inference.
        """
        config = DLPConfig(
            canary_action=DLPAction.BLOCK,
            canary_salt="test_salt",
            secrets_action=DLPAction.BLOCK,
            pii_action=DLPAction.REDACT,
            enable_ner=True,
            secret_patterns=[PatternDef(name="openai_key", regex=r"sk-[A-Za-z0-9]{48}")],
            pii_patterns=[],
            canary_labels=["test_canary"],
            content_keys=["text"],
            surface_overrides={},
        )
        canary_engine = CanaryEngine(config)
        scanner = DLPScanner(config, canary_engine)

        secret_text = "sk-" + "A" * 48

        with patch.object(scanner.ner_detector, "detect") as mock_detect:
            result = scanner.scan(secret_text, ScanSurface.OUTPUT)
            mock_detect.assert_not_called()

        self.assertEqual(result.action, DLPAction.BLOCK)


if __name__ == "__main__":
    unittest.main()
