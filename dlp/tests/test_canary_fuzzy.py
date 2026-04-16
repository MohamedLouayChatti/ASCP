"""Tests for fuzzy canary matching (dlp/canary.py)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.config import DLPConfig
from dlp.canary import CanaryEngine, _normalize
from dlp.models import ScanSurface


def _make_engine(fuzzy: bool = True, overlap: float = 0.8) -> CanaryEngine:
    cfg = DLPConfig.defaults()
    cfg.canary_fuzzy_match = fuzzy
    cfg.canary_fuzzy_overlap = overlap
    return CanaryEngine(cfg)


class TestNormalize(unittest.TestCase):
    def test_strips_non_alphanumeric(self):
        # Hyphens stripped, result is lowercase alphanumeric only
        self.assertEqual(_normalize("CANARY-abcd1234"), "canaryabcd1234")
        self.assertEqual(_normalize("CANARY-abcd"), "canaryabcd")
        self.assertEqual(_normalize("Hello, World!"), "helloworld")

    def test_lowercase(self):
        self.assertEqual(_normalize("HELLO"), "hello")

    def test_empty(self):
        self.assertEqual(_normalize(""), "")


class TestCanaryFuzzyDetection(unittest.TestCase):
    def test_exact_detection_still_works_with_fuzzy_enabled(self):
        engine = _make_engine(fuzzy=True)
        label = list(engine._label_to_token.keys())[0]
        token = engine._label_to_token[label]
        hits = engine.detect(f"Here is the token: {token}", ScanSurface.OUTPUT)
        self.assertEqual(len(hits), 1)
        self.assertFalse(hits[0].fuzzy, "Exact match should have fuzzy=False")

    def test_exact_hit_not_double_counted_in_fuzzy(self):
        engine = _make_engine(fuzzy=True)
        label = list(engine._label_to_token.keys())[0]
        token = engine._label_to_token[label]
        hits = engine.detect(f"Token: {token}", ScanSurface.OUTPUT)
        # Should be exactly 1 hit (exact), not 2 (exact + fuzzy)
        self.assertEqual(len(hits), 1)

    def test_whitespace_inserted_token_detected_fuzzy(self):
        engine = _make_engine(fuzzy=True, overlap=0.7)
        label = list(engine._label_to_token.keys())[0]
        token = engine._label_to_token[label]
        # Insert spaces to defeat exact matching
        spaced = " ".join(token)
        hits = engine.detect(f"See: {spaced}", ScanSurface.OUTPUT)
        fuzzy_hits = [h for h in hits if h.fuzzy]
        self.assertGreater(len(fuzzy_hits), 0, "Should detect whitespace-spaced token via fuzzy")
        self.assertEqual(fuzzy_hits[0].label, label)

    def test_lowercased_token_detected_fuzzy(self):
        engine = _make_engine(fuzzy=True, overlap=0.7)
        label = list(engine._label_to_token.keys())[0]
        token = engine._label_to_token[label]
        lowered = token.lower()
        # Exact match fails (case sensitive), fuzzy should catch it
        self.assertNotIn(token, lowered)  # confirm no exact match
        hits = engine.detect(f"ref: {lowered}", ScanSurface.OUTPUT)
        fuzzy_hits = [h for h in hits if h.fuzzy]
        self.assertGreater(len(fuzzy_hits), 0, "Lowercased token should be found by fuzzy")

    def test_clean_text_no_false_positive(self):
        engine = _make_engine(fuzzy=True, overlap=0.99)  # very strict
        hits = engine.detect("completely unrelated text with random words", ScanSurface.OUTPUT)
        self.assertEqual(hits, [])

    def test_fuzzy_disabled_clean_no_hit(self):
        engine = _make_engine(fuzzy=False)
        label = list(engine._label_to_token.keys())[0]
        token = engine._label_to_token[label]
        spaced = " ".join(token)
        hits = engine.detect(f"ref: {spaced}", ScanSurface.OUTPUT)
        # Fuzzy disabled → only exact match possible → spaced version not found
        self.assertEqual(hits, [])

    def test_fuzzy_hit_has_fuzzy_flag_true(self):
        engine = _make_engine(fuzzy=True, overlap=0.7)
        label = list(engine._label_to_token.keys())[0]
        token = engine._label_to_token[label]
        lowered = token.lower()
        hits = engine.detect(f"see: {lowered}", ScanSurface.OUTPUT)
        fuzzy_hits = [h for h in hits if h.fuzzy]
        if fuzzy_hits:
            self.assertTrue(fuzzy_hits[0].fuzzy)
            self.assertIsNotNone(fuzzy_hits[0].context_excerpt)


if __name__ == "__main__":
    unittest.main()
