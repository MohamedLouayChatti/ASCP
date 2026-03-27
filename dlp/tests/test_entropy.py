"""Tests for Shannon entropy detection (dlp/entropy.py)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.config import DLPConfig
from dlp.entropy import EntropyScanner, shannon_entropy
from dlp.models import ScanSurface, DLPAction


def _make_scanner(**overrides) -> EntropyScanner:
    cfg = DLPConfig.defaults()
    cfg.enable_entropy = True
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return EntropyScanner(cfg)


class TestShannonEntropy(unittest.TestCase):
    def test_empty_string_returns_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_uniform_string_max_entropy(self):
        # All unique chars → maximum entropy
        text = "abcdefghij"
        score = shannon_entropy(text)
        self.assertGreater(score, 3.0)

    def test_repetitive_string_low_entropy(self):
        score = shannon_entropy("aaaaaaaaaaaaaaaaaaaaaa")
        self.assertAlmostEqual(score, 0.0)

    def test_known_high_entropy_token(self):
        # A 32-char random hex string ≈ 4 bits/char
        score = shannon_entropy("a3f7c9b2e1d048561f3a9c7b2e4d5f8a")
        self.assertGreater(score, 3.5)


class TestEntropyScanner(unittest.TestCase):
    def test_below_threshold_not_flagged(self):
        scanner = _make_scanner(entropy_threshold=4.5, entropy_min_length=10)
        # Low-entropy string (all same char)
        result = scanner.scan("aaaaaaaaaaaaaaaaaaaaaa", ScanSurface.OUTPUT)
        self.assertEqual(result, [])

    def test_high_entropy_with_trigger_flagged(self):
        scanner = _make_scanner(
            entropy_threshold=3.5,
            entropy_min_length=10,
            entropy_trigger_words=["key"],
            entropy_negation_words=[],
        )
        # Random-ish token after trigger word
        text = "My key is a3f7c9b2e1d04856"
        result = scanner.scan(text, ScanSurface.OUTPUT)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].category, "secret")
        self.assertIsNotNone(result[0].entropy_score)
        self.assertGreater(result[0].entropy_score, 3.0)

    def test_high_entropy_with_negation_no_trigger_suppressed(self):
        scanner = _make_scanner(
            entropy_threshold=3.5,
            entropy_min_length=10,
            entropy_trigger_words=["real"],
            entropy_negation_words=["example"],
        )
        text = "For example: a3f7c9b2e1d04856"
        result = scanner.scan(text, ScanSurface.OUTPUT)
        self.assertEqual(result, [], "Negation without trigger should suppress the match")

    def test_very_high_entropy_no_trigger_still_flagged(self):
        """Entropy >= threshold + 0.5 fires without requiring a trigger word."""
        scanner = _make_scanner(
            entropy_threshold=2.0,
            entropy_min_length=10,
            entropy_trigger_words=["secret"],
            entropy_negation_words=[],
        )
        # Use a genuinely high-entropy string (≫ 2.5 bits/char)
        high_entropy = "aAbBcCdDeEfFgG"  # alternating mixed case: entropy > 3.5
        result = scanner.scan(high_entropy, ScanSurface.OUTPUT)
        self.assertEqual(len(result), 1)

    def test_action_is_block_by_default(self):
        scanner = _make_scanner(
            entropy_threshold=3.0,
            entropy_min_length=10,
            entropy_trigger_words=["key"],
            entropy_negation_words=[],
            entropy_action="block",
        )
        text = "key: a3f7c9b2e1d04856"
        result = scanner.scan(text, ScanSurface.OUTPUT)
        self.assertTrue(any(m.action == DLPAction.BLOCK for m in result))

    def test_entropy_score_populated_on_match(self):
        scanner = _make_scanner(
            entropy_threshold=3.0,
            entropy_min_length=10,
            entropy_trigger_words=["key"],
            entropy_negation_words=[],
        )
        text = "key: a3f7c9b2e1d04856"
        result = scanner.scan(text, ScanSurface.OUTPUT)
        if result:
            self.assertIsNotNone(result[0].entropy_score)
            self.assertIsInstance(result[0].entropy_score, float)

    def test_short_candidate_below_min_length_ignored(self):
        scanner = _make_scanner(entropy_min_length=30, entropy_trigger_words=["key"])
        text = "key: a3f7c9b2"   # only 10 chars
        result = scanner.scan(text, ScanSurface.OUTPUT)
        self.assertEqual(result, [])

    def test_trigger_wins_over_negation(self):
        scanner = _make_scanner(
            entropy_threshold=3.0,
            entropy_min_length=10,
            entropy_trigger_words=["real"],
            entropy_negation_words=["example"],
        )
        text = "real example key a3f7c9b2e1d04856"
        result = scanner.scan(text, ScanSurface.OUTPUT)
        # trigger present → NOT suppressed
        self.assertGreater(len(result), 0)


if __name__ == "__main__":
    unittest.main()
