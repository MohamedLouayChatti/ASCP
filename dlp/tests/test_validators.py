"""Tests for Luhn algorithm and MatchValidator (dlp/validators.py)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.config import DLPConfig
from dlp.validators import luhn_check, MatchValidator
from dlp.models import DLPMatch, ScanSurface, DLPAction


def _match(pattern_name: str, value: str) -> DLPMatch:
    return DLPMatch(
        pattern_name=pattern_name, category="pii",
        action=DLPAction.REDACT, value=value,
        spans=[(0, len(value))], surface=ScanSurface.OUTPUT,
    )


class TestLuhnCheck(unittest.TestCase):
    """Unit tests for the raw luhn_check() function."""

    def test_valid_visa(self):
        self.assertTrue(luhn_check("4111111111111111"))

    def test_valid_mastercard(self):
        self.assertTrue(luhn_check("5500005555555559"))

    def test_valid_amex(self):
        self.assertTrue(luhn_check("378282246310005"))

    def test_invalid_card_fails(self):
        self.assertFalse(luhn_check("4111111111111112"))

    def test_sequential_digits_fails(self):
        self.assertFalse(luhn_check("1234567890123456"))

    def test_too_short_rejected(self):
        self.assertFalse(luhn_check("123456789012"))   # 12 digits < 13

    def test_non_digits_stripped(self):
        # Hyphens and spaces should be ignored
        self.assertTrue(luhn_check("4111-1111-1111-1111"))

    def test_empty_string_rejected(self):
        self.assertFalse(luhn_check(""))

    def test_product_sku_fails(self):
        # A product SKU that looks card-shaped but isn't valid
        self.assertFalse(luhn_check("1234567890123456"))


class TestMatchValidator(unittest.TestCase):
    def _make_validator(self, enabled: bool = True) -> MatchValidator:
        cfg = DLPConfig.defaults()
        cfg.enable_luhn_validation = enabled
        return MatchValidator(cfg)

    def test_valid_credit_card_kept(self):
        validator = self._make_validator()
        m = _match("credit_card", "4111111111111111")
        result = validator.filter([m])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].value, "4111111111111111")

    def test_invalid_credit_card_dropped(self):
        validator = self._make_validator()
        m = _match("credit_card", "4111111111111112")
        result = validator.filter([m])
        self.assertEqual(result, [])

    def test_non_cc_match_always_passes(self):
        validator = self._make_validator()
        m = _match("email", "user@example.com")
        result = validator.filter([m])
        self.assertEqual(len(result), 1)

    def test_luhn_disabled_keeps_invalid_card(self):
        validator = self._make_validator(enabled=False)
        m = _match("credit_card", "4111111111111112")   # fails Luhn
        result = validator.filter([m])
        self.assertEqual(len(result), 1, "Luhn disabled → invalid card should pass through")

    def test_mixed_matches_filtered_correctly(self):
        validator = self._make_validator()
        matches = [
            _match("credit_card", "4111111111111111"),  # valid
            _match("credit_card", "4111111111111112"),  # invalid
            _match("email", "user@example.com"),        # not CC
        ]
        result = validator.filter(matches)
        self.assertEqual(len(result), 2)
        values = [m.value for m in result]
        self.assertIn("4111111111111111", values)
        self.assertIn("user@example.com", values)
        self.assertNotIn("4111111111111112", values)


if __name__ == "__main__":
    unittest.main()
