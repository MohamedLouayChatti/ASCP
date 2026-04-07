"""
Post-processing validators that eliminate false positives from regex matches.

Currently implements:
  - Luhn algorithm (modulo-10 checksum) for credit card number validation

Extensible: add new validators (ISBN-13, IBAN, ISIN, etc.) by implementing
the same filter() contract in MatchValidator.
"""

from .models import DLPMatch
from .config import DLPConfig


def luhn_check(value: str) -> bool:
    """
    Validate a credit card number using the Luhn algorithm (ISO/IEC 7812).

    Extracts only digit characters, rejects anything with fewer than 13 digits,
    and returns True only if the modulo-10 checksum passes.
    """
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) < 13:
        return False

    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:       # every second digit from the right gets doubled
            digit *= 2
            if digit > 9:    # subtract 9 if result > 9 (same as summing digits)
                digit -= 9
        total += digit

    return total % 10 == 0


class MatchValidator:
    """
    Post-processing filter applied after regex matching.

    When enable_luhn_validation=True, any match whose
    pattern_name is "credit_card" that fails the Luhn checksum is silently
    dropped. This eliminates ~90% of false positives from product SKUs,
    tracking numbers, and other numeric sequences.

    All other matches pass through unchanged regardless of configuration.
    """

    def __init__(self, config: DLPConfig):
        self.config = config

    def filter(self, matches: list[DLPMatch]) -> list[DLPMatch]:
        """Return the filtered match list. Only credit_card matches are Luhn-validated."""
        if not self.config.enable_luhn_validation:
            return matches

        result: list[DLPMatch] = []
        for m in matches:
            if m.pattern_name == "credit_card":
                if luhn_check(m.value):
                    result.append(m)
                # Failed Luhn → not a real card number → discard
            else:
                result.append(m)
        return result
