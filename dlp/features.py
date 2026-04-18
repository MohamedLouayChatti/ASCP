import re
import math
from typing import Any
from collections import Counter
from .models import ScanSurface


def calc_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_features(text: str, surface: ScanSurface) -> dict[str, Any]:
    """
    Extract permissive features for the ML Classifier.
    """
    
    # Simple counting (very permissive regexes)
    num_emails = len(re.findall(r"@[\w-]+\.\w+", text))
    num_phones = len(re.findall(r"\d{3}[-.\s]\d{3}[-.\s]\d{4}", text))
    num_credit_cards = len(re.findall(r"\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}", text))
    
    # Generic entropy check via tokens
    tokens = re.findall(r"\b\w{16,}\b", text)
    entropies = [calc_entropy(t) for t in tokens]
    max_entropy = max(entropies) if entropies else 0.0
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    
    # Bools based on permissive regexes
    has_api_key_pattern = bool(re.search(r"(api[_-]?key|token|secret)[\s=:]*['\&quot;]?\w{10,}", text, flags=re.IGNORECASE))
    has_db_connection = bool(re.search(r"(postgres|mysql|mongodb|redis):\/\/", text, flags=re.IGNORECASE))
    has_private_key = bool(re.search(r"-----BEGIN .* PRIVATE KEY-----", text))

    # Basic context detection
    is_example_context = bool(re.search(r"\b(example|dummy|sample|placeholder|mock|test)\b", text, flags=re.IGNORECASE))
    is_code_context = bool(re.search(r"\b(def|class|function|import|export|if|while|for)\b[\s:\{]", text))

    # Count of matches from high-signal patterns — used as an ML feature.
    # We sum the concrete hit counts already computed above; this is a true
    # measure of "how many things look like secrets/PII" rather than a noisy
    # proxy based on token length.
    num_secrets_detected = (
        num_emails
        + num_phones
        + num_credit_cards
        + int(has_api_key_pattern)
        + int(has_db_connection)
        + int(has_private_key)
    )

    return {
        "num_emails": num_emails,
        "num_phones": num_phones,
        "num_credit_cards": num_credit_cards,
        "num_secrets_detected": num_secrets_detected,
        "has_valid_credit_card": False, # Gets populated conceptually, kept for schema match
        "has_api_key_pattern": has_api_key_pattern,
        "has_db_connection": has_db_connection,
        "has_private_key": has_private_key,
        "is_example_context": is_example_context,
        "is_code_context": is_code_context,
        "max_entropy": max_entropy,
        "avg_entropy": avg_entropy,
        "surface": surface.value
    }