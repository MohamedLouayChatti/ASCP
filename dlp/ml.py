from typing import Any
from .models import ScanSurface, DLPAction

def classify(text: str, surface: ScanSurface, features: dict[str, Any]) -> tuple[DLPAction, float]:
    """
    ML Classifier placeholder.
    If no suspicious features are found, returns ALLOW with 1.0 confidence.
    Otherwise, returns ALLOW with 0.5 confidence to trigger ESCALATE.
    """
    if features.get("num_secrets_detected", 0) == 0 and \
       not features.get("has_api_key_pattern") and \
       not features.get("has_db_connection") and \
       not features.get("has_private_key") and \
       features.get("num_emails", 0) == 0 and \
       features.get("num_phones", 0) == 0 and \
       features.get("num_credit_cards", 0) == 0:
        return DLPAction.ALLOW, 1.0
        
    return DLPAction.ESCALATE, 0.5