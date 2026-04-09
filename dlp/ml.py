from typing import Any
from .models import ScanSurface, DLPAction

def classify(text: str, surface: ScanSurface, features: dict[str, Any]) -> tuple[DLPAction, float]:
    """
    ML Classifier placeholder.
    Currently always falls back to ALLOW, 0.5  (default)
    This will trigger ESCALATE due to threshold < 0.6
    """
    # Later to be implemented completely via external or internal ML models.
    return DLPAction.ALLOW, 1.0