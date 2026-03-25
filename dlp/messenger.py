from typing import List
from .models import DLPResult, ScanSurface

_MESSAGES = {
    "canary": "I cannot share this information.",
    "secret": "I cannot share this information.",
    "pii": "Some personal information was removed from this response.",
    "default": "I cannot complete this request due to a policy constraint.",
}

class SafeMessenger:
    def get_message(self, result: DLPResult) -> str:
        """
        Determines the appropriate safe message without leaking any matched values.
        Different surfaces might yield different formats.
        """
        if result.surface in (ScanSurface.TOOL_ARGS, ScanSurface.TOOL_RESULT):
            # No user-facing text to soften here, just return a structured reason
            if result.canary_hits:
                return "TOOL_BLOCKED_CANARY_VIOLATION"
            if result.secret_matches:
                return "TOOL_BLOCKED_SECRET_VIOLATION"
            if result.pii_matches:
                return "TOOL_BLOCKED_PII_VIOLATION"
            return "TOOL_BLOCKED_POLICY_VIOLATION"

        # OUTPUT surface logic
        if result.canary_hits:
            return _MESSAGES["canary"]
        
        if result.secret_matches:
            return _MESSAGES["secret"]
            
        if result.pii_matches:
            return _MESSAGES["pii"]
            
        return _MESSAGES["default"]
