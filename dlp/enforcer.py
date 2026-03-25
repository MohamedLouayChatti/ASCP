from typing import List, Dict, Any, Optional

from .models import DLPResult, DLPAction, ScanSurface, EnforcementDecision
from .messenger import SafeMessenger

class PolicyEnforcer:
    def __init__(self):
        self.messenger = SafeMessenger()

    def enforce(self, result: DLPResult) -> EnforcementDecision:
        """
        Takes the raw scanner result and applies per-surface policy overrides.
        Generates final decision and safe messages if necessary.
        """
        final_action = result.action
        
        # Example per-surface overrides
        if result.surface == ScanSurface.TOOL_ARGS:
            # On tool arguments, any secret match escalates/blocks regardless of global action
            if result.secret_matches:
                final_action = max(final_action, DLPAction.BLOCK)
        
        if result.surface == ScanSurface.TOOL_RESULT:
            # On tool results, we might only want to redact PII, even if policy says Escalate
            if final_action == DLPAction.ESCALATE and not result.canary_hits and not result.secret_matches:
                final_action = DLPAction.REDACT

        should_block = (final_action == DLPAction.BLOCK)
        should_escalate = (final_action >= DLPAction.ESCALATE) # BLOCK also escalates implicitly or optionally

        # Safe messaging
        safe_message = None
        clean_text = result.clean_text
        
        if should_block:
            # Replaces clean_text entirely with the safe message or just sets safe_message
            safe_message = self.messenger.get_message(result)
            clean_text = safe_message
        
        escalation_event = None
        if should_escalate:
            escalation_event = {
                "surface": result.surface.value,
                "violations": result.violations,
                "action_taken": final_action.name,
                "requires_review": True
            }

        return EnforcementDecision(
            action=final_action,
            clean_text=clean_text,
            violations=result.violations,
            should_block=should_block,
            should_escalate=should_escalate,
            safe_message=safe_message,
            escalation_event=escalation_event
        )
