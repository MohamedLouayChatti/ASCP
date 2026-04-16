from .config import DLPConfig, _parse_action
from .models import DLPResult, DLPAction, ScanSurface, EnforcementDecision
from .messenger import SafeMessenger


class PolicyEnforcer:
    def __init__(self, config: DLPConfig):
        self.config = config
        self.messenger = SafeMessenger()

    def enforce(self, result: DLPResult) -> EnforcementDecision:
        """
        Takes the raw scanner result and applies per-surface policy overrides
        loaded from DLPConfig.surface_overrides. All enforcement decisions are
        driven by YAML configuration — there is no hardcoded business logic here.

        surface_overrides is keyed by the surface name in lower-snake-case
        ("output", "tool_args", "tool_result"). Supported per-surface keys:

          secrets_action                 – override action when secrets are found
          pii_action                     – override action when PII is found
          canary_action                  – override action when canary hits are found
          downgrade_escalate_to_redact   – "true" | "false":
              When true, a final ESCALATE action is downgraded to REDACT if
              the only violations are PII  (no canary hits, no secret matches).
              This allows tool results with PII-only violations to be sanitised
              rather than sent for human review.
        """
        final_action = result.action

        # Resolve the surface key used in the config ("tool_args", "tool_result", etc.)
        surface_key = result.surface.value.lower()
        surface_cfg = self.config.surface_overrides.get(surface_key, {})

        # Apply per-category action overrides for this surface.
        # We take the max (most severe) of the current action and the override,
        # so overrides can only escalate — never silently downgrade a BLOCK.
        if result.secret_matches:
            override = surface_cfg.get("secrets_action")
            if override:
                final_action = max(final_action, _parse_action(override))

        if result.pii_matches:
            override = surface_cfg.get("pii_action")
            if override:
                final_action = max(final_action, _parse_action(override))

        if result.canary_hits:
            override = surface_cfg.get("canary_action")
            if override:
                final_action = max(final_action, _parse_action(override))

        # Conditional downgrade: if configured for this surface, downgrade
        # ESCALATE → REDACT when the only violations are PII (no canary, no secret).
        # This preserves the ability to sanitise content while bypassing a heavy
        # review queue for low-severity, PII-only findings.
        downgrade = surface_cfg.get("downgrade_escalate_to_redact", "false").lower() == "true"
        if (
            downgrade
            and final_action == DLPAction.ESCALATE
            and not result.canary_hits
            and not result.secret_matches
        ):
            final_action = DLPAction.REDACT

        should_block = (final_action == DLPAction.BLOCK)
        should_escalate = (final_action == DLPAction.ESCALATE)

        # Safe messaging
        safe_message = None
        clean_text = result.clean_text

        if should_block:
            safe_message = self.messenger.get_message(result)
            clean_text = safe_message

        escalation_event = None
        if should_escalate:
            escalation_event = {
                "surface": result.surface.value,
                "violations": result.violations,
                "action_taken": final_action.name,
                "requires_review": True,
            }

        decision_layer = getattr(result, "decision_layer", "unknown")
        decision_reason = getattr(result, "decision_reason", "unknown")

        if result.action != final_action:
            decision_layer = "policy"
            
            reasons = []
            if result.secret_matches and surface_cfg.get("secrets_action"):
                reasons.append(f"secrets_action={surface_cfg['secrets_action']}")
            if result.pii_matches and surface_cfg.get("pii_action"):
                reasons.append(f"pii_action={surface_cfg['pii_action']}")
            if result.canary_hits and surface_cfg.get("canary_action"):
                reasons.append(f"canary_action={surface_cfg['canary_action']}")
            downgrade_val = surface_cfg.get("downgrade_escalate_to_redact", "false").lower() == "true"
            if downgrade_val and final_action == DLPAction.REDACT and result.action == DLPAction.ESCALATE:
                reasons.append("downgrade_escalate_to_redact")
                
            decision_reason = f"Policy override ({', '.join(reasons)}): {result.action.name}->{final_action.name}"

        return EnforcementDecision(
            action=final_action,
            clean_text=clean_text,
            violations=result.violations,
            should_block=should_block,
            should_escalate=should_escalate,
            safe_message=safe_message,
            escalation_event=escalation_event,
            dlp_result=result,
            decision_layer=decision_layer,
            decision_reason=decision_reason,
        )
