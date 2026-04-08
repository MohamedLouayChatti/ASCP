"""
DLP Evaluation Runner
=====================

Runs the test corpus against one or more DLPConfig configurations and reports
pass/fail per test case.

Canary handling
---------------
Test cases that contain the ``{canary_token}`` placeholder are automatically
handled: the runner injects a canary via the appropriate surface method, then
substitutes the live token into the payload before scanning.

  • canary-output-*      → inject_canary_into_system_prompt  → scan_output
  • canary-tool_args-*   → inject_canary_into_system_prompt  → scan_tool_args
  • (tool_result canary cases would use inject_canary_into_tool_result,
    but since we scan the result before the agent sees it — and we injected it
    ourselves — those are integration-level tests, not corpus tests.)
"""

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import dlp
from dlp import (
    init as init_dlp,
    scan_output,
    scan_tool_args,
    scan_tool_result,
    inject_canary_into_system_prompt,
    inject_canaries_into_context,
    inject_canary_into_tool_result,
)
from dlp.config import DLPConfig
from dlp.models import DLPAction, EnforcementDecision


@dataclass
class TestCase:
    id: str
    category: str
    surface: str
    input_payload: Any
    expected_action: str
    expected_violations: List[str]
    notes: str = ""
    requires_no_features: bool = False


@dataclass
class EvaluationResult:
    case_id: str
    category: str
    surface: str
    config_type: str
    expected_action: str
    actual_action: str
    passed: bool
    latency_ms: float
    violations: List[str]
    clean_text_or_payload: Any
    message: str


def _has_canary_placeholder(payload: Any) -> bool:
    """Return True if the payload contains the {canary_token} placeholder."""
    if isinstance(payload, str):
        return "{canary_token}" in payload
    if isinstance(payload, dict):
        return any(_has_canary_placeholder(v) for v in payload.values())
    if isinstance(payload, list):
        return any(_has_canary_placeholder(v) for v in payload)
    return False


def _substitute_canary(payload: Any, token: str) -> Any:
    """Deep-replace every {canary_token} occurrence with the live token."""
    if isinstance(payload, str):
        return payload.replace("{canary_token}", token)
    if isinstance(payload, dict):
        return {k: _substitute_canary(v, token) for k, v in payload.items()}
    if isinstance(payload, list):
        return [_substitute_canary(v, token) for v in payload]
    return payload


class Evaluator:
    def __init__(self, corpus_path: str):
        self.corpus_path = Path(corpus_path)
        self.cases: List[TestCase] = self._load_corpus()

    def _load_corpus(self) -> List[TestCase]:
        with open(self.corpus_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cases = []
        for raw in data.get("test_cases", []):
            cases.append(
                TestCase(
                    id=raw["id"],
                    category=raw["category"],
                    surface=raw["surface"],
                    input_payload=raw["input_payload"],
                    expected_action=raw["expected_action"],
                    expected_violations=raw.get("expected_violations", []),
                    notes=raw.get("notes", ""),
                    requires_no_features=raw.get("requires_no_features", False),
                )
            )
        return cases

    def _get_canary_token(self) -> str:
        """
        Inject a canary into a dummy system prompt and return the token.
        This is the correct way to obtain a valid token — it goes through the
        same code path the real application uses.
        """
        _, token, _ = inject_canary_into_system_prompt("Dummy system prompt for evaluation.")
        return token or "fallback_no_token"

    def run_case(
        self, case: TestCase, config_type: str, config: DLPConfig
    ) -> EvaluationResult:
        # Re-initialise DLP singleton for this config
        init_dlp(config)

        # ── Canary substitution ────────────────────────────────────────────────
        # If the payload references {canary_token}, we must obtain a live token
        # from the canary engine (post-init) and substitute it in.
        needs_canary = _has_canary_placeholder(case.input_payload)
        if needs_canary:
            live_token = self._get_canary_token()
            payload = _substitute_canary(case.input_payload, live_token)
        else:
            payload = case.input_payload

        # ── Execute scan ───────────────────────────────────────────────────────
        start_time = time.time()
        try:
            if case.surface == "OUTPUT":
                decision: EnforcementDecision = scan_output(payload)
            elif case.surface == "TOOL_ARGS":
                decision = scan_tool_args("eval_tool", payload)
            elif case.surface == "TOOL_RESULT":
                decision = scan_tool_result("eval_tool", payload)
            else:
                raise ValueError(f"Unknown surface: {case.surface}")
        except Exception as exc:
            decision = EnforcementDecision(
                action=DLPAction.ALLOW,
                clean_text=str(case.input_payload),
                violations=[],
                should_block=False,
                should_escalate=False,
                safe_message=str(exc),
                escalation_event=None,
            )

        latency_ms = (time.time() - start_time) * 1000

        # ── Resolve actual action string ───────────────────────────────────────
        actual_action_str = decision.action.name
        if decision.should_escalate and decision.action != DLPAction.BLOCK:
            actual_action_str = "ESCALATE"

        # ── Collect detected violation categories ──────────────────────────────
        violations: List[str] = []
        if decision.dlp_result:
            if decision.dlp_result.canary_hits:
                violations.append("canary")
            if decision.dlp_result.secret_matches:
                violations.append("secret")
            if decision.dlp_result.pii_matches:
                violations.append("pii")

        passed = actual_action_str == case.expected_action

        return EvaluationResult(
            case_id=case.id,
            category=case.category,
            surface=case.surface,
            config_type=config_type,
            expected_action=case.expected_action,
            actual_action=actual_action_str,
            passed=passed,
            latency_ms=latency_ms,
            violations=violations,
            clean_text_or_payload=decision.clean_text,
            message=decision.safe_message or "",
        )

    def run_all(
        self, configs: Optional[Dict[str, DLPConfig]] = None
    ) -> List[EvaluationResult]:
        """
        Run the full corpus against each configuration.

        Parameters
        ----------
        configs : dict mapping config_name → DLPConfig, or None (uses defaults).
        """
        if configs is None:
            configs = {"DEFAULT": DLPConfig.defaults()}

        results: List[EvaluationResult] = []
        for config_name, config in configs.items():
            has_features = (
                getattr(config, "enable_luhn_validation", False)
                or getattr(config, "enable_context_analysis", False)
            )
            for case in self.cases:
                # Skip cases that are only valid when features are OFF
                if case.requires_no_features and has_features:
                    continue
                res = self.run_case(case, config_name, config)
                results.append(res)
        return results


# ── CLI entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os

    corpus_path = os.path.join(os.path.dirname(__file__), "corpus.json")
    evaluator = Evaluator(corpus_path)

    config_default = DLPConfig.defaults()

    config_all = DLPConfig.defaults()
    config_all.enable_luhn_validation = True
    config_all.enable_context_analysis = True

    results = evaluator.run_all(
        {"DEFAULT": config_default, "ALL_FEATURES": config_all}
    )

    total = len(results)
    failed_results = [r for r in results if not r.passed]
    passed_count = total - len(failed_results)

    print(f"\n{'='*60}")
    print(f"DLP Evaluation  |  Total: {total}  Passed: {passed_count}  Failed: {len(failed_results)}")
    print(f"{'='*60}")

    if failed_results:
        print("\nFailed cases:")
        for r in failed_results:
            print(
                f"  FAIL  {r.case_id:<45} [{r.config_type}]  "
                f"expected={r.expected_action}  got={r.actual_action}  "
                f"violations={r.violations}"
            )
    else:
        print("\nAll cases passed!")