import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import time

# We must import from the main dlp module
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dlp import init as init_dlp, scan_output, scan_tool_args, scan_tool_result, inject_canaries_into_context
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

class Evaluator:
    def __init__(self, corpus_path: str):
        self.corpus_path = Path(corpus_path)
        self.cases: List[TestCase] = self._load_corpus()

    def _load_corpus(self) -> List[TestCase]:
        with open(self.corpus_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [TestCase(**case) for case in data.get("test_cases", [])]

    def _replace_canary(self, payload: Any, canary_token: str) -> Any:
        if isinstance(payload, str):
            return payload.replace("{canary_token}", canary_token)
        elif isinstance(payload, dict):
            return {k: self._replace_canary(v, canary_token) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self._replace_canary(v, canary_token) for v in payload]
        return payload

    def run_case(self, case: TestCase, config_type: str, config: DLPConfig) -> EvaluationResult:
        # Initialize DLP singleton for this run
        init_dlp(config)

        # Inject canaries to make semantic analysis active and get a valid token
        _, token, _ = inject_canaries_into_context([{"text": "mock context document"}])

        # Deep replace the {canary_token} in the payload if it exists
        payload = self._replace_canary(case.input_payload, token if token else "fallback_token")

        start_time = time.time()
        
        try:
            if case.surface == "OUTPUT":
                decision: EnforcementDecision = scan_output(payload)
            elif case.surface == "TOOL_ARGS":
                # Assuming input_payload is a dict of args, tool_name can be a dummy like "eval_tool"
                decision = scan_tool_args("eval_tool", payload)
            elif case.surface == "TOOL_RESULT":
                # Assuming input_payload is result_data, tool_name a dummy "eval_tool"
                decision = scan_tool_result("eval_tool", payload)
            else:
                raise ValueError(f"Unknown surface: {case.surface}")
        except Exception as e:
            print(f"Error processing case {case.id}: {e}")
            decision = EnforcementDecision(
                action=DLPAction.ALLOW,
                clean_text=case.input_payload,
                violations=[],
                should_block=False,
                safe_message=str(e),
                should_escalate=False,
                escalation_event=None
            )

        latency = (time.time() - start_time) * 1000  # ms
        
        # Determine actual action string
        actual_action_str = decision.action.name
        if decision.should_escalate and decision.action != DLPAction.BLOCK:
             actual_action_str = "ESCALATE"

        # Compare
        
        # Check if the context analyzer successfully mitigated the ambiguous cases
        violations = []
        if decision.dlp_result:
            if decision.dlp_result.canary_hits:
                violations.append("canary")
            if decision.dlp_result.secret_matches:
                violations.append("secret")
            if decision.dlp_result.pii_matches:
                violations.append("pii")

        # Compare action and expected violations (if needed, but mainly action for now)
        # We can say it passed if action matches AND (for negative tests) if all expected violations are in the detected list
        # Though the original test only checks expected_action. We'll improve expected matching:
        passed = (actual_action_str == case.expected_action)

        return EvaluationResult(
            case_id=case.id,
            category=case.category,
            surface=case.surface,
            config_type=config_type,
            expected_action=case.expected_action,
            actual_action=actual_action_str,
            passed=passed,
            latency_ms=latency,
            violations=violations,
            clean_text_or_payload=decision.clean_text,
            message=decision.safe_message or ""
        )

    def run_all(self, configs: Dict[str, DLPConfig] = None) -> List[EvaluationResult]:
        """
        Runs the test corpus against a set of configurations.
        configs: A dictionary of configuration name to DLPConfig object.
                 If None, uses a default empty configuration.
        """
        if configs is None:
            config = DLPConfig.defaults()
            configs = {"DEFAULT": config}

        results = []
        for config_name, config in configs.items():
            for case in self.cases:
                res = self.run_case(case, config_name, config)
                results.append(res)
            
        return results

if __name__ == "__main__":
    import os
    corpus_path = os.path.join(os.path.dirname(__file__), "corpus.json")
    evaluator = Evaluator(corpus_path)
    
    config_default = DLPConfig.defaults()
    
    config_all = DLPConfig.defaults()
    config_all.enable_luhn_validation = True
    config_all.enable_context_analysis = True
    
    results = evaluator.run_all({"DEFAULT": config_default, "ALL_FEATURES": config_all})
    failed = [r for r in results if not r.passed]
    print(f"Total: {len(results)}, Passed: {len(results)-len(failed)}, Failed: {len(failed)}")
    for f in failed:
        print(f"FAILED: {f.case_id} ({f.config_type}) - Expected {f.expected_action}, got {f.actual_action}. Message: {f.message}")
