import os
import sys
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import dlp
from dlp.models import DLPAction, ScanSurface, DLPMatch
from dlp.config import DLPConfig


class TestIntegration(unittest.TestCase):
    def setUp(self):
        # Re-init before each test to guarantee a clean, known state.
        dlp.init(Path("no_such_file.yaml"))

    def test_dlp_canary_ref_injection_and_detection(self):
        # Inject standard docs
        docs = [{"title": "doc1", "text": "This is public info."}]
        injected, token, label = dlp.inject_canaries_into_context(docs)

        self.assertEqual(len(injected), 1)
        self.assertIn("Note: Internal reference [CANARY-", injected[0]["text"])
        self.assertIsNotNone(token)
        self.assertIsNotNone(label)

        # Simulate model echoing it
        bad_model_output = f"Hello the secret is {token}"
        decision = dlp.scan_output(bad_model_output)

        self.assertEqual(decision.action, DLPAction.BLOCK)
        self.assertTrue(decision.should_block)
        self.assertEqual(decision.safe_message, "I cannot share this information.")
        self.assertNotIn(token, decision.safe_message)
        self.assertEqual(decision.clean_text, decision.safe_message)
        self.assertTrue(any("canary_leak" in v for v in decision.violations))
        self.assertFalse(decision.should_escalate)
        self.assertIsNone(decision.escalation_event)

    def test_tool_argument_secret_blocked(self):
        fake_key = "sk-012345678901234567890123456789012345678901234567"
        args = {"body": f"Here is my key: {fake_key}"}

        decision = dlp.scan_tool_args("send_email", args)

        self.assertTrue(decision.should_block)
        self.assertEqual(decision.safe_message, "TOOL_BLOCKED_SECRET_VIOLATION")
        self.assertNotIn("sk-", decision.safe_message)

    def test_tool_result_pii_redacted(self):
        content = """
dlp:
  pii_action: REDACT
  pii_patterns:
    - name: email
      regex: "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\\\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]"
      action: REDACT
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name

        try:
            dlp.init(Path(temp_path))
            tool_result = {"user_info": {"email": "user@email.com", "name": "Test"}}
            decision = dlp.scan_tool_result("get_user", tool_result)

            self.assertEqual(decision.action, DLPAction.REDACT)
            self.assertFalse(decision.should_block)
            self.assertIn("[REDACTED_pii_email]", decision.clean_text)
            self.assertNotIn("user@email.com", decision.clean_text)
        finally:
            os.remove(temp_path)

    def test_block_path_produces_decision(self):
        fake_key = "sk-012345678901234567890123456789012345678901234567"
        args = {"body": f"Here is my key: {fake_key}"}

        decision = dlp.scan_tool_args("test", args)

        self.assertTrue(decision.should_block)
        self.assertFalse(decision.should_escalate)
        self.assertIsNotNone(decision.safe_message)

    def test_scan_without_init_uses_fallback(self):
        """Test that scanning uses safe defaults when init() falls back to non-existent file."""
        decision = dlp.scan_output("test input with email@example.com")

        self.assertIsNotNone(decision)
        self.assertIsNotNone(decision.action)

    def test_reinit_with_different_policy(self):
        """Test that re-initializing with a different policy works correctly."""
        dlp.init(Path("nonexistent1.yaml"))
        decision1 = dlp.scan_output("sk-" + "A" * 48)
        self.assertEqual(decision1.action, DLPAction.BLOCK)

        dlp.init(Path("nonexistent2.yaml"))
        decision2 = dlp.scan_output("sk-" + "B" * 48)
        self.assertEqual(decision2.action, DLPAction.BLOCK)

    def test_multiple_reinits_consistent_state(self):
        """Test that multiple re-initializations maintain consistent state."""
        for i in range(3):
            dlp.init(Path(f"fake_policy_{i}.yaml"))
            token = dlp.inject_canaries_into_context([{"text": "test"}])[1]
            self.assertIsNotNone(token)

    def test_scan_tool_result_with_nested_dict(self):
        """Test scan_tool_result with deeply nested dictionary structures."""
        nested_result = {
            "level1": {
                "level2": {
                    "level3": {
                        "email": "user@example.com",
                        "secret": "sk-" + "C" * 48
                    }
                }
            }
        }

        decision = dlp.scan_tool_result("nested_tool", nested_result)

        self.assertTrue(decision.should_block)
        self.assertEqual(decision.action, DLPAction.BLOCK)

    def test_scan_tool_result_with_list_of_dicts(self):
        """Test scan_tool_result with list structures."""
        content = """
dlp:
  pii_action: REDACT
  pii_patterns:
    - name: email
      regex: "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\\\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]"
      action: REDACT
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name

        try:
            dlp.init(Path(temp_path))
            result_with_list = {
                "records": [
                    {"email": "user1@test.com", "name": "User 1"},
                    {"email": "user2@test.com", "name": "User 2"}
                ]
            }

            decision = dlp.scan_tool_result("list_tool", result_with_list)

            self.assertEqual(decision.action, DLPAction.REDACT)
            self.assertFalse(decision.should_block)
            count = decision.clean_text.count("[REDACTED")
            self.assertGreaterEqual(count, 2)
        finally:
            os.remove(temp_path)

    def test_all_three_surfaces_with_different_violations(self):
        """Test that all three surfaces properly handle violations."""
        fake_key = "sk-" + "D" * 48
        fake_email = "test@example.com"

        output_decision = dlp.scan_output(f"Key: {fake_key}")
        self.assertEqual(output_decision.action, DLPAction.BLOCK)
        self.assertEqual(output_decision.dlp_result.surface, ScanSurface.OUTPUT)

        args_decision = dlp.scan_tool_args("test", {"arg": fake_key})
        self.assertEqual(args_decision.action, DLPAction.BLOCK)
        self.assertEqual(args_decision.dlp_result.surface, ScanSurface.TOOL_ARGS)

        result_decision = dlp.scan_tool_result("test", {"result": fake_email})
        self.assertEqual(result_decision.action, DLPAction.REDACT)
        self.assertEqual(result_decision.dlp_result.surface, ScanSurface.TOOL_RESULT)

    def test_escalation_decision_with_dlp_result_populated(self):
        """Test that escalation decision includes dlp_result for telemetry."""
        content = """
dlp:
  canary_action: BLOCK
  canary_salt: "salt"
  secrets_action: PASS_TO_ML
  pii_action: REDACT
  enable_ner: false
  secret_patterns:
    - name: test_secret
      regex: "secret_[0-9]+"
  pii_patterns:
    - name: test_pii
      regex: "pii_[0-9]+"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name

        try:
            dlp.init(Path(temp_path))

            decision = dlp.scan_output("Found secret_1234567890123456")

            self.assertEqual(decision.action, DLPAction.ESCALATE)
            self.assertTrue(decision.should_escalate)
            self.assertIsNotNone(decision.dlp_result)
            self.assertGreater(len(decision.dlp_result.secret_matches), 0)
            self.assertIn("secret_1234567890123456", decision.dlp_result.secret_matches[0].value)
            self.assertIsNotNone(decision.escalation_event)
        finally:
            os.remove(temp_path)

    def test_safe_redaction_preserves_text_integrity(self):
        """Test that redaction maintains text integrity and position correctness."""
        content = """
dlp:
  pii_action: REDACT
  pii_patterns:
    - name: email
      regex: "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\\\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]"
      action: REDACT
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name

        try:
            dlp.init(Path(temp_path))
            text = "Contact us at user@domain.com or admin@company.com"
            decision = dlp.scan_output(text)

            self.assertEqual(decision.action, DLPAction.REDACT)
            redacted = decision.clean_text

            self.assertIn("Contact us at", redacted)
            self.assertIn("or", redacted)
            self.assertNotIn("user@domain.com", redacted)
            self.assertNotIn("admin@company.com", redacted)
        finally:
            os.remove(temp_path)

    def test_multiple_scans_per_session(self):
        """Test that multiple consecutive scans work correctly with canary state."""
        docs, token, label = dlp.inject_canaries_into_context([{"text": "doc"}])

        decision1 = dlp.scan_output("I will not leak the token")
        self.assertEqual(decision1.action, DLPAction.ALLOW)

        decision2 = dlp.scan_output(f"Actually here is: {token}")
        self.assertEqual(decision2.action, DLPAction.BLOCK)
        self.assertTrue(decision2.should_block)

        decision3 = dlp.scan_output("Just regular text now")
        self.assertEqual(decision3.action, DLPAction.ALLOW)

    def test_tool_args_secret_always_blocks(self):
        """
        Secrets in TOOL_ARGS must always block, even when the global
        secrets_action policy is set to ALLOW.

        This verifies two things:
        1. DLPConfig.defaults() encodes the tool_args.secrets_action=block override
           so that protective behaviour is present out-of-the-box.
        2. The enforcer correctly applies the override when a YAML policy sets
           secrets_action to ALLOW at the global level.
        """
        # --- Part 1: assert the override is present in built-in defaults ---
        defaults = DLPConfig.defaults()
        self.assertIn(
            "tool_args",
            defaults.surface_overrides,
            "DLPConfig.defaults() must include a 'tool_args' surface override.",
        )
        self.assertEqual(
            defaults.surface_overrides["tool_args"].get("secrets_action", "").lower(),
            "block",
            "DLPConfig.defaults() must set tool_args.secrets_action = 'block'.",
        )

        # --- Part 2: behavioural test — ALLOW policy + tool_args override = BLOCK ---
        content = """
dlp:
  canary_action: ALLOW
  canary_salt: "salt"
  secrets_action: ALLOW
  pii_action: ALLOW
  enable_ner: false
  secret_patterns:
    - name: api_key
      regex: "sk-[A-Za-z0-9]{48}"
  pii_patterns:
    - name: email
      regex: "[a-z]+@[a-z]+\\\\.[a-z]+"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name

        try:
            dlp.init(Path(temp_path))

            fake_key = "sk-" + "E" * 48
            decision = dlp.scan_tool_args("api_call", {"token": fake_key})

            # Surface override must force BLOCK despite global ALLOW policy.
            self.assertTrue(
                decision.should_block,
                "scan_tool_args() must block secrets even when secrets_action=ALLOW globally.",
            )
            self.assertEqual(decision.action, DLPAction.BLOCK)
            self.assertEqual(decision.dlp_result.surface, ScanSurface.TOOL_ARGS)
        finally:
            os.remove(temp_path)

    def test_violations_list_properly_populated(self):
        """Test that violations list is properly populated with violation types."""
        fake_key = "sk-" + "F" * 48
        decision = dlp.scan_output(f"Secret: {fake_key}")

        self.assertGreater(len(decision.violations), 0)
        self.assertTrue(any("secret" in v.lower() for v in decision.violations))

    def test_action_prevents_information_leakage_in_decision(self):
        """Test that safe_message and clean_text never leak actual matched values."""
        sensitive_values = [
            "sk-" + "G" * 48,
            "aws_key=AKIA" + "H" * 16,
            "ghp_" + "I" * 36,
            "sensitive@company.com"
        ]

        for value in sensitive_values:
            decision = dlp.scan_output(f"Found: {value}")

            if decision.action == DLPAction.REDACT:
                self.assertNotIn(value, decision.clean_text)

            if decision.action in [DLPAction.BLOCK, DLPAction.ESCALATE]:
                if decision.safe_message is not None:
                    self.assertNotIn(value, decision.safe_message)

    def test_surface_overrides_configurable_via_yaml(self):
        """
        surface_overrides must be fully driven by YAML. Verify that a custom
        policy can add a pii_action override on the output surface.
        """
        content = """
dlp:
  canary_action: BLOCK
  canary_salt: "test_salt"
  secrets_action: BLOCK
  pii_action: ESCALATE
  enable_ner: false
  secret_patterns: []
  pii_patterns:
    - name: email
      regex: "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\\\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]"
  surface_overrides:
    output:
      pii_action: redact
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name

        try:
            dlp.init(Path(temp_path))

            # Global pii_action is ESCALATE, but the output surface override says REDACT.
            # Because overrides only escalate (max), and REDACT < ESCALATE, the
            # override here acts as a floor.  Let's confirm the config is parsed.
            from dlp.config import _parse_action, DLPAction as A
            import dlp as _dlp
            overrides = _dlp._scanner.config.surface_overrides
            self.assertIn("output", overrides)
            self.assertEqual(overrides["output"].get("pii_action", "").lower(), "redact")
        finally:
            os.remove(temp_path)

    def test_downgrade_escalate_to_redact_configurable(self):
        """
        downgrade_escalate_to_redact on tool_result must be configurable via YAML.
        When set to false, a pure-PII escalation on TOOL_RESULT must NOT be downgraded.
        """
        content = """
dlp:
  canary_action: BLOCK
  canary_salt: "test_salt"
  secrets_action: BLOCK
  pii_action: ESCALATE
  enable_ner: false
  secret_patterns: []
  pii_patterns:
    - name: email
      regex: "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\\\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]"
  surface_overrides:
    tool_result:
      downgrade_escalate_to_redact: "false"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name

        try:
            dlp.init(Path(temp_path))

            # PII on TOOL_RESULT with pii_action=ESCALATE and downgrade disabled
            # → must remain ESCALATE, not be downgraded to REDACT
            decision = dlp.scan_tool_result("query", {"email": "user@example.com"})
            self.assertEqual(decision.action, DLPAction.ESCALATE)
            self.assertTrue(decision.should_escalate)
        finally:
            os.remove(temp_path)


