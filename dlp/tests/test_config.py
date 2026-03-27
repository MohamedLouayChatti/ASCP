import unittest
import tempfile
import os
import sys
import logging
from pathlib import Path
from unittest.mock import patch, mock_open

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.config import load_dlp_config, DLPConfig, _parse_action
from dlp.models import DLPAction

class TestConfig(unittest.TestCase):
    def test_load_valid_config(self):
        content = """
dlp:
  canary_action: BLOCK
  canary_salt: "my_salt"
  secrets_action: ESCALATE
  pii_action: ALLOW
  enable_ner: true
  canary_labels:
    - custom_label_1
    - custom_label_2
  secret_patterns:
    - name: test_secret
      regex: "secret[0-9]+"
  pii_patterns:
    - name: test_pii
      regex: "pii[0-9]+"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
            
        try:
            config = load_dlp_config(Path(temp_path))
            self.assertEqual(config.canary_salt, "my_salt")
            self.assertEqual(config.enable_ner, True)
            self.assertEqual(len(config.secret_patterns), 1)
            self.assertEqual(config.secret_patterns[0].name, "test_secret")
            self.assertEqual(len(config.pii_patterns), 1)
            self.assertEqual(config.canary_labels, ["custom_label_1", "custom_label_2"])
        finally:
            os.remove(temp_path)

    def test_load_empty_patterns(self):
        content = """
dlp:
  enable_ner: true
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
            
        try:
            with self.assertLogs(level=logging.CRITICAL) as cm:
                config = load_dlp_config(Path(temp_path))
                self.assertTrue(any("Both secret_patterns and pii_patterns are empty" in log for log in cm.output))
        finally:
            os.remove(temp_path)


class TestConfigErrorPaths(unittest.TestCase):
    """Test configuration loading error handling and edge cases."""

    def test_load_nonexistent_file_returns_defaults(self):
        """Test that nonexistent file path falls back to defaults."""
        nonexistent = Path("/this/path/does/not/exist/policy.yaml")
        config = load_dlp_config(nonexistent)
        
        # Should return defaults
        self.assertEqual(config.canary_action, DLPAction.BLOCK)
        self.assertEqual(config.secrets_action, DLPAction.BLOCK)
        self.assertEqual(config.pii_action, DLPAction.REDACT)
        self.assertEqual(len(config.secret_patterns), 3)
        self.assertEqual(len(config.pii_patterns), 3)  # email, ipv4, credit_card

    def test_load_invalid_yaml_syntax_returns_defaults(self):
        """Test that invalid YAML syntax gracefully falls back to defaults."""
        content = """
dlp:
  this is not valid yaml: [unclosed bracket
  invalid structure!
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
        
        try:
            # Should not raise, should return defaults
            with self.assertLogs(level=logging.CRITICAL) as cm:
                config = load_dlp_config(Path(temp_path))
                self.assertIsNotNone(config)
                self.assertEqual(config.canary_action, DLPAction.BLOCK)
                self.assertTrue(any("Failed to parse YAML" in log for log in cm.output))
        finally:
            os.remove(temp_path)

    def test_load_missing_dlp_section_returns_defaults(self):
        """Test that YAML without 'dlp' section returns defaults."""
        content = """
other_config:
  some_value: 123
  patterns:
    - name: not_dlp
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
        
        try:
            config = load_dlp_config(Path(temp_path))
            # Should return defaults when dlp section is missing
            self.assertEqual(config.canary_action, DLPAction.BLOCK)
            self.assertEqual(len(config.secret_patterns), 3)
        finally:
            os.remove(temp_path)

    def test_load_empty_yaml_file_returns_defaults(self):
        """Test that empty YAML file returns defaults."""
        content = ""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
        
        try:
            config = load_dlp_config(Path(temp_path))
            self.assertEqual(config.canary_action, DLPAction.BLOCK)
        finally:
            os.remove(temp_path)

    def test_load_config_with_only_secret_patterns(self):
        """Test config with secrets but missing PII patterns logs no warning."""
        content = """
dlp:
  canary_action: BLOCK
  canary_salt: "salt"
  secrets_action: BLOCK
  pii_action: REDACT
  enable_ner: false
  secret_patterns:
    - name: api_key
      regex: "key[0-9]+"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
        
        try:
            # Should NOT log critical warning since secret_patterns is not empty
            config = load_dlp_config(Path(temp_path))
            self.assertEqual(len(config.secret_patterns), 1)
        finally:
            os.remove(temp_path)

    def test_load_config_with_only_pii_patterns(self):
        """Test config with PII but missing secret patterns logs no warning."""
        content = """
dlp:
  canary_action: BLOCK
  canary_salt: "salt"
  secrets_action: BLOCK
  pii_action: REDACT
  enable_ner: false
  pii_patterns:
    - name: phone
      regex: "[0-9]{10}"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
        
        try:
            # Should NOT log critical warning since pii_patterns is not empty
            config = load_dlp_config(Path(temp_path))
            self.assertEqual(len(config.pii_patterns), 1)
        finally:
            os.remove(temp_path)

    def test_load_config_with_malformed_pattern_entries(self):
        """Test that config handles patterns with missing fields gracefully."""
        content = """
dlp:
  canary_action: BLOCK
  canary_salt: "salt"
  secrets_action: BLOCK
  pii_action: REDACT
  enable_ner: false
  secret_patterns:
    - name: complete_pattern
      regex: "pattern[0-9]+"
    - regex: "missing_name"
    - name: missing_regex
  pii_patterns:
    - name: email_pattern
      regex: "email[a-z]+"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
        
        try:
            config = load_dlp_config(Path(temp_path))
            # Should load patterns, filling missing fields with defaults
            self.assertEqual(len(config.secret_patterns), 3)
            self.assertEqual(config.secret_patterns[0].name, "complete_pattern")
            self.assertEqual(config.secret_patterns[1].name, "unknown")  # Default
            self.assertEqual(config.secret_patterns[2].regex, "")  # Default
        finally:
            os.remove(temp_path)

    def test_parse_action_all_valid_actions(self):
        """Test that _parse_action correctly handles all valid action types."""
        self.assertEqual(_parse_action("ALLOW"), DLPAction.ALLOW)
        self.assertEqual(_parse_action("REDACT"), DLPAction.REDACT)
        self.assertEqual(_parse_action("ESCALATE"), DLPAction.ESCALATE)
        self.assertEqual(_parse_action("BLOCK"), DLPAction.BLOCK)

    def test_parse_action_case_insensitive(self):
        """Test that _parse_action is case-insensitive."""
        self.assertEqual(_parse_action("allow"), DLPAction.ALLOW)
        self.assertEqual(_parse_action("Allow"), DLPAction.ALLOW)
        self.assertEqual(_parse_action("ALLOW"), DLPAction.ALLOW)
        self.assertEqual(_parse_action("block"), DLPAction.BLOCK)
        self.assertEqual(_parse_action("Block"), DLPAction.BLOCK)

    def test_parse_action_invalid_returns_allow(self):
        """Test that invalid action strings default to ALLOW."""
        self.assertEqual(_parse_action("INVALID"), DLPAction.ALLOW)
        self.assertEqual(_parse_action("UNKNOWN"), DLPAction.ALLOW)
        self.assertEqual(_parse_action(""), DLPAction.ALLOW)
        self.assertEqual(_parse_action("123"), DLPAction.ALLOW)

    def test_dlp_config_defaults_are_sensible(self):
        """Test that DLPConfig.defaults() returns sensible defaults."""
        defaults = DLPConfig.defaults()
        
        # Verify sensible security defaults
        self.assertEqual(defaults.canary_action, DLPAction.BLOCK)
        self.assertEqual(defaults.secrets_action, DLPAction.BLOCK)
        self.assertEqual(defaults.pii_action, DLPAction.REDACT)
        self.assertFalse(defaults.enable_ner)
        
        # Verify patterns are present
        self.assertGreater(len(defaults.secret_patterns), 0)
        self.assertGreater(len(defaults.pii_patterns), 0)
        self.assertGreater(len(defaults.canary_labels), 0)

    def test_config_with_all_action_types_in_yaml(self):
        """Test config with all 4 action types defined."""
        content = """
dlp:
  canary_action: BLOCK
  canary_salt: "test_salt"
  secrets_action: ESCALATE
  pii_action: REDACT
  enable_ner: false
  secret_patterns:
    - name: secret
      regex: "secret"
  pii_patterns:
    - name: pii
      regex: "pii"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
            f.write(content)
            temp_path = f.name
        
        try:
            config = load_dlp_config(Path(temp_path))
            self.assertEqual(config.canary_action, DLPAction.BLOCK)
            self.assertEqual(config.secrets_action, DLPAction.ESCALATE)
            self.assertEqual(config.pii_action, DLPAction.REDACT)
        finally:
            os.remove(temp_path)

    def test_yaml_import_error_falls_back_to_defaults(self):
        """Test that missing PyYAML gracefully falls back to defaults."""
        temp_path = Path(tempfile.gettempdir()) / "test_policy.yaml"
        temp_path.write_text("dlp:\n  some_config: true")
        
        try:
            # Mock yaml import to raise ImportError
            with patch.dict('sys.modules', {'yaml': None}):
                with self.assertLogs(level=logging.CRITICAL) as cm:
                    config = load_dlp_config(temp_path)
                    # Should log that yaml is unavailable
                    self.assertTrue(any("PyYAML" in log for log in cm.output))
                    # Should use defaults
                    self.assertEqual(config.canary_action, DLPAction.BLOCK)
        finally:
            temp_path.unlink()


if __name__ == '__main__':
    unittest.main()
