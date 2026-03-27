import unittest
import tempfile
import os
import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.config import load_dlp_config, DLPConfig

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

if __name__ == '__main__':
    unittest.main()
