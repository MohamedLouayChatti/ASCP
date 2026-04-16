import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.config import DLPConfig
from dlp.canary import CanaryEngine
from dlp.models import ScanSurface


class TestCanaryEngine(unittest.TestCase):
    def setUp(self):
        self.config = DLPConfig.defaults()
        self.engine = CanaryEngine(self.config)

    def test_seeding_and_detection(self):
        docs = [{"text": "Hello world"}]
        injected_docs, token, label = self.engine.inject_into_context(docs)
        self.assertIsNotNone(token)

        text = f"Leaked: {token}"
        hits = self.engine.detect(text, ScanSurface.OUTPUT)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].label, label)
        self.assertEqual(hits[0].surface, ScanSurface.OUTPUT)

    def test_rotate_canaries(self):
        """
        Verify that rotate_canaries() actually invalidates previous tokens.

        We directly inspect _label_to_token before and after rotation.
        Accessing a private attribute is intentional here: we are testing the
        internal token management contract of CanaryEngine itself — the very
        state that rotation is supposed to change.  This is not testing the
        public API of consumers; it is testing the engine's own invariants.
        """
        target_label = "db_password"

        # Record the token for a known label before rotation.
        token_before = self.engine._label_to_token[target_label]

        self.engine.rotate_canaries(reason="unit test")

        # The token for the same label must have changed.
        token_after = self.engine._label_to_token[target_label]
        self.assertNotEqual(
            token_before,
            token_after,
            "Token for 'db_password' should differ after rotation.",
        )

        # The old token must no longer be in the reverse lookup.
        self.assertNotIn(
            token_before,
            self.engine._token_to_label,
            "Old token should be removed from _token_to_label after rotation.",
        )

        # The new token must be in the reverse lookup and map back to the same label.
        self.assertIn(token_after, self.engine._token_to_label)
        self.assertEqual(self.engine._token_to_label[token_after], target_label)

        # All original labels must still be present after rotation.
        for label in ["api_credential_mock", "db_password", "sys_admin_token"]:
            self.assertIn(label, self.engine._label_to_token)

    def test_inject_into_context_text_key(self):
        docs = [{"title": "test", "text": "hello world"}]
        injected, token, label = self.engine.inject_into_context(docs)
        self.assertEqual(len(injected), 1)
        self.assertIn("Note: Internal reference", injected[0]["text"])
        # Original key is preserved; no _dlp_canary_ref fallback used
        self.assertNotIn("_dlp_canary_ref", injected[0])

        hits = self.engine.detect(injected[0]["text"], ScanSurface.OUTPUT)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].token, token)

    def test_inject_into_context_content_key(self):
        docs = [{"title": "test", "content": "hello world"}]
        injected, token, label = self.engine.inject_into_context(docs)
        self.assertIn("Note: Internal reference", injected[0]["content"])
        self.assertNotIn("_dlp_canary_ref", injected[0])

    def test_inject_into_context_body_key(self):
        """Documents using 'body' (a configured content key) must receive the canary."""
        docs = [{"body": "some document body"}]
        injected, token, label = self.engine.inject_into_context(docs)
        self.assertIn("Note: Internal reference", injected[0]["body"])
        self.assertNotIn("_dlp_canary_ref", injected[0])

    def test_inject_into_context_page_content_key(self):
        """LangChain-style 'page_content' documents must receive the canary."""
        docs = [{"page_content": "retrieved chunk text"}]
        injected, token, label = self.engine.inject_into_context(docs)
        self.assertIn("Note: Internal reference", injected[0]["page_content"])
        self.assertNotIn("_dlp_canary_ref", injected[0])

    def test_inject_into_context_unknown_key_falls_back(self):
        """Documents with no configured key must fall back to '_dlp_canary_ref'."""
        docs = [{"unknown_key": "some value"}]
        injected, token, label = self.engine.inject_into_context(docs)
        self.assertIn("_dlp_canary_ref", injected[0])
        self.assertNotIn("Note: Internal reference", injected[0].get("unknown_key", ""))

    def test_detect_no_match(self):
        hits = self.engine.detect("Nothing sensitive here.", ScanSurface.OUTPUT)
        self.assertEqual(hits, [])

    def test_inject_empty_docs_returns_none(self):
        docs, token, label = self.engine.inject_into_context([])
        self.assertIsNone(token)
        self.assertIsNone(label)


if __name__ == '__main__':
    unittest.main()
