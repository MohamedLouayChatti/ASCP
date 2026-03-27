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
        docs = [{"text": "Hello world"}]
        _, old_token, old_label = self.engine.inject_into_context(docs)
        self.engine.rotate_canaries()
        
        # We need to find the new token for the same label to ensure it changed.
        # But wait, with secrets.choice, we don't know which label it picks. Let's just generate tokens and detect them.
        _, new_token, new_label = self.engine.inject_into_context(docs)
        
        # It's possible but extremely unlikely to pick the same salt/signature combo
        # Or we can just assert that old_token is not detected anymore
        hits_old = self.engine.detect(old_token, ScanSurface.OUTPUT)
        self.assertEqual(len(hits_old), 0)
        
        # Old token shouldn't hit anymore
        hits_old = self.engine.detect(old_token, ScanSurface.OUTPUT)
        self.assertEqual(len(hits_old), 0)
        
        # New token should hit
        hits_new = self.engine.detect(new_token, ScanSurface.OUTPUT)
        self.assertEqual(len(hits_new), 1)

    def test_inject_into_context(self):
        docs = [{"title": "test", "content": "hello world"}]
        injected, token, label = self.engine.inject_into_context(docs)
        self.assertEqual(len(injected), 1)
        self.assertIn("Note: Session reference", injected[0]["content"])
        
        # Extract token and detect
        hits = self.engine.detect(injected[0]["content"], ScanSurface.OUTPUT)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].token, token)

if __name__ == '__main__':
    unittest.main()
