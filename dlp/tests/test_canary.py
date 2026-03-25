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
        # Already seeded by default
        text = f"Leaked: {self.engine._label_to_token['db_password']}"
        hits = self.engine.detect(text, ScanSurface.OUTPUT)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].label, "db_password")
        self.assertEqual(hits[0].surface, ScanSurface.OUTPUT)

    def test_rotate_canaries(self):
        old_token = self.engine._label_to_token["db_password"]
        self.engine.rotate_canaries()
        new_token = self.engine._label_to_token["db_password"]
        
        self.assertNotEqual(old_token, new_token)
        
        # Old token shouldn't hit anymore
        hits_old = self.engine.detect(old_token, ScanSurface.OUTPUT)
        self.assertEqual(len(hits_old), 0)
        
        # New token should hit
        hits_new = self.engine.detect(new_token, ScanSurface.OUTPUT)
        self.assertEqual(len(hits_new), 1)

    def test_inject_into_context(self):
        docs = [{"title": "test", "content": "hello world"}]
        injected = self.engine.inject_into_context(docs)
        self.assertEqual(len(injected), 1)
        self.assertIn("Note: Session reference", injected[0]["content"])
        
        # Extract token and detect
        hits = self.engine.detect(injected[0]["content"], ScanSurface.OUTPUT)
        self.assertEqual(len(hits), 1)

if __name__ == '__main__':
    unittest.main()
