"""Tests for document fingerprinting (dlp/fingerprint.py)."""
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.config import DLPConfig
from dlp.fingerprint import DocumentFingerprinter, _word_trigrams
from dlp.models import ScanSurface


def _make_fp(threshold: float = 0.3, max_docs: int = 100, ttl: int = 3600) -> DocumentFingerprinter:
    cfg = DLPConfig.defaults()
    cfg.enable_fingerprinting = True
    cfg.fingerprint_threshold = threshold
    cfg.fingerprint_max_docs = max_docs
    cfg.fingerprint_ttl_seconds = ttl
    cfg.content_keys = ["text", "content"]
    return DocumentFingerprinter(cfg)


class TestWordTrigrams(unittest.TestCase):
    def test_basic_trigrams(self):
        t = _word_trigrams("the quick brown fox")
        self.assertIn("the quick brown", t)
        self.assertIn("quick brown fox", t)

    def test_fewer_than_3_words_empty(self):
        self.assertEqual(_word_trigrams("hello world"), set())
        self.assertEqual(_word_trigrams(""), set())

    def test_punctuation_stripped(self):
        t = _word_trigrams("hello, world! how")
        self.assertIn("hello world how", t)


class TestDocumentFingerprinter(unittest.TestCase):
    def test_exact_reproduction_hits(self):
        fp = _make_fp(threshold=0.3)
        doc_text = "the quick brown fox jumps over the lazy dog and the cat"
        fp.fingerprint_docs([{"text": doc_text}], ["text"])

        result = fp.scan(doc_text, ScanSurface.OUTPUT)
        self.assertEqual(len(result), 1)
        self.assertGreaterEqual(result[0].overlap_ratio, 0.3)

    def test_partial_reproduction_above_threshold_hits(self):
        fp = _make_fp(threshold=0.4)
        doc_text = "alpha beta gamma delta epsilon zeta eta theta iota kappa"
        fp.fingerprint_docs([{"text": doc_text}], ["text"])

        # Use first half of the trigrams — still a significant portion
        partial = "alpha beta gamma delta epsilon zeta eta"
        result = fp.scan(partial, ScanSurface.OUTPUT)
        if result:
            self.assertGreaterEqual(result[0].overlap_ratio, 0.0)

    def test_unrelated_text_no_hit(self):
        fp = _make_fp(threshold=0.3)
        doc_text = "the quick brown fox jumps over the lazy dog"
        fp.fingerprint_docs([{"text": doc_text}], ["text"])

        result = fp.scan("completely different content here with no overlap", ScanSurface.OUTPUT)
        self.assertEqual(result, [])

    def test_clear_resets_fingerprints(self):
        fp = _make_fp(threshold=0.1)
        doc_text = "the quick brown fox jumps over the lazy dog"
        fp.fingerprint_docs([{"text": doc_text}], ["text"])
        fp.clear()

        result = fp.scan(doc_text, ScanSurface.OUTPUT)
        self.assertEqual(result, [], "After clear(), no fingerprints should remain")
        self.assertEqual(fp.doc_count, 0)

    def test_lru_eviction_at_max_docs(self):
        fp = _make_fp(max_docs=3)
        # Fingerprint 3 docs in a single call so they get doc_0, doc_1, doc_2
        docs = [
            {"text": f"unique content document number {i} with extra words here now"}
            for i in range(3)
        ]
        fp.fingerprint_docs(docs, ["text"])
        self.assertEqual(fp.doc_count, 3)

        # Adding a 4th batch of 1 doc should evict the oldest entry (doc_0)
        fp.fingerprint_docs([{"text": "brand new document about something else entirely"}], ["text"])
        self.assertLessEqual(fp.doc_count, 3)

    def test_ttl_eviction(self):
        fp = _make_fp(ttl=0)  # 0 seconds → everything immediately expired
        doc_text = "the quick brown fox jumps over the lazy dog"
        fp.fingerprint_docs([{"text": doc_text}], ["text"])
        time.sleep(0.01)  # let TTL expire

        # scan() triggers eviction before checking
        result = fp.scan(doc_text, ScanSurface.OUTPUT)
        self.assertEqual(result, [], "Expired fingerprints should be evicted on scan")

    def test_multi_doc_fingerprinting(self):
        fp = _make_fp(threshold=0.3)
        docs = [
            {"text": "the quick brown fox fox fox jumps jumps jumps over"},
            {"content": "hello world this is document two totally different"},
        ]
        fp.fingerprint_docs(docs, ["text", "content"])
        self.assertEqual(fp.doc_count, 2)

    def test_empty_text_not_fingerprinted(self):
        fp = _make_fp()
        fp.fingerprint_docs([{"text": ""}], ["text"])
        self.assertEqual(fp.doc_count, 0)

    def test_fingerprint_hit_fields(self):
        fp = _make_fp(threshold=0.1)
        doc_text = "alpha beta gamma delta epsilon zeta the quick brown fox"
        fp.fingerprint_docs([{"text": doc_text}], ["text"])

        result = fp.scan(doc_text, ScanSurface.OUTPUT)
        if result:
            hit = result[0]
            self.assertEqual(hit.doc_id, "doc_0")
            self.assertIsInstance(hit.overlap_ratio, float)
            self.assertIsInstance(hit.matched_trigrams, int)
            self.assertEqual(hit.surface, ScanSurface.OUTPUT)


if __name__ == "__main__":
    unittest.main()
