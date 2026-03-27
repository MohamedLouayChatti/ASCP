"""
Document-level fingerprinting for verbatim reproduction detection.

Computes word-level trigram sets for each retrieved document and scans model
output for significant overlap. When a high proportion of a document's trigrams
appear verbatim in the output, the model is directly reproducing source material
— which may violate confidentiality, copyright, or RAG attribution requirements.

Memory management:
  TTL eviction  — entries older than fingerprint_ttl_seconds are pruned.
  LRU eviction  — when fingerprint_max_docs is reached, the oldest entry
                  (by insertion order) is removed before adding a new one.
Both limits are configurable in YAML.
"""

import re
import time
from collections import OrderedDict

from .models import FingerprintHit, ScanSurface
from .config import DLPConfig


def _word_trigrams(text: str) -> set[str]:
    """
    Compute word-level trigrams from text.
    Word-level is more robust than character trigrams: normalises punctuation
    and is less sensitive to minor formatting differences.
    Returns empty set when text has fewer than 3 words.
    """
    words = re.sub(r"[^\w\s]", "", text.lower()).split()
    if len(words) < 3:
        return set()
    return {f"{words[i]} {words[i+1]} {words[i+2]}" for i in range(len(words) - 2)}


class _DocEntry:
    """Internal: a fingerprinted document with its creation timestamp."""

    __slots__ = ("trigrams", "created_at")

    def __init__(self, trigrams: set[str]) -> None:
        self.trigrams = trigrams
        self.created_at = time.monotonic()


class DocumentFingerprinter:
    """
    Fingerprints retrieved documents and detects verbatim reproduction in output.

    Usage:
        fingerprinter.fingerprint_docs(retrieved_docs, content_keys)
        # ... model generates output ...
        hits = fingerprinter.scan(model_output, ScanSurface.OUTPUT)
    """

    def __init__(self, config: DLPConfig) -> None:
        self.config = config
        # OrderedDict preserves insertion order for deterministic LRU eviction
        self._store: OrderedDict[str, _DocEntry] = OrderedDict()

    # ── Eviction ─────────────────────────────────────────────────────────────

    def _evict_expired(self) -> None:
        """Remove entries whose age exceeds fingerprint_ttl_seconds."""
        now = time.monotonic()
        ttl = self.config.fingerprint_ttl_seconds
        expired = [
            doc_id
            for doc_id, entry in self._store.items()
            if now - entry.created_at > ttl
        ]
        for doc_id in expired:
            del self._store[doc_id]

    def _evict_lru_if_full(self) -> None:
        """Evict the oldest entry when the store is at capacity."""
        while len(self._store) >= self.config.fingerprint_max_docs:
            self._store.popitem(last=False)  # FIFO removal

    # ── Public API ────────────────────────────────────────────────────────────

    def fingerprint_docs(self, docs: list[dict], content_keys: list[str]) -> None:
        """
        Fingerprint a batch of retrieved documents.

        Each document is labelled "doc_<index>" so callers can trace hits back
        to the source. Expired entries are pruned before insertion.
        """
        self._evict_expired()
        for idx, doc in enumerate(docs):
            doc_id = f"doc_{idx}"
            # Extract text following the same priority order as canary injection
            text = next(
                (str(doc[k]) for k in content_keys if k in doc),
                " ".join(str(v) for v in doc.values()),
            )
            trigrams = _word_trigrams(text)
            if not trigrams:
                continue
            self._evict_lru_if_full()
            self._store[doc_id] = _DocEntry(trigrams)

    def scan(self, text: str, surface: ScanSurface) -> list[FingerprintHit]:
        """
        Check output for verbatim reproduction of any fingerprinted document.

        Returns FingerprintHit for each document whose trigram overlap ratio
        meets or exceeds fingerprint_threshold. Expired entries are pruned first.
        """
        self._evict_expired()
        output_trigrams = _word_trigrams(text)
        if not output_trigrams:
            return []

        hits: list[FingerprintHit] = []
        for doc_id, entry in self._store.items():
            if not entry.trigrams:
                continue
            matched = len(output_trigrams & entry.trigrams)
            ratio = matched / len(entry.trigrams)
            if ratio >= self.config.fingerprint_threshold:
                hits.append(
                    FingerprintHit(
                        doc_id=doc_id,
                        overlap_ratio=round(ratio, 4),
                        matched_trigrams=matched,
                        surface=surface,
                    )
                )
        return hits

    def clear(self) -> None:
        """Reset all stored fingerprints (e.g., at the start of a new session)."""
        self._store.clear()

    @property
    def doc_count(self) -> int:
        """Number of currently stored fingerprints."""
        return len(self._store)
