import hashlib
import logging
import re
import secrets
from copy import deepcopy
from datetime import datetime, timezone
from difflib import SequenceMatcher

from .models import CanaryHit, ScanSurface
from .config import DLPConfig


def _normalize(text: str) -> str:
    """Lowercase and strip non-alphanumeric characters for fuzzy comparison."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


class CanaryEngine:
    def __init__(self, config: DLPConfig):
        self._salt = config.canary_salt
        self._content_keys = config.content_keys
        self._config = config
        self._token_to_label: dict[str, str] = {}
        self._label_to_token: dict[str, str] = {}
        self.seed(config.canary_labels)

    def _generate_token(self, label: str) -> str:
        raw = f"{self._salt}:{label}".encode("utf-8")
        return f"CANARY-{hashlib.sha256(raw).hexdigest()[:16]}"

    def seed(self, labels: list[str]) -> None:
        for label in labels:
            token = self._generate_token(label)
            self._token_to_label[token] = label
            self._label_to_token[label] = token

    def rotate_canaries(self, reason: str = "scheduled") -> None:
        """
        Replace the salt with a fresh cryptographically random value, invalidating
        all previous tokens. Logs a WARNING for audit trail.
        """
        new_salt = secrets.token_hex(32)
        timestamp = datetime.now(timezone.utc).isoformat()
        logging.warning(
            "Canary rotation at %s (reason: %s). All previous tokens invalid. "
            "Old salt prefix: %s...",
            timestamp, reason, self._salt[:8],
        )
        self._salt = new_salt
        labels = list(self._label_to_token.keys())
        self._token_to_label.clear()
        self._label_to_token.clear()
        self.seed(labels)

    def inject_into_context(
        self, docs: list[dict[str, str]]
    ) -> tuple[list[dict[str, str]], str | None, str | None]:
        """
        Selects one document at random and injects a canary token into it.
        Searches content_keys in order; falls back to '_canary' with a warning.
        Returns (modified_docs, injected_token, injected_label).
        """
        if not docs or not self._label_to_token:
            return docs, None, None

        docs_copy = deepcopy(docs)
        doc_idx = secrets.randbelow(len(docs_copy))
        target_doc = docs_copy[doc_idx]

        label = secrets.choice(list(self._label_to_token.keys()))
        token = self._label_to_token[label]
        injection_text = f"\nNote: Session reference [{token}]."

        content_key = next((k for k in self._content_keys if k in target_doc), None)
        if content_key is not None:
            target_doc[content_key] = target_doc[content_key] + injection_text
        else:
            logging.warning(
                "Canary injection fallback: document has none of the configured "
                "content_keys %s. Token stored in '_canary' (invisible to model).",
                self._content_keys,
            )
            target_doc["_canary"] = injection_text

        return docs_copy, token, label

    # ── Detection ─────────────────────────────────────────────────────────────

    def detect(self, text: str, surface: ScanSurface) -> list[CanaryHit]:
        """Exact detection + optional fuzzy detection."""
        exact_hits = self._detect_exact(text, surface)
        if self._config.canary_fuzzy_match:
            exact_tokens = {h.token for h in exact_hits}
            fuzzy_hits = self._detect_fuzzy(text, surface, exact_tokens)
            return exact_hits + fuzzy_hits
        return exact_hits

    def _detect_exact(self, text: str, surface: ScanSurface) -> list[CanaryHit]:
        hits: list[CanaryHit] = []
        for token, label in self._token_to_label.items():
            idx = text.find(token)
            if idx != -1:
                start = max(0, idx - 20)
                end = min(len(text), idx + len(token) + 20)
                excerpt = text[start:end].replace("\n", " ")
                hits.append(
                    CanaryHit(token=token, label=label,
                              context_excerpt=excerpt, surface=surface, fuzzy=False)
                )
        return hits

    def _detect_fuzzy(
        self, text: str, surface: ScanSurface, exact_tokens: set[str]
    ) -> list[CanaryHit]:
        """
        Normalized sliding-window fuzzy search for reformatted canary tokens.

        Steps:
          1. Normalize text and token (lowercase, alphanumeric only).
          2. Quick substring check (catches whitespace insertion / case changes).
          3. Sliding window with SequenceMatcher for partial character-level similarity.

        Only tokens not already found by exact detection are checked.
        """
        norm_text = _normalize(text)
        overlap_threshold = self._config.canary_fuzzy_overlap
        hits: list[CanaryHit] = []

        for token, label in self._token_to_label.items():
            if token in exact_tokens:
                continue
            norm_token = _normalize(token)
            if len(norm_token) < 8:
                continue

            token_len = len(norm_token)

            # Step 1: exact substring on normalized text
            if norm_token in norm_text:
                idx = norm_text.index(norm_token)
                approx = int(idx * len(text) / max(1, len(norm_text)))
                excerpt = text[max(0, approx - 10):approx + len(token) + 20].replace("\n", " ")
                hits.append(
                    CanaryHit(token=token, label=label,
                              context_excerpt=excerpt, surface=surface, fuzzy=True)
                )
                continue

            # Step 2: sliding window with SequenceMatcher
            window_size = int(token_len * 1.2)
            step = max(1, token_len // 4)
            for i in range(0, max(1, len(norm_text) - token_len + 1), step):
                window = norm_text[i:i + window_size]
                ratio = SequenceMatcher(None, norm_token, window[:token_len]).ratio()
                if ratio >= overlap_threshold:
                    approx = int(i * len(text) / max(1, len(norm_text)))
                    excerpt = text[max(0, approx - 10):approx + len(token) + 30].replace("\n", " ")
                    hits.append(
                        CanaryHit(token=token, label=label,
                                  context_excerpt=excerpt, surface=surface, fuzzy=True)
                    )
                    break

        return hits
