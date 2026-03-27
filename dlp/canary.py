import hashlib
import logging
import secrets
from copy import deepcopy
from datetime import datetime, timezone

from .models import CanaryHit, ScanSurface
from .config import DLPConfig


class CanaryEngine:
    def __init__(self, config: DLPConfig):
        self._salt = config.canary_salt
        self._content_keys = config.content_keys
        self._token_to_label: dict[str, str] = {}
        self._label_to_token: dict[str, str] = {}

        # Trust the dataclass contract — canary_labels is always present.
        self.seed(config.canary_labels)

    def _generate_token(self, label: str) -> str:
        """Deterministically generates a canary token for a given label and salt."""
        raw = f"{self._salt}:{label}".encode("utf-8")
        hash_hex = hashlib.sha256(raw).hexdigest()[:16]
        return f"CANARY-{hash_hex}"

    def seed(self, labels: list[str]) -> None:
        """Seeds the engine with a list of canary labels."""
        for label in labels:
            token = self._generate_token(label)
            self._token_to_label[token] = label
            self._label_to_token[label] = token

    def rotate_canaries(self, reason: str = "scheduled") -> None:
        """
        Rotates canary tokens by replacing the salt with a fresh cryptographically
        random value. All previous tokens are immediately invalidated.

        Args:
            reason: Human-readable reason for the rotation (logged for audit purposes).
        """
        new_salt = secrets.token_hex(32)
        timestamp = datetime.now(timezone.utc).isoformat()
        logging.warning(
            "Canary rotation at %s (reason: %s). "
            "All previous tokens are now invalid. "
            "Old salt prefix: %s...",
            timestamp,
            reason,
            self._salt[:8],
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
        Selects one document and embeds a plain-text canary token into it.
        Survives HTML stripping because it's plain text.
        Returns the modified docs, the injected token, and its label.

        The document key used for injection is the first key from ``content_keys``
        (configured via DLPConfig) that is present in the chosen document. If none
        of the configured keys are present, the token is stored under ``_canary`` —
        a key the model will never see — which means the canary is effectively
        disabled for that document. Operators should ensure their document schema
        uses one of the configured keys.
        """
        if not docs or not self._label_to_token:
            return docs, None, None

        docs_copy = deepcopy(docs)

        # Pick a random document to inject into
        doc_idx = secrets.randbelow(len(docs_copy))
        target_doc = docs_copy[doc_idx]

        # Pick a random label
        label = secrets.choice(list(self._label_to_token.keys()))
        token = self._label_to_token[label]

        # Plain-text injection
        injection_text = f"\nNote: Session reference [{token}]."

        # Try configured content keys in order before falling back.
        content_key = next(
            (k for k in self._content_keys if k in target_doc), None
        )
        if content_key is not None:
            target_doc[content_key] = target_doc[content_key] + injection_text
        else:
            # Fallback: the model will never see this key, so the canary is
            # inert.  Operators should add the document's actual key to
            # DLPConfig.content_keys to make detection work.
            logging.warning(
                "Canary injection fallback: document has none of the configured "
                "content_keys %s. Token stored in '_canary' and will not be "
                "visible to the model.",
                self._content_keys,
            )
            target_doc["_canary"] = injection_text

        return docs_copy, token, label

    def detect(self, text: str, surface: ScanSurface) -> list[CanaryHit]:
        """
        Scans text for all seeded canary tokens.
        """
        hits = []
        for token, label in self._token_to_label.items():
            idx = text.find(token)
            if idx != -1:
                # Extract a short excerpt for context
                start = max(0, idx - 20)
                end = min(len(text), idx + len(token) + 20)
                excerpt = text[start:end].replace('\n', ' ')

                hits.append(CanaryHit(
                    token=token,
                    label=label,
                    context_excerpt=excerpt,
                    surface=surface
                ))
        return hits
