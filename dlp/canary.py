import hashlib
import secrets
from copy import deepcopy

from .models import CanaryHit, ScanSurface
from .config import DLPConfig

class CanaryEngine:
    def __init__(self, config: DLPConfig):
        self._salt = config.canary_salt
        self._token_to_label: dict[str, str] = {}
        self._label_to_token: dict[str, str] = {}
        
        # Seed default labels
        self.seed(config.canary_labels if hasattr(config, 'canary_labels') and config.canary_labels else ["api_credential_mock", "db_password", "sys_admin_token"])

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

    def rotate_canaries(self) -> None:
        """
        Rotates canary tokens. In a production system, this would change the salt
        and re-seed, effectively invalidating all previous tokens.
        """
        import uuid
        self._salt = str(uuid.uuid4())
        labels = list(self._label_to_token.keys())
        self._token_to_label.clear()
        self._label_to_token.clear()
        self.seed(labels)

    def inject_into_context(self, docs: list[dict[str, str]]) -> tuple[list[dict[str, str]], str | None, str | None]:
        """
        Selects one document and embeds a plain-text canary token into it.
        Survives HTML stripping because it's plain text.
        Returns the modified docs, the injected token, and its label.
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
        
        # Append to the document text (assuming 'text' or 'content' key, we will try both)
        content_key = "text" if "text" in target_doc else "content"
        if content_key in target_doc:
            target_doc[content_key] = target_doc[content_key] + injection_text
        else:
            # Fallback if we don't know the schema
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
