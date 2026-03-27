import logging

from .models import DLPMatch, DLPAction, ScanSurface
from .config import DLPConfig

logger = logging.getLogger(__name__)


class NERDetector:
    def __init__(self, config: DLPConfig, model: str = "en_core_web_sm"):
        self.config = config
        self._model = model
        self._nlp = None
        self._load_failed = False

    def _load(self) -> bool:
        if self._nlp is not None:
            return True
        if self._load_failed or not self.config.enable_ner:
            return False

        try:
            import spacy
            from spacy.util import is_package
            
            if not is_package(self._model):
                logger.warning(f"spaCy model '{self._model}' not found. NER disabled. Run 'python -m spacy download {self._model}'")
                self._load_failed = True
                return False
                
            self._nlp = spacy.load(self._model)
            return True
        except ImportError:
            logger.warning("spaCy not installed. NER disabled. Run 'pip install spacy'")
            self._load_failed = True
            return False
        except Exception as e:
            logger.warning(f"Failed to load spaCy model '{self._model}': {e}. NER disabled.")
            self._load_failed = True
            return False

    def detect(self, text: str, surface: ScanSurface) -> list[DLPMatch]:
        """Detects Named Entities that are PII."""
        if not self._load():
            return []

        # We assume _load() populated self._nlp
        doc = self._nlp(text)
        matches = []

        # Relevant PII labels
        pii_labels = {"PERSON", "ORG", "GPE", "LOC", "DATE", "EMAIL", "PHONE"}

        for ent in doc.ents:
            if ent.label_ in pii_labels:
                matches.append(DLPMatch(
                    pattern_name=f"ner_{ent.label_.lower()}",
                    category="pii",
                    action=self.config.pii_action,
                    value=ent.text,
                    spans=[(ent.start_char, ent.end_char)],
                    surface=surface
                ))

        return matches
