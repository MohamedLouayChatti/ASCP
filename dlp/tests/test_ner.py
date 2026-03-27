import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add the parent directory to the path so we can import dlp
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.models import ScanSurface, DLPAction, DLPMatch
from dlp.config import DLPConfig
from dlp.ner import NERDetector


def _is_spacy_model_available():
    """Check if spaCy and required model are available."""
    try:
        import spacy
        from spacy.util import is_package
        return is_package("en_core_web_sm")
    except (ImportError, Exception):
        return False


def _is_spacy_available():
    """Check if spaCy package is installed."""
    try:
        import spacy
        return True
    except ImportError:
        return False


class TestNERDetectorWithMock(unittest.TestCase):
    """Test NER with mocked spaCy to ensure core logic works without model."""
    
    def setUp(self):
        self.config = DLPConfig.defaults()
        self.config.enable_ner = True
        
    def _create_mock_entity(self, text, label, start_char, end_char):
        """Helper to create a mock spaCy entity."""
        entity = Mock()
        entity.text = text
        entity.label_ = label
        entity.start_char = start_char
        entity.end_char = end_char
        return entity
    
    def _create_mock_doc(self, entities):
        """Helper to create a mock spaCy doc with entities."""
        doc = Mock()
        doc.ents = entities
        return doc
    
    def test_ner_detector_person_detection(self):
        """Test NER detector recognizes PERSON entities."""
        detector = NERDetector(self.config, model="en_core_web_sm")
        
        # Inject a mock nlp directly
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        # Create mock entity
        entities = [self._create_mock_entity("John Smith", "PERSON", 10, 20)]
        doc = self._create_mock_doc(entities)
        mock_nlp.return_value = doc
        
        # Run detection
        matches = detector.detect("Hello John Smith.", ScanSurface.OUTPUT)
        
        # Verify
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pattern_name, "ner_person")
        self.assertEqual(matches[0].category, "pii")
        self.assertEqual(matches[0].value, "John Smith")
        self.assertEqual(matches[0].spans, [(10, 20)])
        self.assertEqual(matches[0].surface, ScanSurface.OUTPUT)
    
    def test_ner_detector_org_detection(self):
        """Test NER detector recognizes ORG (Organization) entities."""
        detector = NERDetector(self.config, model="en_core_web_sm")
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        entities = [self._create_mock_entity("Google Inc", "ORG", 15, 25)]
        doc = self._create_mock_doc(entities)
        mock_nlp.return_value = doc
        
        matches = detector.detect("Works at Google Inc.", ScanSurface.OUTPUT)
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pattern_name, "ner_org")
        self.assertEqual(matches[0].value, "Google Inc")
    
    def test_ner_detector_gpe_detection(self):
        """Test NER detector recognizes GPE (Geopolitical Entity) entities."""
        detector = NERDetector(self.config, model="en_core_web_sm")
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        entities = [self._create_mock_entity("France", "GPE", 8, 14)]
        doc = self._create_mock_doc(entities)
        mock_nlp.return_value = doc
        
        matches = detector.detect("Living in France.", ScanSurface.OUTPUT)
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pattern_name, "ner_gpe")
        self.assertEqual(matches[0].value, "France")
    
    def test_ner_detector_loc_detection(self):
        """Test NER detector recognizes LOC (Location) entities."""
        detector = NERDetector(self.config, model="en_core_web_sm")
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        entities = [self._create_mock_entity("Mount Everest", "LOC", 5, 18)]
        doc = self._create_mock_doc(entities)
        mock_nlp.return_value = doc
        
        matches = detector.detect("Climbing Mount Everest.", ScanSurface.OUTPUT)
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pattern_name, "ner_loc")
        self.assertEqual(matches[0].value, "Mount Everest")
    
    def test_ner_detector_date_detection(self):
        """Test NER detector recognizes DATE entities."""
        detector = NERDetector(self.config, model="en_core_web_sm")
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        entities = [self._create_mock_entity("January 15, 2024", "DATE", 4, 20)]
        doc = self._create_mock_doc(entities)
        mock_nlp.return_value = doc
        
        matches = detector.detect("Born January 15, 2024.", ScanSurface.OUTPUT)
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pattern_name, "ner_date")
        self.assertEqual(matches[0].value, "January 15, 2024")
    
    def test_ner_detector_multiple_entities(self):
        """Test NER detector with multiple different entity types."""
        detector = NERDetector(self.config, model="en_core_web_sm")
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        entities = [
            self._create_mock_entity("John Smith", "PERSON", 0, 10),
            self._create_mock_entity("Google", "ORG", 20, 26),
            self._create_mock_entity("USA", "GPE", 35, 38)
        ]
        doc = self._create_mock_doc(entities)
        mock_nlp.return_value = doc
        
        matches = detector.detect("John Smith works at Google in USA.", ScanSurface.OUTPUT)
        
        self.assertEqual(len(matches), 3)
        self.assertEqual(matches[0].pattern_name, "ner_person")
        self.assertEqual(matches[1].pattern_name, "ner_org")
        self.assertEqual(matches[2].pattern_name, "ner_gpe")
    
    def test_ner_detector_non_pii_entities_ignored(self):
        """Test that non-PII entity types are ignored."""
        detector = NERDetector(self.config, model="en_core_web_sm")
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        entities = [
            self._create_mock_entity("Apple", "PRODUCT", 10, 15),  # Not in PII labels
            self._create_mock_entity("John", "PERSON", 25, 29)
        ]
        doc = self._create_mock_doc(entities)
        mock_nlp.return_value = doc
        
        matches = detector.detect("I love the Apple product. John uses it.", ScanSurface.OUTPUT)
        
        # Should only detect PERSON, not PRODUCT
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pattern_name, "ner_person")
    
    def test_ner_detector_respects_enable_ner_config(self):
        """Test that NER respects enable_ner configuration."""
        self.config.enable_ner = False
        
        detector = NERDetector(self.config)
        
        # Even with mock nlp, should return empty if disabled
        matches = detector.detect("John Smith here.", ScanSurface.OUTPUT)
        
        self.assertEqual(len(matches), 0)
    
    def test_ner_detector_load_failure_returns_empty(self):
        """Test that load failures gracefully return empty matches."""
        detector = NERDetector(self.config)
        detector._load_failed = True
        
        matches = detector.detect("John Smith here.", ScanSurface.OUTPUT)
        
        self.assertEqual(len(matches), 0)
    
    def test_ner_detector_applies_correct_action(self):
        """Test that detected entities have the correct action applied."""
        self.config.pii_action = DLPAction.REDACT
        
        detector = NERDetector(self.config)
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        entities = [self._create_mock_entity("John Smith", "PERSON", 0, 10)]
        doc = self._create_mock_doc(entities)
        mock_nlp.return_value = doc
        
        matches = detector.detect("John Smith.", ScanSurface.OUTPUT)
        
        self.assertEqual(matches[0].action, DLPAction.REDACT)
    
    def test_ner_detector_scan_surface_preservation(self):
        """Test that scan surface is correctly preserved in matches."""
        detector = NERDetector(self.config)
        
        # Test different surfaces
        for surface in [ScanSurface.OUTPUT, ScanSurface.TOOL_ARGS, ScanSurface.TOOL_RESULT]:
            mock_nlp = Mock()
            detector._nlp = mock_nlp
            detector._load_failed = False
            
            entities = [self._create_mock_entity("John", "PERSON", 0, 4)]
            doc = self._create_mock_doc(entities)
            mock_nlp.return_value = doc
            
            matches = detector.detect("John here.", surface)
            self.assertEqual(matches[0].surface, surface)
    
    @unittest.skipUnless(_is_spacy_available(), "spaCy not available")
    def test_ner_detector_model_not_found_fallback(self):
        """Test graceful handling when spaCy model is not found."""
        with patch('spacy.util.is_package', return_value=False):
            detector = NERDetector(self.config)
            
            # Should fail to load and return empty
            matches = detector.detect("John Smith.", ScanSurface.OUTPUT)
            
            self.assertEqual(len(matches), 0)
            self.assertTrue(detector._load_failed)
    
    def test_ner_detector_spacy_import_error_fallback(self):
        """Test graceful handling when spaCy is not installed."""
        detector = NERDetector(self.config)
        
        # Mock ImportError by patching at the point of import
        with patch.dict('sys.modules', {'spacy': None}):
            detector._nlp = None
            detector._load_failed = False
            
            result = detector._load()
            
            self.assertFalse(result)
            self.assertTrue(detector._load_failed)
    
    def test_ner_detector_empty_text(self):
        """Test NER detector with empty text."""
        detector = NERDetector(self.config)
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        doc = self._create_mock_doc([])
        mock_nlp.return_value = doc
        
        matches = detector.detect("", ScanSurface.OUTPUT)
        
        self.assertEqual(len(matches), 0)
    
    def test_ner_detector_no_entities(self):
        """Test NER detector when no entities are found."""
        detector = NERDetector(self.config)
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        doc = self._create_mock_doc([])
        mock_nlp.return_value = doc
        
        matches = detector.detect("This is a simple sentence.", ScanSurface.OUTPUT)
        
        self.assertEqual(len(matches), 0)
    
    def test_ner_detector_load_cached(self):
        """Test that model is loaded only once."""
        detector = NERDetector(self.config)
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        
        # First call
        result1 = detector._load()
        # Second call
        result2 = detector._load()
        
        self.assertTrue(result1)
        self.assertTrue(result2)
    
    def test_ner_detector_action_from_config(self):
        """Test that detected entities use the configured PII action."""
        # Test with BLOCK action
        self.config.pii_action = DLPAction.BLOCK
        detector = NERDetector(self.config)
        
        mock_nlp = Mock()
        detector._nlp = mock_nlp
        detector._load_failed = False
        
        entities = [self._create_mock_entity("John", "PERSON", 0, 4)]
        doc = self._create_mock_doc(entities)
        mock_nlp.return_value = doc
        
        matches = detector.detect("John.", ScanSurface.OUTPUT)
        
        self.assertEqual(matches[0].action, DLPAction.BLOCK)


    def test_ner_spacy_load_generic_exception(self):
        """Test fallback on generic exception gracefully."""
        self.config.enable_ner = True
        detector = NERDetector(self.config)
        
        with patch('spacy.util.is_package', side_effect=Exception("Disk corrupted")):
            result = detector._load()
            self.assertFalse(result)
            self.assertTrue(detector._load_failed)

class TestNERDetectorWithRealModel(unittest.TestCase):
    """Integration tests with real spaCy model."""
    
    def setUp(self):
        self.config = DLPConfig.defaults()
        self.config.enable_ner = True
        
    def test_real_ner_person_detection(self):
        """Test with actual spaCy model on real text."""
        detector = NERDetector(self.config)
        
        if not detector._load():
            self.fail("spaCy model could not be loaded - required for real tests")
        
        text = "John Smith works at Microsoft in Seattle."
        matches = detector.detect(text, ScanSurface.OUTPUT)
        
        # Should detect at least one entity
        self.assertGreater(len(matches), 0)
        
        # Check that we have relevant PII matches
        pattern_names = {m.pattern_name for m in matches}
        self.assertIn("ner_person", pattern_names)
        self.assertIn("ner_org", pattern_names)
        self.assertIn("ner_gpe", pattern_names)
    
    def test_real_ner_multiple_people(self):
        """Test detection of multiple people with real model."""
        detector = NERDetector(self.config)
        
        if not detector._load():
            self.fail("spaCy model could not be loaded")
        
        # spaCy's en_core_web_sm sometimes misclassifies "Carol at Google" as PRODUCT or skips.
        # "Michael, Sarah, and Jessica" works reliably.
        text = "Michael met with Sarah and Jessica at Google."
        matches = detector.detect(text, ScanSurface.OUTPUT)
        
        # Verify we get some matches
        self.assertGreater(len(matches), 0)
        self.assertEqual(all(m.category == "pii" for m in matches), True)
        
        # People should be detected
        person_matches = [m.value for m in matches if m.pattern_name == "ner_person"]
        self.assertIn("Michael", person_matches)
        self.assertIn("Sarah", person_matches)
        self.assertIn("Jessica", person_matches)
    
    def test_real_ner_span_accuracy(self):
        """Test that spans are correctly calculated."""
        detector = NERDetector(self.config)
        
        if not detector._load():
            self.fail("spaCy model could not be loaded")
        
        text = "Contact John Smith immediately."
        matches = detector.detect(text, ScanSurface.OUTPUT)
        
        # Find person matches
        person_matches = [m for m in matches if m.pattern_name == "ner_person"]
        
        self.assertGreater(len(person_matches), 0)
        match = person_matches[0]
        # Verify span extraction is correct
        for start, end in match.spans:
            extracted = text[start:end]
            self.assertEqual(extracted, match.value)

    def test_real_ner_all_entity_types(self):
        """Test that the real model correctly flags all PII entity types."""
        detector = NERDetector(self.config)
        if not detector._load():
            self.fail("spaCy model could not be loaded")
            
        text = "On January 15, 2024, Albert Einstein visited Mount Everest in Nepal for the United Nations."
        matches = detector.detect(text, ScanSurface.OUTPUT)
        
        pattern_names = {m.pattern_name for m in matches}
        extracted_values = {m.value for m in matches}
        
        self.assertIn("ner_date", pattern_names)
        self.assertIn("ner_person", pattern_names)
        self.assertIn("ner_loc", pattern_names)
        self.assertIn("ner_gpe", pattern_names)
        self.assertIn("ner_org", pattern_names)
        
        # Checking some specific text extracts just to be absolutely sure the NER works perfectly:
        self.assertTrue(any("Albert Einstein" in val for val in extracted_values))
        self.assertTrue(any("Mount Everest" in val for val in extracted_values))
        self.assertTrue(any("Nepal" in val for val in extracted_values))
        self.assertTrue(any("United Nations" in val for val in extracted_values))

    def test_real_ner_skips_non_pii(self):
        """Ensure standard nouns and non-PII labels aren't flagged as PII by default."""
        detector = NERDetector(self.config)
        if not detector._load():
            self.fail("spaCy model could not be loaded")
            
        # "Apple" is often PRODUCT or ORG depending on context; "laptop" is nothing/object.
        # "$100" is MONEY. "three" is CARDINAL. Non-PII labels shouldn't be matched.
        text = "I bought a cool laptop for $100."
        matches = detector.detect(text, ScanSurface.OUTPUT)
        
        # The default config only allows PERSON, ORG, GPE, LOC, DATE, EMAIL, PHONE
        self.assertEqual(len(matches), 0)

    def test_real_ner_empty_or_whitespace(self):
        """Real model handles empty and whitespace safely."""
        detector = NERDetector(self.config)
        
        matches = detector.detect("", ScanSurface.OUTPUT)
        self.assertEqual(len(matches), 0)
        
        matches = detector.detect("   \n\t  ", ScanSurface.OUTPUT)
        self.assertEqual(len(matches), 0)

if __name__ == '__main__':
    unittest.main()
