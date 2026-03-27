# DLP Module Development

## Philosophy

This branch is module-scoped. Development artifacts should stay under `dlp/` whenever possible to reduce merge conflicts when integrating into `main`.

## Local Commands

```bash
python -m pytest dlp/tests -v
python -m pytest dlp/tests -v --cov=dlp --cov-report=term-missing
```

## Optional Developer Dependencies

Use `dlp/requirements-dev.txt` if your environment does not already provide tools.

```bash
pip install -r dlp/requirements-dev.txt
```

## NER (Named Entity Recognition) Module

### Overview

The NER module provides Named Entity Recognition capabilities using spaCy to detect personally identifiable information (PII) such as:
- **PERSON**: Names of individuals (e.g., "John Smith")
- **ORG**: Organizations (e.g., "Google", "Microsoft")
- **GPE**: Geopolitical entities (e.g., "USA", "France")
- **LOC**: Physical locations (e.g., "Mount Everest")
- **DATE**: Temporal expressions (e.g., "January 15, 2024")

### Installation

NER is an optional feature. To use it, install spaCy and the English model:

```bash
# Install spaCy package
pip install spacy

# Download the English model
python -m spacy download en_core_web_sm
```

Alternatively, install via optional dependencies:

```bash
pip install "ascp-dlp[ner]"
```

### Configuration

Enable NER in your DLP policy YAML:

```yaml
dlp:
  enable_ner: true
  pii_action: REDACT  # or BLOCK, ESCALATE
```

### Implementation Details

**Location**: `dlp/ner.py`

The `NERDetector` class:
- Lazy-loads the spaCy model on first use
- Caches the model to avoid repeated loading
- Gracefully handles missing spaCy or models
- Integrates seamlessly with the DLP scanning pipeline

**Key Features**:
- **Lazy Loading**: Model is only loaded when NER is enabled and first needed
- **Error Handling**: Gracefully degrades if spaCy or model not available
- **Deduplication**: Avoids double-reporting when regex patterns already caught the same entity
- **Performance**: Short-circuits expensive NER processing if canary or secret already triggered

### Testing

Comprehensive tests are provided in `dlp/tests/test_ner.py`:

**Unit Tests** (with mocks):
```bash
python -m pytest dlp/tests/test_ner.py::TestNERDetectorWithMock -v
```

- 16 unit tests covering all entity types
- Tests for configuration respect
- Tests for error handling and graceful degradation
- Tests for redaction and blocking actions

**Integration Tests** (with real model, if available):
```bash
python -m pytest dlp/tests/test_ner.py::TestNERDetectorWithRealModel -v
```

- Tests with actual spaCy model
- Real-world text processing
- Span accuracy validation

**Integration Tests with Scanner**:
```bash
python -m pytest dlp/tests/test_integration.py::TestNERIntegration -v
```

- Tests NER within the full DLP pipeline
- Tests all three scan surfaces (OUTPUT, TOOL_ARGS, TOOL_RESULT)
- Tests interaction with canaries and secrets detection
- Tests multiple entity detection and redaction

### Running All Tests

```bash
# Run all tests including NER
python -m pytest dlp/tests -v

# Run with coverage report
python -m pytest dlp/tests -v --cov=dlp --cov-report=html --cov-report=term-missing
```

### NER in the DLP Pipeline

1. **Regex Scanning** (secrets & PII patterns) - runs first
2. **NER Scanning** - runs only if:
   - `enable_ner: true` in config
   - No BLOCK action already triggered (optimization)
   - Model successfully loaded
3. **Deduplication** - NER results compared against regex results
   - Overlapping spans are skipped to avoid double-counting
   - Preserves original detection source (regex takes precedence)

### Example Usage

```python
from dlp import DLPConfig, NERDetector, ScanSurface

config = DLPConfig.defaults()
config.enable_ner = True

detector = NERDetector(config)

# Detect NER entities
text = "John Smith works at Microsoft in Seattle."
matches = detector.detect(text, ScanSurface.OUTPUT)

for match in matches:
    print(f"Found {match.pattern_name}: {match.value}")
    # Output: Found ner_person: John Smith
    #         Found ner_org: Microsoft
    #         Found ner_gpe: Seattle
```

### Troubleshooting

**NER not detecting anything**:
- Verify `enable_ner: true` in config
- Check that spaCy and model are installed: `python -m spacy download en_core_web_sm`
- Check logs for model loading errors

**Poor detection quality**:
- Current model `en_core_web_sm` is a lightweight, general-purpose model
- For specialized domains, consider fine-tuning or using larger models
- Review detected entities to validate accuracy

**Performance concerns**:
- NER is computationally expensive; results are only used if workflow hasn't already blocked
- Model is lazily loaded and cached
- Consider disabling NER if processing speed is critical and regex patterns are sufficient

## CI Template

A reusable CI template is provided at `dlp/ci/workflows/tests.yml`.

Important: GitHub Actions only runs from `.github/workflows/` at repository root. In the target monorepo, copy or adapt this template there.
