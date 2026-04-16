# ASCP Data Leakage Prevention (DLP) Module

A production-grade Data Leakage Prevention system designed to detect and prevent sensitive information leakage through language model outputs and tool interactions. The module combines pattern-based detection, cryptographic canary injection, and optional Named Entity Recognition to enforce configurable security policies.

## Overview

The DLP module operates as Layer C of the ASCP framework, providing real-time scanning and enforcement of data protection policies across three primary surfaces:

- **OUTPUT**: Language model generated text
- **TOOL_ARGS**: Tool parameters and arguments before execution
- **TOOL_RESULT**: Data returned from external tools

The system employs an advanced 10-layer detection pipeline across three categories of sensitive information:

1. **Secrets**: 
   - Exact pattern matching (OpenAI, AWS, GitHub)
   - **Shannon Entropy Detection** catches novel formats using mathematical randomness.
2. **Personally Identifiable Information (PII)**: 
   - Regex matching (Email, IPv4, Credit Cards)
   - **Luhn Algorithm Validation** massively reduces credit card false positives.
   - Optional **Named Entity Recognition (NER)** via spaCy.
3. **Canary Leaks & Intellectual Property**: 
   - Cryptographic canary token injection.
   - **Fuzzy Canary Matching** detects subtle token manipulation by LLMs.
   - **Document Fingerprinting** blocks verbatim reproduction of confidential RAG contexts.

Advanced processing capabilities include **Contextual Window Analysis** to downgrade examples/documentation safely, **Format-Preserving Redaction** to keep pipelines running, and **Structured Data Scanning** for precise JSON/dict path attribution.

## Design Philosophy

The DLP module prioritizes security, correctness, and observability:

- **Security-First**: Uses cryptographic randomness (`secrets` module) for canary generation. Prevents information leakage through placeholder patterns.
- **Explicit Policy Encoding**: All detection rules and enforcement decisions are defined in YAML configuration, enabling policy-as-code practices.
- **Comprehensive Telemetry**: Returns detailed violation information to enable proper auditing and incident response.
- **Composable Enforcement**: Supports multiple enforcement actions (ALLOW, REDACT, ESCALATE, BLOCK) with per-surface overrides.

## Installation

### Dependencies

```bash
pip install pyyaml  # Required for policy configuration
pip install spacy   # Optional, for Named Entity Recognition
python -m spacy download en_core_web_sm  # Optional, for NER
```

The module gracefully degrades if PyYAML or spaCy are unavailable, logging appropriate warnings.

### Setup

```python
import dlp

# Option 1: Use built-in defaults (no configuration file needed)
dlp.init()

# Option 2: Use custom policy file
from pathlib import Path
dlp.init(Path("policy.yaml"))  # See policy.default.yaml template
```

## Demo Secret Fixtures

The end-to-end demo uses secret-like test values to validate BLOCK behavior for secret leakage scenarios.

For safety, those values are loaded from a local file that is not committed:

1. Copy `dlp_demo_secrets_example.py` to `dlp_demo_secrets.py`
2. Edit `dlp_demo_secrets.py` with local test-only values
3. Run `python dlp_demo.py`

Notes:

- `dlp_demo_secrets.py` is gitignored and must stay local
- If the local file is missing, the demo still runs with placeholders and skips secret-dependent scenarios

## Configuration

The DLP system is configured via YAML policy files. **A complete default policy template is available at [`policy.default.yaml`](policy.default.yaml)** with comprehensive documentation for external developers.

### Optional YAML Configuration

If no custom policy file is provided to `dlp.init()`, the system automatically falls back to sensible built-in defaults that include:

- **Secrets Detection**: OpenAI, AWS, and GitHub token patterns
- **PII Detection**: Email addresses and IPv4 addresses
- **Canary Tokens**: Three example canary labels for tracking information leakage

This means you can use the DLP module without providing a configuration file:

```python
import dlp

# Uses built-in defaults automatically
dlp.init()  # No file needed; uses DLPConfig.defaults()
```

### Custom Policy Files

To customize enforcement actions, detection patterns, or canary labels, copy `policy.default.yaml` and modify it:

```python
from pathlib import Path
import dlp

# Initialize with custom policy
dlp.init(Path("policy.yaml"))
```

### Configuration Example

Here's a complete policy configuration (also fully documented in [`policy.default.yaml`](policy.default.yaml)):

```yaml
dlp:
  canary_action: BLOCK              # Action on canary leaks
  canary_salt: "production_salt_change_me"
  secrets_action: BLOCK             # Action on detected secrets
  pii_action: REDACT                # Action on detected PII
  enable_ner: true                  # Enable Named Entity Recognition
  
  canary_labels:
    - api_credential_mock
    - db_password
    - sys_admin_token
  
  secret_patterns:
    - name: openai_key
      regex: "sk-[A-Za-z0-9]{48}"
    - name: aws_access_key
      regex: "AKIA[0-9A-Z]{16}"
    - name: github_token
      regex: "ghp_[A-Za-z0-9]{36}"
  
  pii_patterns:
    - name: email
      regex: "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]*[a-zA-Z0-9-]"
    - name: ipv4
      regex: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    - name: credit_card
      regex: "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b"

  # Advanced Features (all strictly opt-in)
  luhn_validation: true
  format_preserving_redaction: true
  enable_structured_scan: false

  entropy:
    enabled: true
    threshold: 4.5
  
  context_analysis:
    enabled: true
    window: 50
    on_negation: downgrade

  canary_fuzzy_match: true
  canary_fuzzy_overlap: 0.8

  fingerprinting:
    enabled: true
    threshold: 0.3
```

### Configuration Validation

The loader performs validation checks:

- **Empty Pattern Lists**: If both `secret_patterns` and `pii_patterns` are empty, a CRITICAL log warning is issued to prevent silent degradation.
- **Missing Fields**: Unspecified fields use sensible defaults defined in `DLPConfig.defaults()`.
- **Import Errors**: PyYAML import failures are caught gracefully; the system logs a warning and uses default configuration.

## Public API

All functions are defined in `dlp/__init__.py` and require `init()` to be called first.

### Core Scanning Functions

#### `scan_output(text: str) -> EnforcementDecision`

Scans language model output for secrets, PII, and canary leaks.

```python
decision = dlp.scan_output("Here is my API key: sk-...")
if decision.should_block:
    return decision.safe_message  # User-friendly error message
```

#### `scan_tool_args(tool_name: str, args: dict[str, Any]) -> EnforcementDecision`

Scans tool arguments before execution. Tool arguments always receive stricter enforcement.

```python
decision = dlp.scan_tool_args("execute_query", {"password": "secret123"})
if decision.should_block:
    raise PermissionError(decision.safe_message)
```

#### `scan_tool_result(tool_name: str, result: dict[str, Any]) -> EnforcementDecision`

Scans tool results after execution. Results may receive different enforcement than outputs.

```python
decision = dlp.scan_tool_result("database_query", {"user_emails": [...]}
```

#### `inject_canaries_into_context(docs: list[dict[str, str]]) -> tuple[list[dict[str, str]], str | None, str | None]`

Injects cryptographic canary tokens into retrieved documents to detect unauthorized leakage.

```python
docs, token, label = dlp.inject_canaries_into_context(retrieved_documents)
# token: "CANARY-a1b2c3d4e5f6g7h8"
# label: "api_credential_mock"

# Pass docs to model. If model leaks the token, detection occurs in subsequent scan_output()
```

### EnforcementDecision Object

Contains the final policy determination:

```python
@dataclass
class EnforcementDecision:
    action: DLPAction                    # ALLOW, REDACT, ESCALATE, or BLOCK
    clean_text: str                      # Redacted or safe message text
    should_block: bool                   # True if request must be rejected
    should_escalate: bool                # True if human review required
    violations: list[str]                # Detected violation types
    safe_message: str | None             # User-facing message if blocked
    escalation_event: dict | None        # Data for review queue
    dlp_result: DLPResult | None         # Underlying scan results for telemetry
```

## Enforcement Actions

Actions are applied in priority order: `BLOCK > ESCALATE > REDACT > ALLOW`.

### ALLOW
No violation detected. Text passes through unchanged.

### REDACT
Non-critical PII detected. Matching spans are replaced with placeholders (`[REDACTED_category_pattern]`). Text is returned cleaned.

### ESCALATE
Policy violation detected but decision deferred to human review. The `escalation_event` dictionary contains detection details for a review queue. Output is blocked pending review.

### BLOCK
Critical violation (canary leak or secret) detected. Output is replaced with a safe message. No violation details are leaked to the user.

## Architecture

### Core Components

#### `models.py`
Defines core data structures and enumerations:

- `DLPAction`: Enum for enforcement actions
- `ScanSurface`: Enum for detection surfaces (OUTPUT, TOOL_ARGS, TOOL_RESULT)
- `DLPMatch`: Individual match detected by scanners
- `CanaryHit`: Canary token detection
- `DLPResult`: Aggregated scan results
- `EnforcementDecision`: Final policy decision

#### `config.py`
Configuration loading and validation:

- `DLPConfig`: Dataclass holding all configuration state
- `load_dlp_config()`: Loads and validates YAML policy files
- `_parse_action()`: Converts action strings to enums

Ensures empty pattern lists are detected and logged as CRITICAL warnings.

#### `canary.py`
Canary seed and detection:

- `CanaryEngine.seed()`: Initializes label-to-token mappings using SHA256 hashing
- `CanaryEngine.inject_into_context()`: Injects canary tokens into documents. Returns injected docs plus the injected token and label as a tuple for per-request tracking (avoiding shared mutable state).
- `CanaryEngine.detect()`: Scans text for known canary tokens
- `CanaryEngine.rotate_canaries()`: Regenerates token mappings (for periodic rotation)

Uses `secrets.choice()` and `secrets.randbelow()` for cryptographic randomness.

#### `patterns.py`
Regex-based pattern matching and redaction:

- `PatternEngine.scan_text()`: Scans text against configured patterns, returns matches and redacted text in a single pass
- `PatternEngine.apply_redactions()`: Static method for applying redactions with overlap merging
- `PatternEngine.scan_args()`: JSON-serializes tool arguments for comprehensive scanning

Overlapping matches are merged into a single `[REDACTED]` placeholder to prevent information leakage about detection overlap.

#### `ner.py`
Optional Named Entity Recognition via spaCy:

- `NERDetector.detect()`: Uses spaCy models to identify PERSON, ORG, GPE, LOC, DATE entities
- Graceful degradation: If spaCy is unavailable or models cannot be loaded, returns empty matches and logs warnings
- Lazy loading: Model is only loaded on first detection call

#### *Advanced Detectors* (`entropy.py`, `validators.py`, `context.py`, `fingerprint.py`, `structured.py`)
- `EntropyScanner`: Calculates Shannon entropy for catching novel secrets.
- `MatchValidator`: Runs Luhn checksums on credit cards.
- `ContextAnalyzer`: Suppresses non-critical matches surrounded by 'documentation' keywords.
- `DocumentFingerprinter`: Retains stateful word trigrams of injected context to block verbatim reproduction.
- `scan_dict()`: Recursively walks JSON tools/results for exact path attribution.

#### `scanner.py`
Orchestrates all detection engines:

- `DLPScanner.scan()`: Main entry point coordinating canary, regex, and NER scanning
- Short-circuit logic: Stops expensive NER scanning if canary or secret already detected
- Unified redaction: Collects all redaction spans (regex + NER) and applies in single pass to maintain offset correctness

#### `enforcer.py`
Policy enforcement and decision logic:

- `PolicyEnforcer.enforce()`: Combines scan results with policy overrides (e.g., TOOL_ARGS always blocks on secrets)
- Per-surface overrides: Different enforcement rules for different surfaces
- Safe messaging: Generates user-facing messages without leaking violation details
- Escalation routing: Creates escalation event payloads for review queues

#### `messenger.py`
User-facing message generation:

- `SafeMessenger.get_message()`: Returns appropriate safe messages based on action and surface
- Surface-aware: TOOL_ARGS/TOOL_RESULT return structured codes; OUTPUT returns polite user messages
- No information leakage: Messages never contain matched values or violation details

### Data Flow

```text
Input Text / Tool Dictionary
    ↓
DLPScanner.scan_structured()
    ├→ Structured Walk (JSON elements)
    │   ├→ PatternEngine.scan() (Regex)
    │   ├→ MatchValidator.filter() (Luhn validation)
    │   ├→ ContextAnalyzer.filter() (Window suppression)
    │   └→ EntropyScanner.scan() (Shannon entropy)
    ├→ Global String Pass
    │   ├→ CanaryEngine.detect() (Exact + Fuzzy)
    │   ├→ NERDetector.detect() (Optional spaCy)
    │   └→ DocumentFingerprinter.scan() (Verbatim checks)
    ↓
    Collect all violations (with precise JSON paths) and redactions
    ↓
    Apply unified redaction / Format-preserving placeholders
    ↓
DLPResult
    ↓
PolicyEnforcer.enforce()
    ↓
SafeMessenger.get_message()
    ↓
EnforcementDecision
```

## Testing

### Run All Tests

```bash
pytest dlp/tests -v
```

### Run with Coverage

```bash
pytest dlp/tests -v --cov=dlp --cov-report=term-missing
```

### Test Suites

- **test_canary.py**: Canary injection, detection, and rotation
- **test_config.py**: Configuration loading with valid and empty patterns
- **test_integration.py**: End-to-end scanning workflows including canary leaks and NER paths
- **test_messenger.py**: Safe message generation for all action types
- **test_patterns.py**: Regex pattern matching and redaction logic

All tests use the public API; no tests access private attributes.

## Recent Improvements

### Critical Fixes

1. **Re-initialization Support**: Removed early-return guard in `init()` allowing proper re-initialization with different policies in tests.

2. **Escalation Logic**: Fixed overly broad escalation check. `should_escalate` now correctly triggers only on ESCALATE action, not BLOCK.

3. **Canary Concurrency**: Removed shared mutable state (`_last_injected`). `inject_into_context()` now returns the injected token directly, enabling proper per-request tracking.

4. **Cryptographic Randomness**: Replaced `random` module with `secrets` for canary token selection and document injection.

### Security Improvements

5. **Configurable Canary Labels**: Canary labels now loaded from configuration, enabling decentralized policy management.

6. **Configuration Validation**: Empty pattern lists trigger CRITICAL warnings, preventing silent security degradation.

7. **Unified Redaction**: NER and regex matches processed in single pass using span-based replacement, preventing unintended global string replacements.

8. **Placeholder Standardization**: Changed `[REDACTED_multiple]` to single `[REDACTED]` to prevent information leakage about match overlaps.

### Code Quality

9. **Modern Type Hints**: Updated to Python 3.9+ syntax (`list[...]`, `str | None` instead of `List[...]`, `Optional[str]`).

10. **Graceful Degradation**: PyYAML import moved inside function with proper exception handling.

11. **Rich Telemetry**: `EnforcementDecision` now includes `dlp_result` for complete violation information without requiring double queries.

## Module Integration

This module is designed for integration into the ASCP framework:

- Self-contained structure minimizes root-level conflicts
- Policy-as-code approach enables centralized governance
- **Optional configuration**: Works with built-in defaults if no custom policy provided
- Detailed violation telemetry supports Layer D auditing
- Per-surface enforcement enables nuanced policy implementation

### Initialization Options

**For development or quick start**: Use built-in defaults

```python
from pathlib import Path
import dlp

# Application startup - uses built-in defaults
dlp.init()
```

**For production deployments**: Provide a custom policy file

```python
from pathlib import Path
import dlp

# Copy policy.default.yaml to your deployment location, customize as needed
dlp.init(Path("config/policy.yaml"))
```

See [`policy.default.yaml`](policy.default.yaml) for all available configuration options and production deployment guidelines.

## Development Guidelines

### Adding New Pattern Types

1. Define regex pattern in `policy.yaml`
2. Run tests to ensure no regressions
3. All patterns are category-tagged (secret/pii)

### Adding New NER Entity Types

1. Update `pii_labels` set in `ner.py`
2. Ensure spaCy model supports the entity type
3. Add test case with mocked detection

### Adding New Enforcement Actions

1. Extend `DLPAction` enum in `models.py`
2. Update `PolicyEnforcer.enforce()` logic
3. Update `SafeMessenger.get_message()` with appropriate messages
4. Add test cases covering new action

## Performance Considerations

- Canary injection uses deterministic SHA256 hashing (not cryptographic generation) for token derivation from labels, enabling consistency without state storage
- NER is only executed if canary and secret checks pass, reducing expensive model calls
- Pattern matching is short-circuited at BLOCK level
- All redactions applied in single pass to minimize string operations

## License and Repository

This module is part of the ASCP project.

Repository: https://github.com/MohamedLouayChatti/ASCP

Branch: DLP
