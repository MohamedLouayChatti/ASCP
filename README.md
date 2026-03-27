# ASCP: Agent Security Control Plane

A security-first, real-time evaluation, enforcement, and testing platform for RAG and agent-based LLM systems. ASCP treats LLM outputs, retrieval, and tool use as untrusted by default, detecting and preventing security violations at runtime (online) and development time (CI).

## Quick Start

### Installation (Development)

```bash
# Clone and navigate
git clone https://github.com/MohamedLouayChatti/ASCP.git
cd ASCP

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with test dependencies
pip install -e ".[dev]"
```

### Run Tests

```bash
# Run all tests with coverage
pytest dlp/tests/ -v --cov=dlp --cov-report=term-missing
```

### View API Documentation

The main public API of the DLP module is in `dlp/__init__.py`:

```python
from dlp import (
    scan_output,           # Scan final LLM output
    scan_tool_args,        # Scan tool arguments pre-execution
    scan_tool_result,      # Scan tool results post-execution
    inject_canaries_into_context  # Embed canary tokens in retrieval context
)
```

## Architecture Overview

```
User Query
    ↓
RAG / Agent System (Retriever + Generator + Tools)
    ↓
ASCP Security & Evaluation Control Plane
└─ Layer A: Real-Time RAG Evaluation (EVAL)
└─ Layer B: Typed Tool Security Contracts (C1)
└─ Layer C: Data Leakage + Policy Guard (DLP+POLICY) ← This module
└─ Layer D: Telemetry + Risk Scoring (OPS)
    ↓
Response / Action (Allowed | Blocked | Escalated)
```

### Layer C (DLP): What This Module Does

**Data Leakage Prevention (DLP)** scans three surfaces:
1. **OUTPUT**: Final LLM response before returning to user
2. **TOOL_ARGS**: Tool arguments before execution
3. **TOOL_RESULT**: Tool output before passing back to agent

**Detection Methods**:
- **Canary Tokens**: Deterministic tokens injected into retrieval context to catch leakage
- **Secret Scanning**: Pattern matching for API keys, credentials, etc.
- **PII Detection**: Regex-based + optional spaCy NER for personally identifiable information

**Actions**:
- **BLOCK**: Reject and return safe message
- **REDACT**: Remove sensitive data and continue
- **ESCALATE**: Flag for human review + continue
- **ALLOW**: Pass through unchanged

## CI/CD Pipeline

Tests run automatically on GitHub Actions for every push and pull request:

- **Test Matrix**: Python 3.9, 3.10, 3.11, 3.12
- **Coverage**: Full coverage reports with per-module breakdown
- **Code Quality**: Black, isort, flake8, mypy checks
- **Integration Tests**: Full end-to-end workflow validation

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed development guidelines.

## Project Structure

```
dlp/
├── __init__.py          ← Public API (scan_output, scan_tool_args, scan_tool_result)
├── models.py            ← Type definitions (DLPResult, DLPMatch, etc.)
├── config.py            ← Policy YAML loading (DLPConfig)
├── canary.py            ← CanaryEngine for token injection & leakage detection
├── patterns.py          ← PatternEngine for regex-based scanning
├── ner.py               ← NERDetector (optional spaCy integration)
├── scanner.py           ← DLPScanner orchestration
├── enforcer.py          ← PolicyEnforcer for per-surface decisions
├── messenger.py         ← SafeMessenger for secure error messages
└── tests/               ← Comprehensive test suite (12 tests, 79% coverage)
```

## Configuration

Create a `policy.yaml` to configure DLP behavior:

```yaml
dlp:
  canary_action: block
  canary_salt: "your-secret-salt"
  secrets_action: block
  pii_action: redact
  enable_ner: false
  
  secret_patterns:
    - name: openai_key
      regex: "sk-[A-Za-z0-9]{48}"
    - name: aws_access_key
      regex: "AKIA[0-9A-Z]{16}"
  
  pii_patterns:
    - name: email
      regex: "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+"
    - name: phone
      regex: "\\b(?:\\d{1,3}[-.]?){2}\\d{4}\\b"
```

## Example Usage

```python
from dlp import scan_output, scan_tool_args, scan_tool_result, inject_canaries_into_context

# Inject canaries into retrieved documents
docs = [{"title": "doc1", "text": "some content"}]
injected_docs = inject_canaries_into_context(docs)

# Scan LLM output for leakage
llm_output = "The answer is..."
decision = scan_output(llm_output)
if decision.should_block:
    return decision.safe_message

# Scan tool arguments pre-execution
args = {"email": "user@example.com", "api_key": secret_key}
decision = scan_tool_args("send_email", args)
if decision.should_block:
    raise PermissionError(decision.safe_message)

# Scan tool results post-execution
result = tool_result  # { "status": "ok", "user_data": {...} }
decision = scan_tool_result("get_user", result)
return decision.clean_text  # Safely redacted result
```

## Test Coverage

Current coverage: **79%** across all modules

```
dlp/canary.py    96% ✅
dlp/enforcer.py  96% ✅
dlp/patterns.py  94% ✅
dlp/models.py    91% ✅
dlp/scanner.py   79%
dlp/config.py    68%
dlp/messenger.py 65%
dlp/ner.py       30% (optional, lazy-loaded)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Local development setup
- Running tests locally
- Code quality tools
- Git workflow
- PR guidelines

## License

MIT

## Questions?

Open an issue on GitHub or contact the ASCP team.
