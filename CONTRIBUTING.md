# Contributing to ASCP

Thank you for contributing to ASCP (Agent Security Control Plane)! This document explains our development workflow and CI/CD pipeline.

## Local Development Setup

### Prerequisites
- Python 3.9+
- pip or your preferred package manager
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/MohamedLouayChatti/ASCP.git
   cd ASCP
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install the package in development mode with test dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Verify installation**
   ```bash
   pytest dlp/tests/ -v
   ```

## Running Tests Locally

### Run all tests
```bash
pytest dlp/tests/ -v
```

### Run tests with coverage report
```bash
pytest dlp/tests/ -v --cov=dlp --cov-report=term-missing --cov-report=html
```

This generates a full HTML coverage report in `htmlcov/index.html`.

### Run specific test file
```bash
pytest dlp/tests/test_integration.py -v
```

### Run specific test
```bash
pytest dlp/tests/test_integration.py::TestIntegration::test_canary_injection_and_detection -v
```

### Mark tests
Tests can be marked with labels (see `pyproject.toml`):
```bash
# Run only unit tests
pytest -v -m "unit"

# Run only integration tests
pytest -v -m "integration"

# Skip integration tests
pytest -v -m "not integration"
```

## Code Quality

### Code formatting with Black
```bash
black dlp --diff           # Preview changes
black dlp                  # Apply formatting
```

### Import sorting with isort
```bash
isort dlp --diff           # Preview changes
isort dlp                  # Apply sorting
```

### Type checking with mypy
```bash
mypy dlp --ignore-missing-imports
```

### Linting with flake8
```bash
flake8 dlp
```

## Continuous Integration (GitHub Actions)

### What runs automatically

The CI pipeline is defined in `.github/workflows/tests.yml` and runs automatically on:
- **Push** to `main`, `DLP`, or `develop` branches
- **Pull Request** to `main`, `DLP`, or `develop` branches

### What the CI pipeline does

1. **Test Matrix** (runs in parallel)
   - Tests across Python versions: 3.9, 3.10, 3.11, 3.12
   - Each version runs full test suite
   - Automatically caches pip dependencies for speed
   - Generates coverage XML for each run

2. **Code Quality Job**
   - Runs Black formatting check
   - Runs isort import check
   - Runs mypy type checking (non-blocking)

3. **Integration Tests Job**
   - Runs end-to-end integration tests
   - Validates the public DLP API (`scan_output`, `scan_tool_args`, `scan_tool_result`)

### CI Status Checks
- All tests must pass before merging to `main`
- Coverage reports are uploaded to Codecov (optional - available in PR comments)
- Code quality checks are informational but should be addressed

### View CI Results

1. **In GitHub**: Go to the pull request → **Checks** tab to see all workflow runs
2. **Real-time**: Click **Details** next to a failed check to see detailed logs

## Before Submitting a PR

1. **Run tests locally**
   ```bash
   pytest dlp/tests/ -v --cov=dlp
   ```

2. **Format your code**
   ```bash
   black dlp
   isort dlp
   ```

3. **Fix linting issues**
   ```bash
   flake8 dlp
   ```

4. **Run type checks** (non-blocking but good to know)
   ```bash
   mypy dlp --ignore-missing-imports
   ```

5. **Push to your branch and open a PR**

## Troubleshooting

### Tests fail locally but pass in CI
- Ensure you're on the same Python version as the CI
- Run `pip install -e ".[dev]"` to reinstall dependencies
- Check the exact error message in CI logs

### Import errors when running tests
- Ensure you're in the virtual environment
- Try: `export PYTHONPATH="." && pytest dlp/tests/`

### Coverage report differs between local and CI
- CI runs across multiple Python versions; check the Python version you're using locally
- Use `pytest --cov=dlp --cov-report=xml` to match CI exactly

## Project Structure

```
ASCP/
├── .github/workflows/          # GitHub Actions CI configuration
│   └── tests.yml              # Main test workflow
├── dlp/                        # Data Leakage Prevention module (main code)
│   ├── __init__.py            # Public API: scan_output, scan_tool_args, etc.
│   ├── models.py              # Core type definitions
│   ├── config.py              # DLPConfig and policy loading
│   ├── canary.py              # CanaryEngine for leakage detection
│   ├── patterns.py            # PatternEngine for regex-based scanning
│   ├── ner.py                 # Optional NERDetector for advanced PII
│   ├── scanner.py             # DLPScanner orchestration
│   ├── enforcer.py            # PolicyEnforcer for decision-making
│   ├── messenger.py           # SafeMessenger for secure error messages
│   └── tests/                 # Test suite
│       ├── test_canary.py
│       ├── test_patterns.py
│       ├── test_integration.py
│       └── test_messenger.py
├── pyproject.toml             # Package metadata & tool configuration
├── .gitignore                 # Git ignore rules
└── README.md                  # Project documentation
```

## Configuration Files

### `pyproject.toml`
Defines:
- **Project metadata**: name, version, description, authors
- **Dependencies**: core (`pyyaml`) and optional (`spacy` for NLP, `pytest` for testing)
- **Tool configs**: pytest, black, isort, mypy, coverage
- **Build system**: setuptools + wheel

## Common Issues

### "ModuleNotFoundError: No module named 'dlp'"

**Cause**: The package isn't installed.

**Solution**:
```bash
pip install -e ".[dev]"
```

### Tests run fine locally but fail in CI

**Possible causes**:
- Python version mismatch
- Missing dependency for optional features
- Platform-specific code path (Windows vs Linux)

**How to debug**: Run the exact same Python version as CI:
```bash
python3.11 -m pytest dlp/tests/ -v
```

### Coverage lower in CI than locally

**Cause**: CI runs multiple Python versions and may have platform-specific skips.

**Solution**: Check the specific CI job logs to see coverage breakdown by version.

## Security Notes

- Never commit secrets, API keys, or credentials
- The `.gitignore` file covers common Python artifacts and virtual environments
- Coverage reports are public; don't include sensitive data in test fixtures

## Questions?

Open an issue or contact the ASCP team. Thank you for contributing! 🚀
