# ASCP DLP Module

Layer C Data Leakage Prevention module for ASCP.

## Scope

This folder is intentionally self-contained so it can be merged into larger ASCP repositories with minimal root-level conflicts.

## Public API

Defined in `dlp/__init__.py`:

- `scan_output(text)`
- `scan_tool_args(tool_name, args)`
- `scan_tool_result(tool_name, result)`
- `inject_canaries_into_context(docs)`

## Run Tests

From repository root:

```bash
python -m pytest dlp/tests -v
```

With coverage:

```bash
python -m pytest dlp/tests -v --cov=dlp --cov-report=term-missing
```

## Architecture

- `models.py`: core types and actions
- `config.py`: config loading and defaults
- `canary.py`: canary seed/inject/detect/rotate
- `patterns.py`: regex scanners and redaction
- `ner.py`: optional lazy-loaded spaCy detector
- `scanner.py`: orchestrates all scanners
- `enforcer.py`: final policy decisioning
- `messenger.py`: safe user-facing policy messages
- `tests/`: module unit + integration tests

## Integration Notes

In a monorepo, keep root CI/build files owned by the platform repository. If needed, adapt templates from `dlp/ci/` into root-level workflows.
