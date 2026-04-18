# DLP Module — Development Guide

## Philosophy

This branch defines a complete, 5-step ML-enhanced scanning architecture optimised for ASCP security operations. The guiding principle is **defence in depth via layering**: fast deterministic rules catch known-bad patterns cheaply, while the ML layer handles ambiguous or novel content that regexes cannot reliably classify.

Development effort should be prioritised in this order:
1. **Pattern rules** (`patterns.py`, `policy.default.yaml`) — highest ROI, zero ML cost.
2. **Feature extraction** (`features.py`) — improves ML signal without retraining.
3. **LoRA adapter** (`ML/train.ipynb`) — last resort; retraining is expensive.
4. **Core enforcer** (`enforcer.py`) — rarely needs touching; all logic is config-driven.

---

## Local Setup

### Core (required)

```bash
pip install -r requirements.txt
```

### Development tools (linting, testing, coverage)

```bash
pip install -r requirements-dev.txt
```

### ML stack (required for Steps 3 & 4)

```bash
pip install torch transformers peft bitsandbytes accelerate
```

### HuggingFace credentials

The base model (`google/gemma-2-2b-it`) is downloaded automatically on first run. You must authenticate first:

```bash
huggingface-cli login
# or: export HF_TOKEN="your_token"
```

The LoRA adapter is bundled locally at `dlp/ML/dlp_lora_package/` — no additional download needed.

---

## Pipeline Architecture

```
Input Text + Surface
       │
       ▼
┌──────────────────────┐
│  1. Canary Engine    │  ── Hit → BLOCK (hard stop, no ML)
│     canary.py        │
└──────────┬───────────┘
           │ Clean
           ▼
┌──────────────────────┐
│  2. Pattern Engine   │  ── ALLOW / BLOCK / REDACT / ESCALATE
│     patterns.py      │     → short-circuit to Step 5
│     validators.py    │
│     context.py       │
└──────────┬───────────┘
           │ PASS_TO_ML
           ▼
┌──────────────────────┐
│  3. Feature          │
│     Extraction       │
│     features.py      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  4. ML Classification│  ── ALLOW / REDACT / ESCALATE / BLOCK
│     ml.py            │
│     (Gemma-2 + LoRA) │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────────────┐
│  5. Policy Enforcer              │
│     enforcer.py                  │
│     (applies surface_overrides)  │
└──────────────────┬───────────────┘
                   │
                   ▼
           EnforcementDecision
```

### File map

| File | Role |
|---|---|
| `__init__.py` | Public API: `init`, `inject_*`, `scan_*` |
| `models.py` | Data classes: `DLPAction`, `DLPResult`, `EnforcementDecision`, etc. |
| `config.py` | `DLPConfig` dataclass + `load_dlp_config()` YAML loader |
| `canary.py` | `CanaryEngine`: token generation, injection, exact + fuzzy detection |
| `patterns.py` | `PatternEngine`: regex matching, redaction, format-preserving substitution |
| `validators.py` | `MatchValidator`: Luhn algorithm for credit card false-positive elimination |
| `context.py` | `ContextAnalyzer`: window-based trigger/negation analysis |
| `features.py` | `extract_features()`: entropy, entity counts, structural signals |
| `ml.py` | `MLInferenceEngine` singleton + `classify()` entry point |
| `enforcer.py` | `PolicyEnforcer`: applies per-surface overrides from config |
| `scanner.py` | `DLPScanner`: orchestrates Steps 1–4, returns `DLPResult` |
| `messenger.py` | `SafeMessenger`: generates safe user-facing block messages |

---

## Modifying the Pipeline

### Tweaking Pattern Rules (`patterns.py` / `policy.default.yaml`)

Add a new entry under `secret_patterns` or `pii_patterns` in the YAML:

```yaml
secret_patterns:
  - name: my_custom_token
    regex: "MYPREFIX-[A-Za-z0-9]{20}"
    action: BLOCK
```

Pattern-level `action` overrides the global `secrets_action` / `pii_action` for that specific pattern. Use `PASS_TO_ML` to defer ambiguous patterns to the ML layer.

### Tweaking Feature Extraction (`features.py`)

`extract_features()` returns a flat dict of numeric/boolean signals. Adding a new key here makes it available to the ML prompt in `ml.py` automatically. New signals guide the model without requiring LoRA retraining — prefer this over retraining whenever possible.

Example: detecting implicit nested JSON structure or specialised log patterns is achievable by adding regex checks to `extract_features()`.

### Bypassing ML for Fast Iteration

If you are iterating on regex rules or config behaviour and do not want to load ~1.5 GB of model weights:

- **Option A**: Do not install `torch` / `transformers`. The scanner detects their absence at import time and skips Steps 3 and 4 entirely, logging a warning.
- **Option B**: Set `unmatched_action: ALLOW` in your YAML. Unmatched text will be allowed without invoking ML.

The scanner always executes Steps 1, 2, and 5 regardless of ML availability.

### Retraining the LoRA Adapter

Use `dlp/ML/train.ipynb`. Training data is in `dlp/ML/data/dlp_ml_dataset.jsonl`. The base model must remain `google/gemma-2-2b-it` to match the bundled adapter configuration. After training, replace the contents of `dlp/ML/dlp_lora_package/` and update `adapter_config.json` if hyperparameters changed.

---

## Testing

```bash
# Run all tests
python -m pytest dlp/tests -v

# Run with coverage (HTML + terminal)
python -m pytest dlp/tests -v --cov=dlp --cov-report=term-missing --cov-report=html
```

Test files and what they cover:

| Test file | Covers |
|---|---|
| `test_canary.py` | Canary injection, exact detection, block path |
| `test_canary_fuzzy.py` | Fuzzy/normalised canary matching |
| `test_config.py` | YAML loading, defaults, surface overrides |
| `test_context.py` | Contextual window trigger/negation logic |
| `test_format_preserving.py` | Format-preserving redaction output |
| `test_integration.py` | End-to-end scan → enforce paths; ML tests run if `torch` is available |
| `test_messenger.py` | Safe message generation |
| `test_models.py` | `DLPAction` priority ordering, dataclass behaviour |
| `test_patterns.py` | Regex matching, PASS_TO_ML routing |
| `test_validators.py` | Luhn algorithm correct/incorrect card numbers |

Integration tests auto-detect `torch` availability. When the ML stack is present, the test runner exercises the full 5-step path with quantised model inference. When absent, only Steps 1, 2, and 5 are exercised.

---

## CI

The GitHub Actions workflow lives at `dlp/ci/workflows/tests.yml`. It runs `pytest` with coverage on every push and pull request.