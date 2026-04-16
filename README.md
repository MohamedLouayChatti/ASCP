# ASCP Data Leakage Prevention (DLP) Module (v0.1.0)

A production-grade Data Leakage Prevention system designed to detect and prevent sensitive information leakage through language model outputs and tool interactions. The module combines deterministic pattern-based detection, cryptographic canary injection, mathematical feature extraction, and a locally-hosted fine-tuned Large Language Model to enforce configurable security policies.

## Overview

The DLP module operates as **Layer C** of the ASCP framework, providing real-time scanning and enforcement of data protection policies across three primary scan surfaces:

- **`OUTPUT`**: Language model generated text (scanned before returning to the user)
- **`TOOL_ARGS`**: Tool parameters and arguments (scanned before execution)
- **`TOOL_RESULT`**: Data returned from external tools (scanned before the agent sees it)

### The 5-Step Pipeline Architecture

The system employs an advanced 5-step detection pipeline that intelligently routes text from fast, deterministic checks to complex ML-based classification. Steps 3 and 4 are only reached when the deterministic layers cannot reach a definitive decision.

```
┌─────────────────────────────────────────────────────────────────────┐
│                      DLP Scanner Pipeline                           │
│                                                                     │
│  Input Text + Surface                                               │
│         │                                                           │
│         ▼                                                           │
│  ┌─────────────────┐   Canary Hit    ┌──────────────┐               │
│  │ 1. Canary Engine│────────────────►│ BLOCK (hard) │               │
│  └────────┬────────┘                 └──────────────┘               │
│           │ Clean                                                   │
│           ▼                                                         │
│  │ 2. Pattern      │  /REDACT/       │ Return Pattern Action    │   │
│  ┌─────────────────┐   ALLOW/BLOCK   ┌──────────────────────────┐   │
│  │    Engine       │  ESCALATE ─────►│ (short-circuits ML)      │   │
│  └────────┬────────┘                 └──────────────────────────┘   │
│           │ PASS_TO_ML                                              │
│           ▼                                                         │
│  ┌─────────────────┐                                                │
│  │ 3. Feature      │                                                │
│  │    Extraction   │                                                │
│  └────────┬────────┘                                                │
│           │                                                         │
│           ▼                                                         │
│  ┌─────────────────┐                                                │
│  │ 4. ML           │  ALLOW/REDACT/                                 │
│  │    Classification│  ESCALATE/BLOCK                               │
│  └────────┬────────┘                                                │
│           │                                                         │
│           ▼                                                         │
│  ┌─────────────────────────────────────┐                            │
│  │ 5. Policy Enforcer                  │                            │
│  │    (applies surface overrides)      │                            │
│  └────────────────┬────────────────────┘                            │
│                   │                                                 │
└───────────────────┼─────────────────────────────────────────────────┘
                    │
                    ▼
            Final EnforcementDecision
        (action, clean_text, should_block, …)
```

**Step 1 — Canary Engine**: Detects cryptographic canary tokens injected into system prompts, RAG documents, or tool results. Acts as a hard-stop early exit — any exact or fuzzy match immediately returns `BLOCK`, bypassing all further processing.

**Step 2 — Pattern Engine**: Executes deterministic regex rules for Secrets and PII. Optionally runs contextual window analysis (to downgrade documentation/example matches) and Luhn algorithm validation (to eliminate credit card false positives). If a pattern's action is `ALLOW`, `BLOCK`, `REDACT`, or `ESCALATE`, the result short-circuits directly to Step 5. Only patterns with action `PASS_TO_ML` proceed further.

**Step 3 — Feature Extraction**: Extracts quantitative signals from the text — entity counts, Shannon entropy scores, structural patterns, and surface context — that serve as inputs to the ML classifier.

**Step 4 — ML Classification**: Uses a locally-hosted fine-tuned `google/gemma-2-2b-it` model with a task-specific LoRA adapter to produce a final `ALLOW`, `REDACT`, `ESCALATE`, or `BLOCK` decision based on the text and extracted features. Lazy-loaded — only instantiated on first use.

**Step 5 — Policy Enforcer**: The `PolicyEnforcer` applies per-surface overrides defined in `policy.default.yaml`. Overrides can only escalate the action (e.g. forcing `BLOCK` on `TOOL_ARGS`) — they can never silently downgrade a `BLOCK`. The `downgrade_escalate_to_redact` flag on `TOOL_RESULT` is the only permitted downgrade, and only applies to PII-only findings.

### ML Integration (Gemma-2)

The ML backend is a locally-hosted inference engine built on **Gemma-2 2B**:

- **LoRA Adapter**: A custom fine-tuned adapter (`dlp/ML/dlp_lora_package/`) is merged on top of the base model at load time.
- **Quantization**: Runs in 4-bit NF4 (via `bitsandbytes`), keeping VRAM/RAM usage below ~6 GB.
- **Graceful Degradation**: Heavy dependencies (`torch`, `transformers`, `peft`, `bitsandbytes`) are lazy-loaded on first classification. If they are unavailable, the module operates on Steps 1, 2, and 5 only — no crash, no silent failure, just a log message.

## Installation

### Production / Core Only

```bash
pip install pyyaml>=6.0
```

PyYAML is the only hard runtime dependency. Everything else is optional.

### With ML Classification (Steps 3 & 4)

```bash
pip install torch transformers peft bitsandbytes accelerate
# Optional: faster HuggingFace downloads
pip install hf-transfer
```

The base model (`google/gemma-2-2b-it`, ~1.5 GB) is downloaded automatically from HuggingFace on the first classification call. A HuggingFace account with model access is required:

```bash
huggingface-cli login
# or: export HF_TOKEN="your_token"
```

## Quick Setup

```python
import dlp

# Option 1: Built-in defaults (no configuration file needed)
dlp.init()

# Option 2: Load from a YAML policy file
from pathlib import Path
dlp.init(Path("policy.default.yaml"))

# Option 3: Pass a DLPConfig object directly
from dlp.config import DLPConfig
dlp.init(DLPConfig.defaults())
```

## Core API

### Canary Injection (call BEFORE the LLM)

```python
# Inject into system prompt
modified_prompt, token, label = dlp.inject_canary_into_system_prompt(system_prompt)

# Inject into RAG context documents
modified_docs, token, label = dlp.inject_canaries_into_context(docs)

# Inject into a tool result before the agent sees it
modified_result, token, label = dlp.inject_canary_into_tool_result("my_tool", result)
```

### Scanning (call AFTER the LLM / BEFORE tool execution)

```python
# Scan LLM output before returning to the user
decision = dlp.scan_output(llm_response_text)

# Scan tool arguments before executing
decision = dlp.scan_tool_args("database_query", {"query": "SELECT ..."})

# Scan tool results before passing back to the agent
decision = dlp.scan_tool_result("my_tool", tool_result_data)

if decision.should_block:
    return decision.safe_message  # safe, generic error string

if decision.action.name == "REDACT":
    return decision.clean_text    # sensitive fields replaced with [REDACTED_...]

if decision.should_escalate:
    handle_escalation(decision.escalation_event)
```

## Advanced Features

| Feature | Config Key | Default |
|---|---|---|
| Luhn validation for credit cards | `luhn_validation` | `false` |
| Contextual window analysis | `context_analysis.enabled` | `false` |
| Format-preserving redaction | `format_preserving_redaction` | `false` |
| Fuzzy canary matching | `canary_fuzzy_match` | `false` |
| Per-surface action overrides | `surface_overrides` | see YAML |

All advanced features default to `false`. Enable them selectively in `policy.default.yaml`.

## Testing & Demo

```bash
# Run all tests
python -m pytest dlp/tests -v

# Run with coverage
python -m pytest dlp/tests -v --cov=dlp --cov-report=term-missing

# Run the interactive demo
# 1. Copy the secrets example file and populate it
cp dlp_demo_secrets_example.py dlp_demo_secrets.py
# 2. Edit dlp_demo_secrets.py with your test values
# 3. Run the demo
python dlp_demo.py
```