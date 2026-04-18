# DLP Module — ASCP Integration Guide

## Overview

The DLP module acts as **Layer C: Data Leakage & Policy Guard** of the ASCP Security Control Plane. It intercepts content at two critical boundaries in the LLM request lifecycle:

1. **Pre-LLM** — injecting cryptographic canary tokens into sensitive internal contexts (system prompt, RAG documents, tool results) so any verbatim leakage is immediately detectable.
2. **Post-LLM / Pre-tool** — scanning LLM outputs and tool arguments for secrets, PII, and canary echoes before they leave the trusted perimeter.

```
┌─────────┐        ┌──────────────────┐        ┌───────────────────┐
│  User   │        │ LLM Orchestrator │        │   DLP Module      │
│         │        │                  │        │   (Layer C)       │
└────┬────┘        └────────┬─────────┘        └────────┬──────────┘
     │                      │                           │
     │   Request            │                           │
     │─────────────────────►│                           │
     │                      │                           │
     │              ┌───────▼───────────────────────────▼──────────┐
     │              │  PRE-EXECUTION: Context Preparation           │
     │              │                                               │
     │              │  System prompt / RAG docs / tool results      │
     │              │  ──────────────────────────────────────────►  │
     │              │  inject_canary_into_system_prompt()           │
     │              │  inject_canaries_into_context()               │
     │              │  inject_canary_into_tool_result()             │
     │              │  ◄──────────── instrumented content ─────────  │
     │              └───────────────────────────────────────────────┘
     │                      │
     │              LLM receives instrumented context
     │                      │
     │                      │  LLM generates output / tool call
     │                      │
     │              ┌───────▼───────────────────────────▼──────────┐
     │              │  POST-EXECUTION: Output & Tool Scan           │
     │              │                                               │
     │              │  LLM output text                              │
     │              │  ──────────────────────────────────────────►  │
     │              │  scan_output()  ─►  5-Step Pipeline           │
     │              │  ◄──────────── EnforcementDecision ──────────  │
     │              │                                               │
     │              │  Tool arguments (before execution)            │
     │              │  ──────────────────────────────────────────►  │
     │              │  scan_tool_args()  ─►  5-Step Pipeline        │
     │              │  ◄──────────── EnforcementDecision ──────────  │
     │              └───────────────────────────────────────────────┘
     │                      │
     │              if BLOCK: return safe_message
     │              if REDACT: return clean_text
     │              if ALLOW: return original text
     │                      │
     │◄─────────────────────│
     │  Response
```

---

## Installation

### Core runtime dependency

```bash
pip install pyyaml>=6.0
```

### Optional: ML Classification (Steps 3 & 4)

```bash
pip install torch transformers peft bitsandbytes accelerate
```

The base model (`google/gemma-2-2b-it`, ~1.5 GB) is downloaded automatically on first use. Authenticate with HuggingFace first:

```bash
huggingface-cli login
# or: export HF_TOKEN="your_token"
```

---

## Initialization

Call `dlp.init()` once at application startup, before any LLM calls:

```python
import dlp
from pathlib import Path

# Option A: Use built-in defaults (no config file required)
dlp.init()

# Option B: Load from your YAML policy file
dlp.init(Path("policy.default.yaml"))

# Option C: Pass a DLPConfig object directly
from dlp.config import load_dlp_config
dlp.init(load_dlp_config(Path("policy.default.yaml")))
```

If `init()` is never called explicitly, the first scan or injection call triggers auto-initialization with built-in defaults.

### Lazy Loading & Graceful Degradation

The ML stack is only imported when the first PASS_TO_ML classification is needed. If `torch` or `transformers` are missing, the pipeline automatically skips Steps 3 and 4 and falls back to the Pattern Engine result. Your application will never crash because of a missing ML dependency.

---

## Canary Injection

Inject canaries into all sensitive internal content **before** the LLM sees it. Each injection plants a unique cryptographic token derived from your `canary_salt` and a randomly-chosen label. If the model echoes the token in any output or tool argument, the scanner immediately returns `BLOCK`.

```python
import dlp

# 1. System prompt injection (once per request)
modified_prompt, token, label = dlp.inject_canary_into_system_prompt(system_prompt)
# Pass modified_prompt to the LLM — keep token/label for your audit log

# 2. RAG document injection (after retrieval, before passing to LLM)
modified_docs, token, label = dlp.inject_canaries_into_context(retrieved_docs)
# retrieved_docs is a list[dict]; one document is chosen and modified in-place

# 3. Tool result injection (after tool executes, before agent sees result)
modified_result, token, label = dlp.inject_canary_into_tool_result("my_tool", raw_result)
# Pass modified_result to the agent instead of raw_result
```

---

## Scanning

### LLM Output

```python
decision = dlp.scan_output(llm_response_text)

if decision.should_block:
    # Return safe_message to the user — never return the original text
    return {"error": decision.safe_message}

if decision.action.name == "REDACT":
    # Return the sanitised version with sensitive fields replaced
    return {"content": decision.clean_text}

if decision.should_escalate:
    # Log for human review; decide whether to pass through or hold
    audit_queue.send(decision.escalation_event)

# ALLOW: return original
return {"content": llm_response_text}
```

### Tool Arguments

```python
decision = dlp.scan_tool_args("database_query", {"query": sql, "params": params})

if decision.should_block:
    raise PermissionError(decision.safe_message)

if decision.action.name == "REDACT":
    # Re-parse clean_text (JSON) to get sanitised args
    import json
    safe_args = json.loads(decision.clean_text)
    execute_tool(safe_args)
else:
    execute_tool({"query": sql, "params": params})
```

### Tool Results

```python
decision = dlp.scan_tool_result("user_lookup", tool_output)

if decision.should_block:
    raise RuntimeError(decision.safe_message)

# REDACT is the typical path for PII-only tool results
# (configured via downgrade_escalate_to_redact on tool_result surface)
agent_input = decision.clean_text
```

---

## Surface Scanning Behaviour

Each scan surface receives independent policy enforcement via `surface_overrides` in the YAML:

| Surface | Default behaviour | Typical override |
|---|---|---|
| `output` | Global actions apply | `downgrade_escalate_to_redact: "true"` for PII-heavy domains |
| `tool_args` | Global actions apply | `secrets_action: block` (always; prevents credential exfiltration via tool calls) |
| `tool_result` | Global actions apply | `downgrade_escalate_to_redact: "true"` (avoids review queue for low-severity PII) |

Overrides can only escalate — a `BLOCK` from the scanner can never be silently downgraded by a surface override. The one exception is `downgrade_escalate_to_redact`, which converts `ESCALATE → REDACT` only when there are no canary hits and no secret matches.

---

## EnforcementDecision Reference

Every `scan_*` call returns an `EnforcementDecision`:

```python
@dataclass
class EnforcementDecision:
    action: DLPAction          # ALLOW, PASS_TO_ML, REDACT, ESCALATE, BLOCK
    clean_text: str            # sanitised text (original if ALLOW, redacted if REDACT,
                               # safe_message if BLOCK)
    violations: list[str]      # e.g. ["secret_leak:openai_key", "pii_leak:email"]
    should_block: bool         # True iff action == BLOCK
    should_escalate: bool      # True iff action == ESCALATE
    safe_message: str | None   # user-facing error string (only set on BLOCK)
    escalation_event: dict | None  # structured event payload for ESCALATE
    dlp_result: DLPResult | None   # full scanner result for telemetry
    decision_layer: str        # "canary" | "pattern" | "ml" | "policy"
    decision_reason: str       # human-readable explanation of the decision
```

---

## Policy Configuration Primer

A minimal production-ready policy:

```yaml
dlp:
  canary_salt: "<output of: python -c 'import secrets; print(secrets.token_hex(32))'>"
  canary_action: BLOCK
  secrets_action: BLOCK
  pii_action: REDACT
  unmatched_action: PASS_TO_ML

  surface_overrides:
    tool_args:
      secrets_action: block
    tool_result:
      downgrade_escalate_to_redact: "true"
```

See `policy.default.yaml` for the full list of patterns and advanced feature toggles.

---

## Production Checklist

- [ ] Replace `canary_salt` with a fresh random value: `python -c "import secrets; print(secrets.token_hex(32))"`
- [ ] All DLP instances in your deployment must share the same `canary_salt`
- [ ] Review regex patterns for false positives specific to your data domain
- [ ] Add your document schema keys to `content_keys` if they differ from the defaults
- [ ] Enable `luhn_validation: true` if your domain involves credit card numbers
- [ ] Enable `context_analysis.enabled: true` if you serve documentation or example-heavy content
- [ ] Test with representative production-like data before going live