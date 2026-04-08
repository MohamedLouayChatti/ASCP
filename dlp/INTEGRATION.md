# DLP Module — ASCP Integration Guide

## Overview

The DLP module is the **Layer C: Data Leakage & Policy Guard** of the ASCP Security & Evaluation Control Plane. It operates at two points per LLM request:

1. **Before the LLM call** — inject canaries into sensitive internal contexts (system prompt, RAG docs, tool results)
2. **After the LLM call / before tool execution** — scan all external boundaries (final output, tool arguments)

The fundamental invariant is:

```
Inject into ALL sensitive internal contexts
        ↓
Monitor ALL exfiltration paths
        ↓
Treat any canary detection as CRITICAL system failure → always BLOCK
```

---

## Installation & Initialisation

```python
import dlp
from dlp.config import load_dlp_config
from pathlib import Path

# Call once at application startup
dlp.init(load_dlp_config(Path("policy.default.yaml")))

# Or use safe built-in defaults (no file needed)
dlp.init()
```

The module is a singleton — `init()` can be called again to hot-reload config.

---

## Full Per-Request Integration

```python
import dlp

# ── STEP 1: Inject canary into system prompt ──────────────────────────────────
# Do this BEFORE every LLM call. The canary is a hidden credential the model
# is instructed never to reveal. If it appears in output or tool args → BLOCK.
system_prompt, sp_token, sp_label = dlp.inject_canary_into_system_prompt(
    base_system_prompt
)
# Pass `system_prompt` (modified) to the LLM. Never use the original.

# ── STEP 2: Inject canary into RAG documents ──────────────────────────────────
# Do this AFTER retrieval, BEFORE passing docs to the model.
docs, doc_token, doc_label = dlp.inject_canaries_into_context(retrieved_docs)
# Pass `docs` (modified) to the LLM context. The canary is embedded in one doc.

# ── STEP 3: Call the LLM ─────────────────────────────────────────────────────
llm_response, tool_calls = call_llm(system_prompt=system_prompt, docs=docs, ...)

# ── STEP 4: Before any tool executes — scan tool arguments ───────────────────
# This catches exfiltration: agent sending canary/secrets/PII to external tools.
for tool_name, tool_args in tool_calls:
    decision = dlp.scan_tool_args(tool_name, tool_args)
    if decision.should_block:
        # Log violation: decision.violations, decision.dlp_result.canary_hits
        raise ToolCallBlocked(tool_name, decision.safe_message)
    # If ESCALATE: queue for human review, optionally proceed
    if decision.should_escalate:
        alert_security_team(decision.escalation_event)

    # ── STEP 5: Execute tool, then inject canary into result ──────────────────
    raw_result = execute_tool(tool_name, tool_args)
    tool_result, tr_token, tr_label = dlp.inject_canary_into_tool_result(
        tool_name, raw_result
    )
    # Pass `tool_result` (modified) back to the agent.
    # NOTE: Do NOT scan tool_result for canaries here — you just planted one.
    # The canary in the tool result will be detected if the agent leaks it via
    # a subsequent tool call (caught in STEP 4) or in the final output (STEP 6).

# ── STEP 6: Scan final LLM output before returning to user ───────────────────
decision = dlp.scan_output(llm_response)

if decision.should_block:
    return decision.safe_message          # user-safe refusal, no sensitive data

if decision.action.name == "REDACT":
    return decision.clean_text            # PII-redacted version

return llm_response                       # clean, pass through
```

---

## What Each Injection / Scan Covers

| Call | Direction | What it catches |
|---|---|---|
| `inject_canary_into_system_prompt(prompt)` | IN | — (injection only) |
| `inject_canaries_into_context(docs)` | IN | — (injection only) |
| `inject_canary_into_tool_result(name, data)` | IN | — (injection only) |
| `scan_tool_args(name, args)` | OUT | Canary exfiltration via tool call; secrets in args; PII in args |
| `scan_output(text)` | OUT | System-prompt canary echo; RAG canary echo; tool-result canary echo; secrets; PII |

### Canary injection targets and what leakage they prove

| Injected into | Detected via | Meaning |
|---|---|---|
| System prompt | `scan_output` | Prompt injection / instruction override caused model to reveal internal credential |
| System prompt | `scan_tool_args` | Agent exfiltrating system-level secret through a tool call |
| RAG document | `scan_output` | Model reproduced internal document reference in user-facing response |
| RAG document | `scan_tool_args` | Agent routing retrieved internal content to an external tool |
| Tool result | `scan_output` | Agent parroted internal tool data back to user |
| Tool result | `scan_tool_args` | Agent chaining internal data from one tool to another (tool-to-tool exfiltration) |

---

## EnforcementDecision — Response Fields

```python
decision = dlp.scan_output(text)  # or scan_tool_args(...)

decision.should_block        # bool  — hard stop; show safe_message to user
decision.should_escalate     # bool  — flag for human/SIEM review
decision.safe_message        # str   — user-safe refusal text (no sensitive data leaked)
decision.clean_text          # str   — redacted output (for REDACT action)
decision.violations          # list  — e.g. ["canary_leak:db_password", "secret_leak:openai_key"]
decision.action              # DLPAction enum: ALLOW | REDACT | ESCALATE | BLOCK
decision.escalation_event    # dict  — structured event for SIEM/alert routing
decision.dlp_result          # DLPResult — full detail: canary_hits, secret_matches, pii_matches
```

### Checking specific violation types

```python
if decision.dlp_result:
    if decision.dlp_result.canary_hits:
        # CRITICAL: system failure — log immediately
        for hit in decision.dlp_result.canary_hits:
            logger.critical("CANARY LEAK label=%s surface=%s fuzzy=%s",
                            hit.label, hit.surface.value, hit.fuzzy)

    if decision.dlp_result.secret_matches:
        for m in decision.dlp_result.secret_matches:
            logger.error("SECRET LEAK pattern=%s surface=%s", m.pattern_name, m.surface.value)

    if decision.dlp_result.pii_matches:
        for m in decision.dlp_result.pii_matches:
            logger.warning("PII LEAK pattern=%s", m.pattern_name)
```

---

## On Detection: Canary = Always BLOCK

Canary hits are **not configurable** — they are always `BLOCK` regardless of `canary_action` in the policy YAML. This is intentional and by design. A canary appearing in an external boundary means one of:

- Prompt injection attack succeeded
- Instruction override bypassed model alignment
- Data exfiltration through a tool call
- RAG retrieval boundary was violated

None of these are acceptable. The `logger.critical(...)` call fires immediately on detection so your SIEM / log aggregator gets an alert before the enforcement decision even returns.

---

## Configuration (policy.default.yaml)

Key canary-related settings:

```yaml
dlp:
  canary_salt: "your-secret-salt-here"   # REQUIRED: replace default in production
  canary_labels:
    - api_credential_mock
    - db_password
    - sys_admin_token
  canary_fuzzy_match: false              # set true to catch reformatted tokens
  canary_fuzzy_overlap: 0.8             # similarity threshold (0.0–1.0)
  canary_action: BLOCK                   # ignored — canaries always BLOCK
```

Generate a secure salt:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Extending the Pattern Set

The default patterns cover OpenAI keys, AWS access keys, GitHub tokens, emails, IPv4, and credit cards. Add your own in the YAML:

```yaml
dlp:
  secret_patterns:
    - name: slack_token
      regex: 'xox[baprs]-[0-9A-Za-z\-]{10,48}'
    - name: github_pat
      regex: 'github_pat_[A-Za-z0-9_]{82}'
    - name: db_url
      regex: '(postgres|mysql|mongodb)://[^:]+:[^@]+@[^\s]+'
```

---

## Minimal Smoke Test

```python
import dlp
from dlp.config import DLPConfig

dlp.init(DLPConfig.defaults())

# Inject and retrieve a live token
prompt, token, label = dlp.inject_canary_into_system_prompt("You are a helpful assistant.")
assert token.startswith("CANARY-")

# Simulate leak in output
decision = dlp.scan_output(f"The internal token is {token}")
assert decision.should_block
assert any("canary" in v for v in decision.violations)

# Simulate exfiltration in tool args
decision = dlp.scan_tool_args("send_email", {"body": f"data={token}"})
assert decision.should_block

print("DLP canary workflow: OK")
```

---

## ASCP Layer Wiring Summary

```
User Query
    │
    ▼
RAG Retriever
    │  inject_canaries_into_context(docs)         ← Layer C (DLP inject)
    ▼
System Prompt Builder
    │  inject_canary_into_system_prompt(prompt)   ← Layer C (DLP inject)
    ▼
LLM / Agent
    │
    ├─► Tool Call?
    │       │  scan_tool_args(name, args)          ← Layer C (DLP scan — BLOCKS here)
    │       ▼
    │   Tool Execution
    │       │  inject_canary_into_tool_result(...) ← Layer C (DLP inject)
    │       ▼
    │   [result back to agent]
    │
    ▼
Final LLM Response
    │  scan_output(text)                           ← Layer C (DLP scan — BLOCKS here)
    ▼
Response / Action (Allowed | Redacted | Blocked | Escalated)
```