# Layer D README

## What Layer D Is

Layer D is the telemetry, risk scoring, and incident reporting layer.

Its job is simple:

- receive events from every other layer (A, B, C)
- translate those events into numeric risk contributions
- compute a unified risk score between 0.0 and 1.0
- log every event to persistent storage
- generate a human-readable incident report when something goes wrong

Layer D does not detect threats. It does not block actions. It does not scan outputs.  
It observes, measures, and reports what the other layers found.

---

## How It Works

```
Layer A  →  grounding_score, hallucination_risk, sufficiency    (numeric values)
Layer B  →  tool_call_attempt, policy_block                     (events)
Layer C  →  dlp_hit, canary_leak                                (events)
                          ↓
                    Layer D — scorer.py
                    translates every event into a numeric contribution
                    applies weighted formula
                          ↓
                    risk_score ∈ [0.0, 1.0]
                          ↓
            ┌─────────────┬──────────────┬──────────────┐
            │  log to     │  classify    │  generate    │
            │  JSONL/DB   │  severity    │  incident    │
            │             │              │  report      │
            └─────────────┴──────────────┴──────────────┘
```

---

## The Three ID System

Every event in Layer D carries three identifiers. Understanding them is essential.

| ID | Scope | Changes when |
|---|---|---|
| `session_id` | Full conversation | A new user session starts |
| `correlation_id` | One request / turn | The user sends a new message |
| `event_id` | One specific event | Any event is emitted |

A concrete example across two turns:

```
session_id = "sess-001"   ← same for the whole conversation

  Turn 1 — correlation_id = "req-001"
    event_id = "evt-001"  →  RETRIEVAL
    event_id = "evt-002"  →  TOOL_CALL_ATTEMPT
    event_id = "evt-003"  →  POLICY_BLOCK

  Turn 2 — correlation_id = "req-002"
    event_id = "evt-004"  →  RETRIEVAL
    event_id = "evt-005"  →  DLP_HIT
```

`session_id` is critical for detecting **multi-turn coercion attacks** — where an attacker
spreads a malicious intent across several innocent-looking turns.  
Without it, Layer D sees three isolated requests and misses the pattern.

---

## Risk Score Formula

Layer D receives heterogeneous inputs — some are numeric scores from Layer A,
others are raw events from Layer B and C. Its first job is to translate everything
into a number, then combine them.

### Event → Numeric Contribution

| Source | Event or value | Contribution |
|---|---|---|
| Layer A | `grounding_score` | used directly as `(1 - grounding_score)` |
| Layer A | `hallucination_risk` | used directly |
| Layer B | `policy_block` received | tool component → 1.0 |
| Layer B | `tool risk = high` | tool component → 0.8 |
| Layer B | `tool risk = medium` | tool component → 0.5 |
| Layer B | `tool risk = low` | tool component → 0.1 |
| Layer C | `dlp_hit` received | leakage component → 1.0 |
| Layer C | `canary_leak = false` | leakage component → 0.0 |
| Heuristics | injection detected | injection component → 0.0 to 1.0 |

### Weighted Formula

```
risk_score = 0.35 × (1 − grounding_score)
           + 0.30 × tool_risk_value
           + 0.25 × leakage_signal
           + 0.10 × injection_signal
```

Weights reflect security priority — a data leak is more critical than a weak grounding score.

### Severity Classification

| Score range | Severity | Action taken |
|---|---|---|
| 0.0 — 0.29 | Low | Log only, no action |
| 0.30 — 0.59 | Moderate | Enhanced monitoring, emit warning |
| 0.60 — 0.79 | High | Suspend action, require human approval |
| 0.80 — 1.0 | Critical | Immediate block, create incident report |

---

## Event Types

These are the events Layer D can receive and log.

```python
class EventType(StrEnum):
    RETRIEVAL         = "retrieval_event"
    EVAL_VECTOR       = "eval_vector"
    TOOL_CALL_ATTEMPT = "tool_call_attempt"
    TOOL_CALL_RESULT  = "tool_call_result"
    POLICY_BLOCK      = "policy_block"
    DLP_HIT           = "dlp_hit"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_GRANTED  = "approval_granted"
    APPROVAL_DENIED   = "approval_denied"
    APPROVAL_TIMEOUT  = "approval_timeout"
    INCIDENT_CREATED  = "incident_created"
    SANITIZATION      = "sanitization_event"
    REQUEST_START     = "request_start"
    REQUEST_END       = "request_end"
```

`APPROVAL_TIMEOUT` is emitted when a human approval request receives no response
within the configured threshold. On timeout, the action is automatically blocked
following the safe failure mode defined in the cahier des charges.

---

## Severity Levels

```python
class SeverityLevel(StrEnum):
    INFO     = "info"      # normal operation, everything fine
    WARN     = "warn"      # something suspicious, monitoring needed
    ERROR    = "error"     # technical failure (timeout, schema crash)
    CRITICAL = "critical"  # confirmed security violation
```

---

## Core Data Structures

### TelemetryEvent

Emitted for every significant operation. One event per action.

```python
class TelemetryEvent(BaseModel):
    event_id: str           # unique ID for this specific event (auto-generated)
    correlation_id: str     # links all events in one request/turn (required)
    session_id: str | None  # links all requests in one conversation
    event_type: EventType   # what kind of event this is
    timestamp: datetime     # when it happened, always UTC (auto-generated)
    severity: SeverityLevel # how serious it is (default: INFO)
    tool_name: str | None   # which tool was involved, if any
    reason_code: str | None # why a decision was made (e.g. DOMAIN_POLICY_VIOLATION)
    details: dict           # any extra context specific to this event
    invariant_violated: str | None  # which invariant was breached: I1, I2, I3, I4, I5
    risk_score: float | None        # the computed score at the time of the event
    latency_ms: float | None        # time added by ASCP vs baseline (for paper metrics)
```

### IncidentReport

Generated automatically when risk_score exceeds the critical threshold.

```python
class IncidentReport(BaseModel):
    incident_id: str             # unique ID for this incident (auto-generated)
    correlation_id: str          # links back to the request that caused it (required)
    session_id: str | None       # links back to the full conversation
    timestamp: datetime          # when the incident was created (auto-generated)
    trigger: str                 # what caused it e.g. "canary_token_detected" (required)
    blocked_action: str | None   # what was stopped e.g. "send_email to gmail.com"
    redacted_fields: list[str]   # what was removed from output e.g. ["api_key", "ssn"]
    invariant_at_risk: str | None # which invariant was threatened: I1 to I5
    evidence_references: list[str] # document IDs from Layer A that are relevant
    policy_rule_ids: list[str]   # which policy rules from policies.yaml fired
    risk_score: float            # final score that triggered this report
    summary: str                 # human-readable explanation of the full incident
```

---

## The Five Invariants

Every `TelemetryEvent` and `IncidentReport` can reference one of these invariants.
They are the formal security guarantees ASCP must never violate.

| Code | Guarantee | Example violation |
|---|---|---|
| I1 | No forbidden tool ever executes | Agent calls `delete_database` which is not allowed |
| I2 | Allowed tools only run with safe arguments | `file_read` called with `path = "../../etc/passwd"` |
| I3 | Secrets and canary tokens never appear in outputs | API key leaks into agent response |
| I4 | Untrusted retrieved content cannot change policy | Injected prompt in a document tries to override rules |
| I5 | Every allow/block decision has a reason code and trace | Any decision logged without a reason code |

---

## Storage

Layer D writes to two sinks simultaneously.

### JSONL sink — `sink_jsonl.py`

Appends one JSON line per event to a plain text file.

```
{"event_id": "evt-001", "correlation_id": "req-001", "event_type": "policy_block", ...}
{"event_id": "evt-002", "correlation_id": "req-001", "event_type": "dlp_hit", ...}
```

- append-only, never overwrites previous events
- thread-safe via asyncio lock — prevents file corruption under concurrent writes
- write failures never crash the server — errors are logged and execution continues

### SQLite sink — `sink_sqlite.py`

Persists the same events to a relational database for querying and analytics.

Useful for queries like:

```sql
-- all events from one session
SELECT * FROM events WHERE session_id = 'sess-001';

-- all critical incidents this week
SELECT * FROM incidents WHERE risk_score >= 0.8;

-- how many times was I3 violated
SELECT COUNT(*) FROM events WHERE invariant_violated = 'I3';
```

---

## Incident Report — Field by Field

When an incident is created, each field answers one specific question:

| Field | Question it answers |
|---|---|
| `trigger` | What happened? |
| `blocked_action` | What was stopped? |
| `redacted_fields` | What was removed from the output? |
| `invariant_at_risk` | Which security guarantee was threatened? |
| `evidence_references` | Which retrieved documents were involved? |
| `policy_rule_ids` | Which policy rules fired? |
| `risk_score` | How severe was it? |
| `summary` | Full human-readable explanation |

Note — `redacted_fields` contains only the **labels** of what was removed, never the actual
sensitive values. So `["api_key", "ssn"]` appears in the report, never `"sk-abc123"`.

---

## Architecture

Layer D has four components:

```
apps/telemetry/
    events.py       →  TelemetryEvent and IncidentReport data structures
    sink_jsonl.py   →  async JSONL file writer
    sink_sqlite.py  →  async SQLite writer

apps/risk/
    scorer.py       →  risk score formula and severity classification
```

---

## Security Invariants Enforced by Layer D

Layer D does not enforce invariants directly — that is the job of layers A, B, C.  
But Layer D enforces **I5** — auditability.

I5 states: every allow or block decision must have a reason code and a full trace.

Layer D enforces I5 by:
- requiring `reason_code` on every `POLICY_BLOCK` event
- requiring `invariant_violated` on every incident
- assigning a unique `event_id` to every single operation
- linking everything via `correlation_id` and `session_id`

If any decision exists in the system without a trace in Layer D, I5 is violated.

---

## What Layer D Does Not Do

Layer D does not:

- detect prompt injections
- validate tool arguments
- scan outputs for PII or secrets
- block or allow any action
- execute tools
- replace a proper SIEM in production

It is a pure observation and measurement layer.

---

## Short Mental Model

Layer D is:

- passive — it observes, never acts
- exhaustive — every operation generates at least one event
- structured — all events follow strict typed schemas
- traceable — three-level ID system links everything
- resilient — storage failures never affect security enforcement

Its core question is always:

> "Given everything that just happened across all layers, what is the unified risk level,
> and is there a human-readable record of it?"