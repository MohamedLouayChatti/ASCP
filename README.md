# Layer D — Telemetry & Risk Scoring

Layer D is a **passive observation layer**. It receives events from every other layer, computes a unified risk score, logs everything, and generates incident reports when things go wrong. It never detects threats, blocks actions, or executes tools.

---

## How It Works

```
Layer A  →  grounding_score, hallucination_risk
Layer B  →  tool_call_attempt, policy_block
Layer C  →  dlp_hit, canary_leak
                    ↓
              scorer.py
              weighted formula → risk score [0.0, 1.0]
                    ↓
        ┌───────────┬────────────┬──────────────┐
        │ JSONL /   │ Severity   │ Incident     │
        │ SQLite    │ level      │ report       │
        └───────────┴────────────┴──────────────┘
```

---

## The Three-ID System

Every event carries three IDs that link the full audit trail.

| ID | Scope |
|---|---|
| `session_id` | Entire conversation — essential for detecting multi-turn coercion attacks |
| `correlation_id` | One request / turn |
| `event_id` | One specific event |

---

## Risk Score Formula

All inputs get translated into numbers and combined:

```
risk_score = 0.35 × (1 − grounding_score)
           + 0.30 × tool_risk_value
           + 0.25 × leakage_signal
           + 0.10 × injection_signal
```

### Severity Thresholds

| Score | Severity | Action |
|---|---|---|
| 0.00 – 0.29 | Low | Log only |
| 0.30 – 0.59 | Moderate | Emit warning |
| 0.60 – 0.79 | High | Require human approval |
| 0.80 – 1.00 | Critical | Block + incident report |

---

## The Five Invariants

Security guarantees the system must never violate.

| Code | Guarantee |
|---|---|
| I1 | No forbidden tool ever executes |
| I2 | Allowed tools only run with safe arguments |
| I3 | Secrets and canary tokens never appear in outputs |
| I4 | Untrusted content cannot change policy |
| I5 | Every decision has a reason code and a trace |

Layer D directly enforces **I5**. If a decision exists without a trace, I5 is violated.

---

## Core Data Structures

### TelemetryEvent

One event per significant operation.

Key fields: `event_id`, `correlation_id`, `session_id`, `event_type`, `severity`, `reason_code`, `invariant_violated`, `risk_score`.

### IncidentReport

Auto-generated when `risk_score ≥ 0.80`.

Key fields: `trigger`, `blocked_action`, `redacted_fields` (labels only — never actual values), `invariant_at_risk`, `risk_score`, `summary`.

---

## Storage

Two simultaneous sinks, both append-only. Write failures never crash the server.

- **JSONL** — one JSON line per event, plain text file
- **SQLite** — relational, queryable (e.g. `SELECT * FROM events WHERE invariant_violated = 'I3'`)

---

## What Layer D Is Not

It does not detect injections, validate arguments, scan for PII, or replace a production SIEM. It observes, measures, and reports — nothing more.