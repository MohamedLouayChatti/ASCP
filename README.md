# ASCP — Agent Security Control Plane

**A production-grade security SDK for tool-using AI agents.**

ASCP sits between your agent framework and the outside world, enforcing a layered security policy across every phase of an agent invocation — from grounding and capability validation, through data leakage prevention, to risk scoring and audit logging. It works in-process or as a gRPC sidecar.

```
User Input → [ Layer A ] → [ Layer B ] → [ Layer C ] → [ Layer D ] → Response
               Grounding     Capability    DLP +          Risk Score
               & Trust       Contracts     Canary         & Telemetry
```

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [Layer A — Grounding & Trust](#layer-a--grounding--trust)
- [Layer B — Capability Contracts](#layer-b--capability-contracts)
- [Layer C — Data Leakage Prevention](#layer-c--data-leakage-prevention)
- [Layer D — Risk Scoring & Telemetry](#layer-d--risk-scoring--telemetry)
- [Adapters](#adapters)
- [Configuration](#configuration)
- [Testing](#testing)
- [Installation](#installation)
- [Project Structure](#project-structure)

---

## Architecture Overview

ASCP is organized into four independent but coordinated layers. Each layer has a single responsibility and communicates through well-defined data structures. All layers are coordinated by the `ASCPOrchestrator`.

### The Four Layers

| Layer | Module | Responsibility |
|---|---|---|
| **A** | `grounding/` | Hallucination detection, claim support, context sufficiency |
| **B** | `layerb/` | Capability contracts, tool call validation, policy enforcement |
| **C** | `dlp/` | Secrets/PII detection, canary injection, format-preserving redaction |
| **D** | `layerd/` | Weighted risk scoring, JSONL/SQLite telemetry, incident reports |

### The Five Security Invariants

Every release must uphold these guarantees:

| Code | Guarantee |
|---|---|
| **I1** | No forbidden tool ever executes |
| **I2** | Allowed tools only run with safe, validated arguments |
| **I3** | Secrets and canary tokens never appear in outputs |
| **I4** | Untrusted content cannot change policy |
| **I5** | Every decision has a reason code and a full audit trace |

---

## Quick Start

```python
from ascp_integration.orchestrator import ASCPOrchestrator

orchestrator = ASCPOrchestrator(session_id="my-session")

# Begin a tracked invocation
correlation_id = "req-001"
session_id, decision = await orchestrator.begin_invocation(correlation_id)

# Hook into any lifecycle stage
decision = await orchestrator.hook_user_input(correlation_id, "Summarize these documents.")
decision = await orchestrator.hook_rag_retrieval(correlation_id, documents)
decision = await orchestrator.hook_tool_call(correlation_id, "web_fetch", {"url": "..."})
decision = await orchestrator.hook_agent_output(correlation_id, "The answer is...")

await orchestrator.end_invocation(correlation_id, session_id)
```

`ASCPDecision` is returned at every hook:

```python
@dataclass
class ASCPDecision:
    status: str          # "ALLOW" | "BLOCK" | "REDACT" | "ESCALATE"
    reason_code: str     # Machine-readable reason
    violations: list[str]
    risk_score: float    # 0.0 – 1.0
    severity: str        # "low" | "moderate" | "high" | "critical"
    trace: str           # Human-readable audit string
```

---

## Layer A — Grounding & Trust

**Module**: `grounding/`

Layer A evaluates the factual grounding of an LLM's final answer against its retrieved context. It outputs a trust vector used by Layer D to weight the risk score.

### What it does

- **Claim extraction** (`claim_extractor.py`, `llm_claim_extractor.py`): Extracts atomic factual claims from the LLM's answer. Supports both regex-based extraction and LLM-assisted extraction (via local Ollama or API).
- **Support checking** (`support_checker.py`): For each extracted claim, determines whether supporting evidence exists in the retrieved documents.
- **Sufficiency checking** (`sufficiency.py`): Evaluates whether the retrieved context is complete enough to answer the query, independent of what the model actually said.
- **Trust vector assembly** (`trust_vector.py`): Combines grounding score (claim support ratio) and context sufficiency into a single structured payload for Layer D.

### Usage

```python
from grounding.trust_vector import assemble_trust_vector

trust = assemble_trust_vector(
    query="What is the refund policy?",
    answer="Refunds are processed within 5 business days.",
    documents=retrieved_docs,
)
# trust["grounding_score"]   → 0.0–1.0 (claim support ratio)
# trust["is_sufficient"]     → bool
# trust["unsupported_claims"] → list of strings
```

### Extractor modes

Configured via `.env` or environment variables:

```env
EXTRACTOR_MODE=llm_local   # Use local Ollama
EXTRACTOR_MODE=regex        # Fast, no model needed
```

---

## Layer B — Capability Contracts

**Module**: `layerb/`

Layer B validates every tool call, resource access, and prompt before execution. It enforces a policy-as-code contract that specifies what an agent is allowed to do and under what conditions.

### What it validates

- JSON Schema validation of tool arguments
- Path traversal and denylist enforcement for file operations
- URL allowlisting and SSRF protection for web fetches
- SQL safety rules for database queries
- Agent and framework identity constraints
- Workflow sequencing and precondition rules
- Argument and body size limits
- Approval gating for high-risk operations

### Usage

```python
from layerb import LayerBEngine

engine = LayerBEngine.from_defaults()

result = engine.validate_capability(
    capability_name="file_read",
    args={"path": "/etc/passwd"},
    agent_id="research-agent",
)
# result.decision → "allow" | "block" | "require_approval"
# result.reason   → human-readable explanation
```

### CLI

```bash
python -m layerb paths        # Show active policy file locations
python -m layerb list         # List all registered capabilities
python -m layerb events       # Tail recent security events
python -m layerb feedback --report  # Generate policy improvement suggestions
```

### Policy configuration

Layer B ships with built-in defaults for common capability families (`file_read`, `file_write`, `web_fetch`, `db_query`, `shell_exec`). Override them with a local policy file:

```yaml
# policy/tool_permissions.yaml
capabilities:
  my_custom_reader:
    risk: high
    scopes: [local_fs]
    approval_required: true
    constraints:
      deny_path_traversal: true
      path_denylist:
        - /etc
        - /root
```

```python
engine = LayerBEngine(policy_path="policy/tool_permissions.yaml")
```

### Contract resolution order

1. Exact capability name match
2. Argument schema hash match
3. Inferred family match (`file_read`, `web_fetch`, etc.)
4. Catch-all default
5. Unknown capability mode (configurable via `LAYERB_UNKNOWN_CAPABILITY_MODE`)

---

## Layer C — Data Leakage Prevention

**Module**: `dlp/`

Layer C scans every surface of an agent's execution for secrets, PII, and canary token leaks. It operates pre-LLM (canary injection) and post-LLM (output scanning), and enforces configurable enforcement actions.

### Detection pipeline

Each scan runs up to ten detection steps across three categories:

**Secrets**
- Exact regex patterns (OpenAI, AWS, GitHub tokens)
- Shannon entropy detection for novel secret formats

**PII**
- Regex patterns (email, IPv4, credit cards)
- Luhn algorithm validation to eliminate false positive credit card matches
- Optional Named Entity Recognition via spaCy (PERSON, ORG, GPE, LOC, DATE)

**Canary & IP**
- Cryptographic canary token injection using `secrets` module
- Fuzzy canary matching to catch LLM token manipulations
- Document fingerprinting to block verbatim RAG context reproduction

### Enforcement actions

Applied in priority order: `BLOCK > ESCALATE > REDACT > ALLOW`

| Action | Behavior |
|---|---|
| **ALLOW** | No violation. Text passes unchanged. |
| **REDACT** | PII replaced with `[REDACTED_category_pattern]` placeholders. |
| **ESCALATE** | Decision deferred to human review. Output blocked pending approval. |
| **BLOCK** | Critical violation. Output replaced with a safe user-facing message. |

### Usage

```python
import dlp

dlp.init()  # Uses built-in defaults, no config file needed

# Scan LLM output
decision = dlp.scan_output("Here is your API key: sk-abc123...")
if decision.should_block:
    return decision.safe_message

# Scan tool arguments before execution
decision = dlp.scan_tool_args("execute_query", {"password": "hunter2"})
if decision.should_block:
    raise PermissionError(decision.safe_message)

# Inject canary tokens into RAG context
docs, token, label = dlp.inject_canaries_into_context(retrieved_docs)
# If the LLM echoes `token` in output, scan_output() will catch it
```

### EnforcementDecision

```python
@dataclass
class EnforcementDecision:
    action: DLPAction             # ALLOW | REDACT | ESCALATE | BLOCK
    clean_text: str               # Safe or redacted text
    should_block: bool
    should_escalate: bool
    violations: list[str]
    safe_message: str | None      # User-facing message (never leaks violation detail)
    escalation_event: dict | None # Payload for review queue
    dlp_result: DLPResult | None  # Full scan result for telemetry
```

### Custom policy

```python
from pathlib import Path
import dlp

dlp.init(Path("config/policy.yaml"))
```

See `dlp/policy.default.yaml` for the full documented template.

### Machine learning backend

A fine-tuned LoRA adapter (Gemma 2 2B base) is loaded from `dlp/ML/dlp_lora_package/` for ML-backed DLP classification. The adapter directory must include the trained weight artifact, either `adapter_model.safetensors` or `adapter_model.bin`.

```bash
pip install "ascp[ascp-ml]"
python -c "import torch; print(torch.__version__); print(torch.cuda.is_available()); print(torch.version.cuda)"
```

The `ascp-ml` extra installs CUDA PyTorch wheels directly for supported Windows and Linux x86_64 Python versions.

Warm the classifier at service startup so request handling pays only inference latency:

```python
from ascp_integration.orchestrator import ASCPOrchestrator, DLPConfig

orchestrator = ASCPOrchestrator(
    session_id="prod-session",
    dlp_config=DLPConfig.defaults(),
    warmup_ml=True,
)
```

Training and generation notebooks are in `dlp/ML/`.

---

## Layer D — Risk Scoring & Telemetry

**Module**: `layerd/`

Layer D is a passive observation layer. It receives events from all other layers, computes a unified risk score, and logs everything. It never blocks, detects, or executes — it only observes, measures, and reports.

### Risk score formula

```
risk_score = 0.35 × (1 − grounding_score)   # Layer A signal
           + 0.30 × tool_risk_value           # Layer B signal
           + 0.25 × leakage_signal            # Layer C signal
           + 0.10 × injection_signal          # Prompt injection signal
```

### Severity thresholds

| Score | Severity | Response |
|---|---|---|
| 0.00 – 0.29 | Low | Log only |
| 0.30 – 0.59 | Moderate | Emit warning |
| 0.60 – 0.79 | High | Require human approval |
| 0.80 – 1.00 | Critical | Block + auto-generate incident report |

### Custom Layer D configuration

Layer D supports custom scoring parameter initialization through `layerd.risk.config.ScoringConfig`.
You can override weights, thresholds, and action floors from Python or YAML, then pass the config into `compute_risk_score`.

```python
from layerd.risk.config import ScoringConfig
from layerd.risk.models import RiskInput
from layerd.risk.scorer import compute_risk_score

custom_cfg = ScoringConfig.from_dict({
    "layer_a": {
        "grounding": 0.18,
        "hallucination": 0.30,
    },
    "layer_c": {
        "dlp_block_floor": 0.92,
    },
    "combination": {
        "layer_a": 0.20,
        "layer_b": 0.30,
        "layer_c": 0.50,
    },
    "severity": {
        "critical": 0.90,
        "high": 0.70,
        "medium": 0.35,
    },
})

result = compute_risk_score(
    RiskInput(tool_risk_level="LOW"),
    config=custom_cfg,
)
```

Or load a YAML file:

```python
custom_cfg = ScoringConfig.from_yaml("config/layerd_risk.yaml")
```

### Three-ID audit trail

Every event carries three IDs that link the full trace:

| ID | Scope |
|---|---|
| `session_id` | Entire conversation (detects multi-turn coercion attacks) |
| `correlation_id` | One request / turn |
| `event_id` | One specific event |

### Storage

Two simultaneous append-only sinks. Write failures never crash the server.

- **JSONL** — one JSON object per line, plain text, grep-friendly
- **SQLite** — relational, queryable

```sql
SELECT * FROM events WHERE invariant_violated = 'I3';
SELECT * FROM events WHERE severity = 'critical' ORDER BY timestamp DESC;
```

---

## Adapters

**Module**: `ascp_integration/`

ASCP exposes a consistent security lifecycle to every major agent framework through adapter classes. All adapters wrap `ASCPOrchestrator` and map framework-native callbacks to ASCP hooks.

### Available adapters

| Adapter | Class | Framework |
|---|---|---|
| LangGraph | `ASCPLangGraphAdapter` | LangGraph / LangChain callback handler |
| LangChain | `ASCPLangChainAdapter` | LangChain callback handler |
| CrewAI | `ASCPCrewAIAdapter` | CrewAI flow/task callbacks |
| LlamaIndex | `ASCPLlamaIndexAdapter` | LlamaIndex query engines and retrievers |
| smolagents | `ASCPSmolagentsAdapter` | HuggingFace smolagents |
| gRPC | `ASCPGRPCAdapter` | Out-of-process sidecar (non-Python agents) |

### LangGraph / LangChain

```python
from ascp_integration.orchestrator import ASCPOrchestrator
from ascp_integration.adapters.langgraph_adapter import ASCPLangGraphAdapter

orchestrator = ASCPOrchestrator(session_id="session-1")
adapter = ASCPLangGraphAdapter(orchestrator, agent_id="research-agent")

config = {"callbacks": [adapter]}
# Pass config to graph.invoke(), chain.invoke(), etc.
```

### CrewAI

```python
adapter = ASCPCrewAIAdapter(orchestrator, agent_id="crew-researcher")

payload = await adapter.before_kickoff(
    system_prompt="You are a careful analyst.",
    user_input="Summarize the documents.",
    documents=[{"text": "...", "source": "kb"}],
)
tool_args = await adapter.validate_tool("web_fetch", {"url": "https://example.com"})
answer = await adapter.after_kickoff("Final answer text")
```

### gRPC sidecar

The gRPC contract is defined in `ascp_integration/adapters/proto/ascp.proto`.

```python
from ascp_integration.adapters.grpc_adapter import serve

await serve(host="0.0.0.0", port=50051, tls_key="key.pem", tls_cert="cert.pem")
```

Implemented RPCs: `BeginInvocation`, `EndInvocation`, `HookSystemPrompt`, `HookUserInput`, `HookPromptGet`, `HookRagRetrieval`, `HookResourceRead`, `HookToolCall`, `HookToolResult`, `HookAgentOutput`, `HookStreamingAgentOutput`.

> **Note**: Without TLS credentials, the adapter logs a warning and should be treated as a local-development sidecar only.

---

## Configuration

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `EXTRACTOR_MODE` | `regex` | Claim extraction mode: `regex`, `llm_local`, `llm_api` |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama endpoint for local LLM extraction |
| `OLLAMA_MODEL` | `llama3.2` | Model name for local extraction |
| `OLLAMA_TIMEOUT` | `30.0` | Ollama request timeout in seconds |
| `LAYERB_EVENT_LOG` | `logs/layer_b/events.jsonl` | Layer B event log path |
| `LAYERB_UNKNOWN_CAPABILITY_MODE` | — | How to handle unregistered tools |

Copy `.env.example` to `.env` and customize before running.

### DLP policy

A fully documented policy template is available at `dlp/policy.default.yaml`. Key options:

```yaml
dlp:
  canary_action: BLOCK
  secrets_action: BLOCK
  pii_action: REDACT
  enable_ner: true
  entropy:
    enabled: true
    threshold: 4.5
  canary_fuzzy_match: true
  fingerprinting:
    enabled: true
    threshold: 0.3
```

---

## Testing

### Run all tests

```bash
pytest                                 # Runs dlp/tests (default, per pyproject.toml)
pytest tests/ ascp_integration/tests/ # Layer B integration + adapter tests
pytest layerd/tests/                   # Layer D telemetry and risk tests
```

### With coverage

```bash
pytest dlp/tests -v --cov=dlp --cov-report=term-missing
```

### Demo

```bash
# 1. Copy and configure the secrets fixture
cp dlp_demo_secrets_example.py dlp_demo_secrets.py
# Edit dlp_demo_secrets.py with local test-only values

# 2. Run the end-to-end demo
python dlp_demo.py
```

### Test suites

| Suite | Location | What it covers |
|---|---|---|
| DLP unit tests | `dlp/tests/` | Canary, config, scanner, messenger, patterns, validators, context, integration |
| Layer B tests | `tests/` | Capability matching, contract candidates, validator hardening, feedback loop |
| Layer D tests | `layerd/tests/` | Risk scoring, telemetry event emission |
| Adapter tests | `ascp_integration/tests/` | gRPC adapter, orchestrator integration |

---

## Installation

**Requires Python 3.11+**

### Core SDK

```bash
pip install .
# or with uv
uv sync
```

### Optional extras

Install only what your integration needs:

```bash
pip install "ascp[ascp-grpc]"       # gRPC sidecar adapter
pip install "ascp[ascp-langchain]"  # LangChain / LangGraph adapter
pip install "ascp[ascp-langgraph]"  # LangGraph adapter
pip install "ascp[ascp-crewai]"     # CrewAI adapter
pip install "ascp[ascp-llamaindex]" # LlamaIndex adapter
pip install "ascp[ascp-smolagents]" # smolagents adapter
pip install "ascp[nlp]"             # spaCy NER support
pip install "ascp[ascp-ml]"         # ML-backed DLP (requires CUDA PyTorch)
pip install "ascp[dev]"             # Development tools (pytest, ruff, mypy)
```

---

## Project Structure

```
ASCP/
├── ascp_integration/          # Orchestrator + framework adapters
│   ├── orchestrator.py        # Central coordinator for all four layers
│   ├── adapters/
│   │   ├── langgraph_adapter.py
│   │   ├── langchain_adapter.py
│   │   ├── crew_adapter.py
│   │   ├── llamaindex_adapter.py
│   │   ├── smolagents_adapter.py
│   │   ├── grpc_adapter.py
│   │   └── proto/             # gRPC contract definitions
│   └── tests/
├── grounding/                 # Layer A — trust & grounding
│   ├── claim_extractor.py
│   ├── llm_claim_extractor.py
│   ├── support_checker.py
│   ├── sufficiency.py
│   └── trust_vector.py
├── layerb/                    # Layer B — capability contracts
│   ├── engine.py              # Public SDK API + CLI entry point
│   ├── validator.py           # Core policy enforcement engine
│   ├── policy/                # Bundled default permissions
│   ├── schemas/               # Bundled JSON schemas
│   └── policies/              # Candidate generation & feedback
├── dlp/                       # Layer C — data leakage prevention
│   ├── __init__.py            # Public API: init(), scan_output(), etc.
│   ├── scanner.py             # Detection pipeline orchestrator
│   ├── enforcer.py            # Policy enforcement + decision logic
│   ├── canary.py              # Canary injection & detection
│   ├── patterns.py            # Regex pattern matching & redaction
│   ├── config.py              # Policy loading & validation
│   ├── models.py              # Core data structures & enums
│   ├── ml.py                  # ML-backed DLP integration
│   ├── policy.default.yaml    # Documented policy template
│   ├── ML/                    # Training artifacts & notebooks
│   └── tests/
├── layerd/                    # Layer D — risk scoring & telemetry
│   ├── risk/                  # Risk scorer, config, models
│   ├── telemetry/             # Event emission (JSONL + SQLite)
│   └── tests/
├── common/
│   └── config.py              # Shared settings (pydantic-settings)
├── examples/
│   ├── in_process_example.py  # In-process integration example
│   ├── sidecar_client.py      # gRPC sidecar client example
│   ├── sidecar_server.py      # gRPC sidecar server example
│   └── custom_contract.yaml   # Example custom policy contract
├── tests/                     # Layer B integration tests
├── pyproject.toml
└── uv.lock
```

---

## Repository

[https://github.com/MohamedLouayChatti/ASCP](https://github.com/MohamedLouayChatti/ASCP)
