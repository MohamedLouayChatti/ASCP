# ASCP Adapter SDK

ASCP adapters expose the same security lifecycle to different agent frameworks:

1. `begin_invocation`
2. `handle_system_prompt`
3. `handle_user_input`
4. `handle_rag_documents`
5. `validate_tool_call`
6. `handle_tool_result`
7. `handle_agent_output`
8. `end_invocation`

The lifecycle maps to ASCP layers:

- Layer A: grounding and trust signals for final answers against RAG context.
- Layer B: capability, prompt, resource, approval, workflow, and schema contracts.
- Layer C: DLP scanning plus canary injection for prompts, RAG docs, tool results, tool args, user input, and output.
- Layer D: risk scoring and telemetry events.

## Transport Adapters

The gRPC contract lives in `proto/ascp.proto`.

The server implementation lives in `grpc_adapter.py` and wraps `ASCPOrchestrator`.
It is intended for non-Python or out-of-process integrations where ASCP runs as
a sidecar.

Implemented RPCs:

- `BeginInvocation`
- `EndInvocation`
- `HookSystemPrompt`
- `HookUserInput`
- `HookPromptGet`
- `HookRagRetrieval`
- `HookResourceRead`
- `HookToolCall`
- `HookToolResult`
- `HookAgentOutput`
- `HookStreamingAgentOutput`

For production gRPC deployments, pass TLS key/cert paths to `serve(...)`.
Without TLS, the adapter intentionally logs a warning and should be treated as a
local-development sidecar only.

## In-Process Framework Adapters

The base class is `ASCPAgentAdapter` in `ascp_integration.adapters`.

Available adapters:

- `ASCPLangGraphAdapter` in `langgraph_adapter.py`
- `ASCPLangChainAdapter` in `langchain_adapter.py`
- `ASCPCrewAIAdapter` in `crew_adapter.py`
- `ASCPLlamaIndexAdapter` in `llamaindex_adapter.py`
- `ASCPSmolagentsAdapter` in `smolagents_adapter.py`

Each adapter keeps a correlation id, framework name, agent id, workflow name,
current system prompt, current user input, and current RAG context. Framework
callbacks should mutate native prompt/document/output objects when the framework
allows it, or use the returned sanitized value when mutation is not possible.

## LangGraph and LangChain

Use `ASCPLangGraphAdapter` or `ASCPLangChainAdapter` as a callback handler:

```python
from ascp_integration.orchestrator import ASCPOrchestrator
from ascp_integration.adapters.langgraph_adapter import ASCPLangGraphAdapter

orchestrator = ASCPOrchestrator(session_id="session-1")
adapter = ASCPLangGraphAdapter(orchestrator, agent_id="research-agent")

config = {"callbacks": [adapter]}
```

The adapter handles:

- chat system messages and human messages
- raw LLM prompts
- retriever documents
- tool starts
- tool results
- final LLM generations

## CrewAI

CrewAI integrations usually call the explicit hooks from flow, task, or tool
callbacks:

```python
adapter = ASCPCrewAIAdapter(orchestrator, agent_id="crew-researcher")

payload = await adapter.before_kickoff(
    system_prompt="You are a careful analyst.",
    user_input="Summarize the documents.",
    documents=[{"text": "...", "source": "kb"}],
)

tool_args = await adapter.validate_tool("web_fetch", {"url": "https://example.com"})
tool_result = await adapter.after_tool("web_fetch", {"body": "..."})
answer = await adapter.after_kickoff("Final answer text")
```

## LlamaIndex

Use `ASCPLlamaIndexAdapter` around query engines, retrievers, and agent tools:

```python
adapter = ASCPLlamaIndexAdapter(orchestrator, agent_id="llamaindex-agent")

prepared = await adapter.prepare_query(
    "What changed in the policy?",
    system_prompt="Answer only from retrieved context.",
)
nodes = await adapter.on_retrieval(nodes)
tool_args = await adapter.before_tool_call("db_query", {"query": "SELECT 1"})
response = await adapter.finalize_response(response)
```

## smolagents

Use `ASCPSmolagentsAdapter` around task preparation, tool execution, and final
answers:

```python
adapter = ASCPSmolagentsAdapter(orchestrator, agent_id="smol-agent")

prepared = await adapter.prepare_run(
    "Find the answer.",
    system_prompt="Use tools only when necessary.",
    documents=[{"text": "...", "source": "rag"}],
)
args = await adapter.before_tool_call("file_read", {"path": "notes.txt"})
result = await adapter.after_tool_call("file_read", "file contents")
answer = await adapter.finalize_answer("final answer")
```

## Dependency Extras

Install only what an integration needs:

```bash
pip install "ascp[ascp-grpc]"
pip install "ascp[ascp-langchain]"
pip install "ascp[ascp-langgraph]"
pip install "ascp[ascp-crewai]"
pip install "ascp[ascp-llamaindex]"
pip install "ascp[ascp-smolagents]"
```

The core SDK default DLP configuration does not download an ML model
implicitly. ML-backed DLP can be enabled with the `ascp-ml` extra and an
explicit DLP config. Production ML inference expects a CUDA-enabled PyTorch
install and the bundled LoRA directory must contain `adapter_model.safetensors`
or `adapter_model.bin`. Pass `warmup_ml=True` to `ASCPOrchestrator` at service
startup to load the model once before request traffic.
