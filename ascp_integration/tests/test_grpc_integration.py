import pytest
import asyncio
import grpc

from google.protobuf import struct_pb2

from ascp_integration.orchestrator import ASCPOrchestrator
from ascp_integration.adapters.grpc_adapter import OrchestratorServicer
import ascp_integration.adapters.proto.ascp_pb2 as pb
import ascp_integration.adapters.proto.ascp_pb2_grpc as pb_grpc

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ctx(agent_id="test-agent", framework="pytest", workflow="full"):
    return pb.InvocationContext(agent_id=agent_id, framework=framework, workflow=workflow)


# ---------------------------------------------------------------------------
# Fixtures – all async, all function-scoped to stay simple with STRICT mode
# ---------------------------------------------------------------------------

@pytest.fixture
def orchestrator():
    return ASCPOrchestrator(session_id="test_session_grpc", log_path="test_logs.jsonl")


@pytest.fixture
async def running_server(orchestrator):
    """Start an ephemeral gRPC server and yield the port."""
    server = grpc.aio.server()
    pb_grpc.add_OrchestratorServiceServicer_to_server(
        OrchestratorServicer(orchestrator), server
    )
    port = server.add_insecure_port("[::]:0")
    await server.start()
    yield port
    await server.stop(grace=0)


@pytest.fixture
async def stub(running_server):
    """Return a stub connected to the running server."""
    channel = grpc.aio.insecure_channel(f"localhost:{running_server}")
    yield pb_grpc.OrchestratorServiceStub(channel)
    await channel.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_begin_and_end_invocation(stub):
    ctx = _make_ctx()
    resp = await stub.BeginInvocation(
        pb.BeginInvocationRequest(version="1.0", correlation_id="c1", invocation_context=ctx)
    )
    assert resp.session_id != ""
    assert resp.decision.status == pb.ALLOW

    end_resp = await stub.EndInvocation(
        pb.EndInvocationRequest(version="1.0", correlation_id="c1", session_id=resp.session_id)
    )
    assert end_resp.decision.status == pb.ALLOW


@pytest.mark.asyncio
async def test_hook_system_prompt(stub):
    ctx = _make_ctx()
    resp = await stub.HookSystemPrompt(
        pb.SystemPromptRequest(
            version="1.0", correlation_id="c2",
            prompt_text="You are a helpful assistant.",
            invocation_context=ctx
        )
    )
    assert "assistant" in resp.validated_prompt


@pytest.mark.asyncio
async def test_hook_user_input(stub):
    ctx = _make_ctx()
    resp = await stub.HookUserInput(
        pb.UserInputRequest(
            version="1.0", correlation_id="c2b",
            input_text="Summarize the attached notes.",
            invocation_context=ctx
        )
    )
    assert resp.validated_input != ""
    assert resp.decision.status in (pb.ALLOW, pb.REDACT, pb.BLOCK, pb.ESCALATE)


@pytest.mark.asyncio
async def test_hook_prompt_get(stub):
    ctx = _make_ctx()
    resp = await stub.HookPromptGet(
        pb.PromptGetRequest(
            version="1.0", correlation_id="c3",
            prompt_name="summarize",
            invocation_context=ctx
        )
    )
    assert resp.decision.status in (pb.ALLOW, pb.BLOCK, pb.REQUIRE_APPROVAL)


@pytest.mark.asyncio
async def test_hook_rag_retrieval(stub):
    ctx = _make_ctx()
    resp = await stub.HookRagRetrieval(
        pb.RagRequest(
            version="1.0", correlation_id="c4",
            retrieved_docs=[pb.Document(text="Apollo is secret", source="vault")],
            invocation_context=ctx
        )
    )
    assert len(resp.injected_docs) == 1
    assert resp.decision.status in (pb.ALLOW, pb.REDACT)


@pytest.mark.asyncio
async def test_hook_resource_read(stub):
    ctx = _make_ctx()
    resp = await stub.HookResourceRead(
        pb.ResourceReadRequest(
            version="1.0", correlation_id="c5",
            resource_uri="file://test.txt",
            invocation_context=ctx
        )
    )
    assert resp.decision.status in (pb.ALLOW, pb.BLOCK, pb.REQUIRE_APPROVAL)


@pytest.mark.asyncio
async def test_hook_tool_call_allowed(stub):
    ctx = _make_ctx()
    args = struct_pb2.Struct()
    args.update({"query": "SELECT count(*) FROM items"})
    resp = await stub.HookToolCall(
        pb.ToolCallRequest(
            version="1.0", correlation_id="c6",
            tool_name="safe_query",
            tool_args=args,
            invocation_context=ctx
        )
    )
    assert resp.decision.status in (pb.ALLOW, pb.BLOCK, pb.REQUIRE_APPROVAL)


@pytest.mark.asyncio
async def test_hook_tool_result(stub):
    ctx = _make_ctx()
    resp = await stub.HookToolResult(
        pb.ToolResultRequest(
            version="1.0", correlation_id="c7",
            tool_name="safe_query",
            tool_result_string='{"count": 42}',
            invocation_context=ctx
        )
    )
    assert resp.sanitized_result != ""


@pytest.mark.asyncio
async def test_hook_agent_output(stub):
    ctx = _make_ctx()
    resp = await stub.HookAgentOutput(
        pb.AgentOutputRequest(
            version="1.0", correlation_id="c8",
            generated_text="The total count is 42.",
            context_docs=["Total items: 42"],
            invocation_context=ctx
        )
    )
    assert resp.clean_text != ""
    assert resp.decision.status in (pb.ALLOW, pb.BLOCK, pb.REDACT, pb.ESCALATE)


@pytest.mark.asyncio
async def test_hook_streaming_agent_output(stub):
    ctx = _make_ctx()

    async def request_stream():
        for chunk in ["Hello ", "world"]:
            yield pb.AgentOutputRequest(
                version="1.0", correlation_id="c9",
                generated_text=chunk,
                invocation_context=ctx,
                is_final=(chunk == "world")
            )

    chunks = []
    async for resp in stub.HookStreamingAgentOutput(request_stream()):
        chunks.append(resp.clean_text)

    assert len(chunks) == 2
