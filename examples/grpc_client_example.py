import asyncio
import uuid

import grpc
from google.protobuf import struct_pb2

from ascp_integration.adapters.proto import ascp_pb2 as pb
from ascp_integration.adapters.proto import ascp_pb2_grpc as pb_grpc


async def run_client() -> None:
    print("=== ASCP gRPC Client Demo ===")
    correlation_id = str(uuid.uuid4())

    async with grpc.aio.insecure_channel("localhost:50051") as channel:
        stub = pb_grpc.OrchestratorServiceStub(channel)
        ctx = pb.InvocationContext(
            agent_id="grpc-demo-agent",
            framework="custom",
            workflow="demo",
        )

        system_resp = await stub.HookSystemPrompt(
            pb.SystemPromptRequest(
                version="1.0",
                correlation_id=correlation_id,
                prompt_text="You are a careful assistant.",
                invocation_context=ctx,
            )
        )
        print("[ASCP]: system prompt decision:", pb.DecisionStatus.Name(system_resp.decision.status))

        input_resp = await stub.HookUserInput(
            pb.UserInputRequest(
                version="1.0",
                correlation_id=correlation_id,
                input_text="Find the database name from the retrieved context.",
                invocation_context=ctx,
            )
        )
        print("[ASCP]: user input decision:", pb.DecisionStatus.Name(input_resp.decision.status))

        rag_request = pb.RagRequest(
            version="1.0",
            correlation_id=correlation_id,
            retrieved_docs=[
                pb.Document(text="The secret database is named Prometheus.", source="internal_wiki")
            ],
            invocation_context=ctx,
        )
        rag_response = await stub.HookRagRetrieval(rag_request)
        print("[ASCP]: RAG decision:", pb.DecisionStatus.Name(rag_response.decision.status))

        args = struct_pb2.Struct()
        args.update({"to": "admin@example.com", "body": "Routine report."})
        tool_response = await stub.HookToolCall(
            pb.ToolCallRequest(
                version="1.0",
                correlation_id=correlation_id,
                tool_name="send_email",
                tool_args=args,
                invocation_context=ctx,
            )
        )
        print("[ASCP]: tool decision:", pb.DecisionStatus.Name(tool_response.decision.status))
        if tool_response.decision.status == pb.REQUIRE_APPROVAL:
            print("[ASCP]: approval token:", tool_response.decision.approval_token)

        malicious_output = (
            "I found the database name: Prometheus. "
            f"The internal token is {rag_response.canary_token}"
        )
        output_response = await stub.HookAgentOutput(
            pb.AgentOutputRequest(
                version="1.0",
                correlation_id=correlation_id,
                generated_text=malicious_output,
                context_docs=[doc.text for doc in rag_response.injected_docs],
                invocation_context=ctx,
                is_final=True,
            )
        )
        print("[ASCP]: output decision:", pb.DecisionStatus.Name(output_response.decision.status))
        print("[Client]: clean output:\n", output_response.clean_text)


if __name__ == "__main__":
    asyncio.run(run_client())
