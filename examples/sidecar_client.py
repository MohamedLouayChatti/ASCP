import asyncio
import uuid

import grpc
from google.protobuf import struct_pb2

from ascp_integration.adapters.proto import ascp_pb2 as pb
from ascp_integration.adapters.proto import ascp_pb2_grpc as pb_grpc


def _struct(payload: dict) -> struct_pb2.Struct:
    value = struct_pb2.Struct()
    value.update(payload)
    return value


async def main() -> None:
    correlation_id = str(uuid.uuid4())

    async with grpc.aio.insecure_channel("localhost:50051") as channel:
        stub = pb_grpc.OrchestratorServiceStub(channel)
        ctx = pb.InvocationContext(
            agent_id="sidecar-demo-agent",
            framework="custom-grpc",
            workflow="example",
        )

        session = await stub.BeginInvocation(
            pb.BeginInvocationRequest(
                version="1.0",
                correlation_id=correlation_id,
                invocation_context=ctx,
            )
        )
        print("session:", session.session_id)

        system_prompt = await stub.HookSystemPrompt(
            pb.SystemPromptRequest(
                version="1.0",
                correlation_id=correlation_id,
                prompt_text="You answer only from retrieved documents.",
                invocation_context=ctx,
            )
        )
        print("system prompt:", pb.DecisionStatus.Name(system_prompt.decision.status))

        user_input = await stub.HookUserInput(
            pb.UserInputRequest(
                version="1.0",
                correlation_id=correlation_id,
                input_text="What is the internal project codename?",
                invocation_context=ctx,
            )
        )
        print("user input:", pb.DecisionStatus.Name(user_input.decision.status))

        rag = await stub.HookRagRetrieval(
            pb.RagRequest(
                version="1.0",
                correlation_id=correlation_id,
                retrieved_docs=[
                    pb.Document(text="The internal project codename is Apollo.", source="wiki")
                ],
                invocation_context=ctx,
            )
        )
        print("rag:", pb.DecisionStatus.Name(rag.decision.status))

        allowed_tool = await stub.HookToolCall(
            pb.ToolCallRequest(
                version="1.0",
                correlation_id=correlation_id,
                tool_name="project_lookup",
                tool_args=_struct({"project": "Apollo"}),
                invocation_context=ctx,
            )
        )
        print("project_lookup:", pb.DecisionStatus.Name(allowed_tool.decision.status))

        approval_tool = await stub.HookToolCall(
            pb.ToolCallRequest(
                version="1.0",
                correlation_id=correlation_id,
                tool_name="send_email",
                tool_args=_struct(
                    {
                        "recipient": "admin@example.com",
                        "subject": "Apollo summary",
                        "body": "Apollo summary",
                    }
                ),
                invocation_context=ctx,
            )
        )
        print("send_email:", pb.DecisionStatus.Name(approval_tool.decision.status))
        if approval_tool.decision.approval_token:
            print("approval token:", approval_tool.decision.approval_token)

        tool_result = await stub.HookToolResult(
            pb.ToolResultRequest(
                version="1.0",
                correlation_id=correlation_id,
                tool_name="project_lookup",
                tool_result_string='{"codename": "Apollo"}',
                invocation_context=ctx,
            )
        )
        print("tool result:", pb.DecisionStatus.Name(tool_result.decision.status))

        leaked_answer = (
            "The project codename is Apollo. "
            f"I should not reveal this internal token: {rag.canary_token}"
        )
        output = await stub.HookAgentOutput(
            pb.AgentOutputRequest(
                version="1.0",
                correlation_id=correlation_id,
                generated_text=leaked_answer,
                context_docs=[doc.text for doc in rag.injected_docs],
                invocation_context=ctx,
                is_final=True,
            )
        )
        print("output:", pb.DecisionStatus.Name(output.decision.status))
        print("clean text:", output.clean_text)

        await stub.EndInvocation(
            pb.EndInvocationRequest(
                version="1.0",
                correlation_id=correlation_id,
                session_id=session.session_id,
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
