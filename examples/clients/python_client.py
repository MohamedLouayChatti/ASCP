import asyncio
import grpc
from google.protobuf import struct_pb2

# Adjust imports based on where protoc put your files
from ascp_integration.adapters.proto import ascp_pb2 as pb
from ascp_integration.adapters.proto import ascp_pb2_grpc as pb_grpc

async def run_client():
    port = 50051
    # For production, use TLS:
    # credentials = grpc.ssl_channel_credentials()
    # channel = grpc.aio.secure_channel(f"localhost:{port}", credentials)
    print(f"Connecting to orchestrator at localhost:{port} ...")
    async with grpc.aio.insecure_channel(f"localhost:{port}") as channel:
        stub = pb_grpc.OrchestratorServiceStub(channel)
        
        ctx = pb.InvocationContext(
            agent_id="python-agent-01",
            framework="custom",
            workflow="demo_workflow"
        )
        
        # 1. Begin Invocation
        session_req = pb.BeginInvocationRequest(version="1.0", correlation_id="req_001", invocation_context=ctx)
        session_resp = await stub.BeginInvocation(session_req)
        print(f"Session Started: {session_resp.session_id} - Decision: {pb.DecisionStatus.Name(session_resp.decision.status)}")
        
        # 2. Tool Call Check
        args = struct_pb2.Struct()
        args.update({"query": "SELECT * FROM users", "limit": 10})
        
        tool_req = pb.ToolCallRequest(
            version="1.0",
            correlation_id="req_001",
            tool_name="database_query",
            tool_args=args,
            invocation_context=ctx
        )
        try:
            tool_resp = await stub.HookToolCall(tool_req)
            if tool_resp.decision.status == pb.ALLOW:
                print("Tool call ALLOWED by ASCP.")
            elif tool_resp.decision.status == pb.REQUIRE_APPROVAL:
                print("Tool call REQUIRES APPROVAL.")
            else:
                print(f"Tool call blocked: {tool_resp.decision.reason_code}")
        except grpc.RpcError as e:
            print(f"gRPC error: {e.details()}")

if __name__ == "__main__":
    asyncio.run(run_client())
