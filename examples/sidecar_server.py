import asyncio
import logging
import uuid

from ascp_integration.adapters.grpc_adapter import serve
from ascp_integration.orchestrator import ASCPOrchestrator


logging.basicConfig(level=logging.INFO)


async def main() -> None:
    orchestrator = ASCPOrchestrator(session_id=str(uuid.uuid4()))
    orchestrator.load_layer_b_policy("examples/custom_contract.yaml")
    print("ASCP sidecar listening on localhost:50051")
    await serve(orchestrator, port=50051)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("ASCP sidecar stopped.")
