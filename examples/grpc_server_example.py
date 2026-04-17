# examples/grpc_server_example.py

import sys
import uuid
import asyncio
import logging

from ascp_integration.orchestrator import ASCPOrchestrator
from ascp_integration.adapters.grpc_adapter import serve

logging.basicConfig(level=logging.INFO)

async def main():
    print("=== Initialize ASCP Sidecar Servicer ===")
    session_id = str(uuid.uuid4())
    orchestrator = ASCPOrchestrator(session_id=session_id)
    
    # Load specific policies for layer B if needed
    # orchestrator.load_layer_b_policy("examples/layer_b_custom_policy.yaml")
    
    await serve(orchestrator, port=50051)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Server]: Terminated smoothly.")
