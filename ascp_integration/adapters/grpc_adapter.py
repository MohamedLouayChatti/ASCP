from __future__ import annotations

import logging
import os
from typing import Any, AsyncGenerator

import grpc
from google.protobuf import json_format, struct_pb2

from ascp_integration.orchestrator import ASCPDecision, ASCPOrchestrator

import ascp_integration.adapters.proto.ascp_pb2 as pb
import ascp_integration.adapters.proto.ascp_pb2_grpc as pb_grpc

logger = logging.getLogger(__name__)


_DECISION_STATUS = {
    "ALLOW": pb.ALLOW,
    "BLOCK": pb.BLOCK,
    "REDACT": pb.REDACT,
    "REQUIRE_APPROVAL": pb.REQUIRE_APPROVAL,
    "ESCALATE": pb.ESCALATE,
}


def map_decision(internal_decision: ASCPDecision) -> pb.SecurityDecision:
    decision = pb.SecurityDecision()
    decision.status = _DECISION_STATUS.get(internal_decision.status.upper(), pb.DECISION_UNKNOWN)
    decision.approval_token = internal_decision.approval_token or ""
    decision.reason_code = internal_decision.reason_code or ""
    decision.violations.extend(internal_decision.violations)
    decision.risk_score = float(internal_decision.risk_score or 0.0)
    decision.severity = internal_decision.severity or ""
    decision.trace = internal_decision.trace or ""
    return decision


def map_context(proto_ctx: pb.InvocationContext | None) -> dict[str, Any]:
    if proto_ctx is None:
        return {}

    trust_vector = (
        json_format.MessageToDict(proto_ctx.trust_vector, preserving_proto_field_name=True)
        if proto_ctx.HasField("trust_vector")
        else {}
    )
    metadata = (
        json_format.MessageToDict(proto_ctx.metadata, preserving_proto_field_name=True)
        if proto_ctx.HasField("metadata")
        else {}
    )
    return {
        "agent_id": proto_ctx.agent_id,
        "framework": proto_ctx.framework,
        "workflow": proto_ctx.workflow,
        "history": list(proto_ctx.history),
        "evidence_ids": list(proto_ctx.evidence_ids),
        "trust_vector": trust_vector,
        "metadata": metadata,
    }


def struct_to_dict(value: struct_pb2.Struct | None) -> dict[str, Any]:
    if value is None:
        return {}
    return json_format.MessageToDict(value, preserving_proto_field_name=True)


def dict_to_struct(value: dict[str, Any] | None) -> struct_pb2.Struct:
    struct = struct_pb2.Struct()
    struct.update(value or {})
    return struct


class SecureInterceptor(grpc.aio.ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        logger.info("gRPC call: %s", handler_call_details.method)
        return await continuation(handler_call_details)


class OrchestratorServicer(pb_grpc.OrchestratorServiceServicer):
    def __init__(self, orchestrator: ASCPOrchestrator):
        self.orchestrator = orchestrator

    async def _abort(
        self,
        context: grpc.aio.ServicerContext,
        method: str,
        *,
        code: grpc.StatusCode = grpc.StatusCode.INTERNAL,
        message: str = "An internal error occurred during ASCP hook processing.",
    ) -> None:
        logger.error("Error in %s", method, exc_info=True)
        await context.abort(code, message)

    async def BeginInvocation(
        self,
        request: pb.BeginInvocationRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.BeginInvocationResponse:
        try:
            session_id, decision = await self.orchestrator.begin_invocation(
                request.correlation_id,
                map_context(request.invocation_context),
            )
            return pb.BeginInvocationResponse(session_id=session_id, decision=map_decision(decision))
        except Exception:
            await self._abort(context, "BeginInvocation")

    async def EndInvocation(
        self,
        request: pb.EndInvocationRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.EndInvocationResponse:
        try:
            decision = await self.orchestrator.end_invocation(
                request.correlation_id,
                request.session_id,
            )
            return pb.EndInvocationResponse(decision=map_decision(decision))
        except Exception:
            await self._abort(context, "EndInvocation")

    async def HookSystemPrompt(
        self,
        request: pb.SystemPromptRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.SystemPromptResponse:
        try:
            prompt, decision = await self.orchestrator.hook_system_prompt(
                request.correlation_id,
                request.prompt_text,
                map_context(request.invocation_context),
            )
            return pb.SystemPromptResponse(
                validated_prompt=prompt,
                decision=map_decision(decision),
            )
        except Exception:
            await self._abort(context, "HookSystemPrompt")

    async def HookUserInput(
        self,
        request: pb.UserInputRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.UserInputResponse:
        try:
            text, decision = await self.orchestrator.hook_user_input(
                request.correlation_id,
                request.input_text,
                map_context(request.invocation_context),
            )
            return pb.UserInputResponse(
                validated_input=text,
                decision=map_decision(decision),
            )
        except Exception:
            await self._abort(context, "HookUserInput")

    async def HookPromptGet(
        self,
        request: pb.PromptGetRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.PromptGetResponse:
        try:
            prompt, decision = await self.orchestrator.hook_prompt_get(
                request.correlation_id,
                request.prompt_name,
                map_context(request.invocation_context),
            )
            return pb.PromptGetResponse(prompt_text=prompt, decision=map_decision(decision))
        except Exception:
            await self._abort(context, "HookPromptGet")

    async def HookResourceRead(
        self,
        request: pb.ResourceReadRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.ResourceReadResponse:
        try:
            content, decision = await self.orchestrator.hook_resource_read(
                request.correlation_id,
                request.resource_uri,
                map_context(request.invocation_context),
            )
            return pb.ResourceReadResponse(
                resource_content=content,
                decision=map_decision(decision),
            )
        except Exception:
            await self._abort(context, "HookResourceRead")

    async def HookRagRetrieval(
        self,
        request: pb.RagRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.RagResponse:
        try:
            docs = [{"text": doc.text, "source": doc.source} for doc in request.retrieved_docs]
            injected_docs, token, decision = await self.orchestrator.hook_rag_retrieval(
                request.correlation_id,
                docs,
                map_context(request.invocation_context),
            )

            response = pb.RagResponse(canary_token=token or "")
            for doc in injected_docs:
                proto_doc = response.injected_docs.add()
                proto_doc.text = str(doc.get("text", ""))
                proto_doc.source = str(doc.get("source", ""))
            response.decision.CopyFrom(map_decision(decision))
            return response
        except Exception:
            await self._abort(context, "HookRagRetrieval")

    async def HookToolCall(
        self,
        request: pb.ToolCallRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.ToolCallResponse:
        try:
            approval_token = request.approval_token if request.HasField("approval_token") else None
            decision, sanitized_args = await self.orchestrator.hook_tool_call(
                request.correlation_id,
                request.tool_name,
                struct_to_dict(request.tool_args),
                approval_token=approval_token,
                context=map_context(request.invocation_context),
            )

            response = pb.ToolCallResponse()
            response.decision.CopyFrom(map_decision(decision))
            response.sanitized_args.CopyFrom(dict_to_struct(sanitized_args))

            response.is_allowed = decision.status == "ALLOW"
            response.requires_approval = decision.status == "REQUIRE_APPROVAL"
            response.error_message = "" if response.is_allowed else decision.reason_code
            return response
        except Exception:
            await self._abort(context, "HookToolCall")

    async def HookToolResult(
        self,
        request: pb.ToolResultRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.ToolResultResponse:
        try:
            result, decision = await self.orchestrator.hook_tool_result(
                request.correlation_id,
                request.tool_name,
                request.tool_result_string,
                map_context(request.invocation_context),
            )
            return pb.ToolResultResponse(
                sanitized_result=result,
                decision=map_decision(decision),
            )
        except Exception:
            await self._abort(context, "HookToolResult")

    async def HookAgentOutput(
        self,
        request: pb.AgentOutputRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.AgentOutputResponse:
        try:
            clean_text, decision = await self.orchestrator.hook_agent_output(
                request.correlation_id,
                request.generated_text,
                list(request.context_docs),
                map_context(request.invocation_context),
            )
            response = pb.AgentOutputResponse(clean_text=clean_text)
            response.decision.CopyFrom(map_decision(decision))
            response.was_blocked = decision.status == "BLOCK"
            return response
        except Exception:
            await self._abort(context, "HookAgentOutput")

    async def HookStreamingAgentOutput(
        self,
        request_iterator: AsyncGenerator[pb.AgentOutputRequest, None],
        context: grpc.aio.ServicerContext,
    ) -> AsyncGenerator[pb.AgentOutputResponse, None]:
        try:
            correlation_id = "stream"
            invocation_context: dict[str, Any] = {}

            async def string_stream() -> AsyncGenerator[str, None]:
                nonlocal correlation_id, invocation_context
                async for request in request_iterator:
                    correlation_id = request.correlation_id or correlation_id
                    invocation_context = map_context(request.invocation_context)
                    yield request.generated_text

            async for chunk, decision in self.orchestrator.hook_streaming_agent_output(
                correlation_id,
                string_stream(),
                invocation_context,
            ):
                response = pb.AgentOutputResponse(clean_text=chunk)
                response.decision.CopyFrom(map_decision(decision))
                response.was_blocked = decision.status == "BLOCK"
                yield response
        except Exception:
            await self._abort(context, "HookStreamingAgentOutput")


async def serve(
    orchestrator: ASCPOrchestrator,
    port: int = 50051,
    tls_key_path: str | None = None,
    tls_cert_path: str | None = None,
) -> None:
    options = [
        ("grpc.max_receive_message_length", 10 * 1024 * 1024),
        ("grpc.max_send_message_length", 10 * 1024 * 1024),
    ]
    server = grpc.aio.server(interceptors=(SecureInterceptor(),), options=options)
    pb_grpc.add_OrchestratorServiceServicer_to_server(OrchestratorServicer(orchestrator), server)
    listen_addr = f"[::]:{port}"

    if tls_key_path and tls_cert_path and os.path.exists(tls_key_path) and os.path.exists(tls_cert_path):
        with open(tls_key_path, "rb") as handle:
            private_key = handle.read()
        with open(tls_cert_path, "rb") as handle:
            certificate_chain = handle.read()

        credentials = grpc.ssl_server_credentials(((private_key, certificate_chain),))
        server.add_secure_port(listen_addr, credentials)
        logger.info("Starting secure ASCP gRPC proxy on %s.", listen_addr)
    else:
        logger.warning("No TLS certificates configured. Using insecure gRPC port for development.")
        server.add_insecure_port(listen_addr)
        logger.info("Starting ASCP gRPC proxy on %s.", listen_addr)

    await server.start()
    await server.wait_for_termination()
