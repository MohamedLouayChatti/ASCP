import asyncio
import uuid

from ascp_integration.orchestrator import ASCPOrchestrator


async def main() -> None:
    correlation_id = str(uuid.uuid4())
    orchestrator = ASCPOrchestrator(session_id=str(uuid.uuid4()))
    orchestrator.load_layer_b_policy("examples/custom_contract.yaml")

    context = {
        "agent_id": "in-process-demo-agent",
        "framework": "custom-python",
        "workflow": "example",
    }

    session_id, decision = await orchestrator.begin_invocation(correlation_id, context)
    print("session:", session_id, decision.status)

    system_prompt, decision = await orchestrator.hook_system_prompt(
        correlation_id,
        "You answer only from retrieved documents.",
        context,
    )
    print("system prompt:", decision.status)

    user_input, decision = await orchestrator.hook_user_input(
        correlation_id,
        "What is the internal project codename?",
        context,
    )
    print("user input:", decision.status)

    docs, canary_token, decision = await orchestrator.hook_rag_retrieval(
        correlation_id,
        [{"text": "The internal project codename is Apollo.", "source": "wiki"}],
        context,
    )
    print("rag:", decision.status)

    decision, sanitized_args = await orchestrator.hook_tool_call(
        correlation_id,
        "project_lookup",
        {"project": "Apollo"},
        context=context,
    )
    print("project_lookup:", decision.status, sanitized_args)

    decision, _args = await orchestrator.hook_tool_call(
        correlation_id,
        "send_email",
        {
            "recipient": "admin@example.com",
            "subject": "Apollo summary",
            "body": "Apollo summary",
        },
        context=context,
    )
    print("send_email:", decision.status, decision.approval_token)

    result, decision = await orchestrator.hook_tool_result(
        correlation_id,
        "project_lookup",
        {"codename": "Apollo"},
        context,
    )
    print("tool result:", decision.status, result)

    leaked_answer = (
        "The project codename is Apollo. "
        f"I should not reveal this internal token: {canary_token}"
    )
    clean_text, decision = await orchestrator.hook_agent_output(
        correlation_id,
        leaked_answer,
        [doc["text"] for doc in docs],
        context,
    )
    print("output:", decision.status)
    print("clean text:", clean_text)

    await orchestrator.end_invocation(correlation_id, session_id)


if __name__ == "__main__":
    asyncio.run(main())
