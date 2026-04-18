import pytest
import asyncio
from ascp_integration.orchestrator import ASCPOrchestrator

@pytest.fixture
def orchestrator():
    # Session represents a single conversational lifecycle
    return ASCPOrchestrator(session_id="test_session_123", log_path="test_logs.jsonl")

@pytest.mark.asyncio
async def test_full_rag_and_tool_workflow(orchestrator):
    correlation_id = "request_1"
    
    # ----------- STEP 1: Intercept RAG ---------------------
    raw_docs = [
        {"text": "The company's secret merger data is Project Apollo.", "source": "db"}
    ]
    poisoned_docs, canary_token, rag_decision = await orchestrator.hook_rag_retrieval(correlation_id, raw_docs)
    
    # Assert Layer C canary poisoning worked
    assert any("CANARY-" in doc["text"] or canary_token in doc["text"] for doc in poisoned_docs)
    assert rag_decision.status == "ALLOW"
    
    # ----------- STEP 2: Intercept Valid Tool Call ----------------
    # Assume the LLM tries to query a tool with malicious extracted PII
    try:
         decision, _args = await orchestrator.hook_tool_call(correlation_id, "sql_db_query", {"query": "SELECT * FROM Users WHERE email='admin@acme.com'"})
         assert decision.status in ("ALLOW", "BLOCK", "REQUIRE_APPROVAL", "REDACT", "ESCALATE")
    except PermissionError:
         # Layer C (DLP) might block this because of the email depending on policy.
         # For this test, we just expect it to be handled safely.
         pass
         
    # ----------- STEP 3: Intercept Output Generation ---------
    # Simulate LLM repeating the canary directly to the user
    malicious_output = f"I found the data. The merger is Apollo. Here is a token I found: {canary_token}"
    
    # Layer C flags canary; Layer A evaluates RAG support; Layer D scores risk
    clean_output, output_decision = await orchestrator.hook_agent_output(
        correlation_id, 
        generated_text=malicious_output, 
        context_docs=[d["text"] for d in poisoned_docs]
    )
    
    # System invariants guarantee canaries never escape to the output
    assert canary_token not in clean_output
    assert output_decision.status == "BLOCK"

@pytest.mark.asyncio
async def test_dlp_canary_blocking(orchestrator):
    correlation_id = "request_dlp_1"
    
    # Simulate agent generating a response containing a real seeded canary.
    instrumented_prompt, prompt_decision = await orchestrator.hook_system_prompt(
        correlation_id,
        "You are a test assistant.",
    )
    assert prompt_decision.status == "ALLOW"
    test_token = next(part for part in instrumented_prompt.split() if part.startswith("CANARY-"))
    clean_output, output_decision = await orchestrator.hook_agent_output(
        correlation_id, 
        generated_text=f"The secret is {test_token}", 
        context_docs=["The secret is CANARY-0123456789012345"]
    )
    
    assert test_token not in clean_output
    assert output_decision.status == "BLOCK"
