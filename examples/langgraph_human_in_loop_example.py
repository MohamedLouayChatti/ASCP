# examples/langgraph_human_in_loop_example.py

import os
import uuid
import asyncio
from typing import Dict, Any, Literal

from ascp_integration.orchestrator import ASCPOrchestrator
from ascp_integration.adapters.langgraph_adapter import ASCPLangGraphAdapter

try:
    from langgraph.graph import StateGraph, END, MessageGraph
    from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
    from langchain_core.tools import tool
except ImportError:
    print("This example requires langgraph and langchain-core.")
    print("Install with: uv add langgraph langchain-core")

# ==============================================================================
# Setup the ASCP Orchestrator SDK
# ==============================================================================
# The Orchestrator allows developers to connect dynamic Tool Policies 
# (contracts) through Layer B, and perform DLP scanning & Risk Scoring
# across execution loops.

session_id = str(uuid.uuid4())
orchestrator = ASCPOrchestrator(session_id=session_id)

# Initialize the adapter for LangGraph which hooks into runtime events
adapter = ASCPLangGraphAdapter(orchestrator)

# ==============================================================================
# Application State and Tools
# ==============================================================================
@tool
def sensitive_database_drop(table_name: str) -> str:
    """Drops a table from the database."""
    # In reality, this accesses the DB. We just mock it.
    return f"Dropped table {table_name}"

@tool
def send_email(to: str, body: str) -> str:
    """Sends an email."""
    return f"Email sent to {to}"

tools = [sensitive_database_drop, send_email]
tool_map = {t.name: t for t in tools}

# We define a custom State for Langgraph
class AgentState(dict):
    messages: list
    pending_tool_call: dict
    approval_token: str

# ==============================================================================
# LangGraph Nodes
# ==============================================================================

async def model_node(state: AgentState):
    """The agent logic."""
    print("-> LLM Agent is thinking...")
    messages = state.get("messages", [])
    
    # In this mock, we pretend the LLM decided to call the 'sensitive_database_drop' tool
    if len(messages) == 1:
        # User just asked, so LLM responds with a tool call
        message = AIMessage(
            content="",
            tool_calls=[{"name": "sensitive_database_drop", "args": {"table_name": "users"}, "id": "call_123"}]
        )
        return {"messages": [message]}
    
    # Return final answer
    return {"messages": [AIMessage(content="I have processed your request.")]}

async def trigger_tool_validation(state: AgentState):
    """
    SDK Integration Node: Validates the tool call with ASCP SDK policies.
    If Layer B determines 'REQUIRE_APPROVAL', the graph pauses for a human.
    """
    messages = state.get("messages", [])
    last_message = messages[-1]
    
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        tool_call = last_message.tool_calls[0]
        
        # Pull approval_token if provided by human
        approval_token = state.get("approval_token")
        
        print(f"-> ASCP SDK: Validating execution of '{tool_call['name']}'...")
        decision, sanitized_args = await orchestrator.hook_tool_call(
            correlation_id=adapter.correlation_id,
            tool_name=tool_call["name"],
            tool_args=tool_call["args"],
            approval_token=approval_token,
            context=adapter.invocation_context(),
        )

        if decision.status == "REQUIRE_APPROVAL":
            print(f"-> ASCP SDK: approval required ({decision.reason_code})")
            return {
                "pending_tool_call": {
                    "name": tool_call["name"],
                    "args": sanitized_args,
                    "id": tool_call["id"],
                    "approval_token": decision.approval_token,
                }
            }

        if decision.status == "BLOCK":
            print(f"-> ASCP SDK BLOCK: {decision.reason_code}")
            return {"messages": [ToolMessage(content=decision.reason_code, tool_call_id=tool_call["id"])]}

        tool_call["args"] = sanitized_args
        return {"pending_tool_call": None}

    return {"pending_tool_call": None}

async def execute_tool_node(state: AgentState):
    """Executes the tool now that ASCP authorized it."""
    messages = state.get("messages", [])
    last_message = messages[-1]
    tool_call = last_message.tool_calls[0]
    
    # Execute the actual tool
    tool_instance = tool_map[tool_call["name"]]
    print(f"-> Executing {tool_call['name']}...")
    result = tool_instance.invoke(tool_call["args"])
    
    return {"messages": [ToolMessage(content=result, tool_call_id=tool_call["id"])]}


def route_after_validation(state: AgentState) -> Literal["ask_human", "execute_tool", "model_node"]:
    if state.get("pending_tool_call"):
        return "ask_human"
    
    messages = state.get("messages", [])
    if isinstance(messages[-1], ToolMessage):
        # means it was rejected and ToolMessage with error was appended
        return "model_node"
        
    return "execute_tool"

def route_after_model(state: AgentState) -> Literal["trigger_tool_validation", "__end__"]:
    messages = state.get("messages", [])
    if hasattr(messages[-1], "tool_calls") and messages[-1].tool_calls:
        return "trigger_tool_validation"
    return "__end__"

# ==============================================================================
# Compile Graph
# ==============================================================================
workflow = StateGraph(AgentState)

workflow.add_node("model_node", model_node)
workflow.add_node("trigger_tool_validation", trigger_tool_validation)
workflow.add_node("execute_tool", execute_tool_node)

# Special node: stops the graph execution to ask human
workflow.add_node("ask_human", lambda x: x)

workflow.set_entry_point("model_node")
workflow.add_conditional_edges("model_node", route_after_model)
workflow.add_conditional_edges("trigger_tool_validation", route_after_validation)
workflow.add_edge("execute_tool", "model_node")

# We interrupt before "ask_human" node to pause execution
app = workflow.compile()

# ==============================================================================
# Simulation
# ==============================================================================
async def main():
    print("=== ASCP Human-In-The-Loop SDK Demo ===")
    
    # Simulate adding dynamic Contract in Layer B to require approval for deleting tables
    orchestrator.load_layer_b_policy("examples/layer_b_custom_policy.yaml")
    # Note: Create custom_policy.yaml if you want it to trigger. Assuming it is 
    # configured to 'require_approval' for DB dropping.
    
    print("\n[User Request]: Please delete my old table.")
    inputs = {"messages": [HumanMessage(content="Please delete my old table.")], "approval_token": None}
    
    # 1. Run Graph (Will pause at 'ask_human' because the mock will raise ApprovalRequiredError)
    # Note: In our mock, since we don't actually trigger require_approval unless the policy matches, 
    # we simulate the orchestrator throwing ApprovalRequiredError or we use real policy.
    
    try:
        # Provide the adapter natively in Langgraph configuration callbacks
        config = {"callbacks": [adapter]}
        async for event in app.astream(inputs, config=config):
            pass
    except Exception as e:
        print(f"Workflow paused or error: {e}")
        
    # Later: Human provides approval token!
    print()
    user_choice = input(f"[Human-In-The-Loop] -> The agent requests execution. Do you approve? (y/n): ").strip().lower()

    if user_choice == 'y':
        print("\n[Human]: I approve this action. Generating token...")
        # In a real app, persist the token returned by the pending tool state.
        pending = inputs.get("pending_tool_call") or {}
        inputs["approval_token"] = pending.get("approval_token")
        
        # Replay Graph
        print("\n[System]: Replaying workflow with approval token...")
        try:
            async for event in app.astream(inputs, config=config):
                pass
        except Exception as e:
            print(f"Workflow finished: {e}")
    else:
        print("\n[Human]: Action cancelled.")
        print("[System]: Execution halted by human decision.")

if __name__ == "__main__":
    asyncio.run(main())
