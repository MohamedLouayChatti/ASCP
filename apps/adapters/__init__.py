"""
ASCP Adapter SDK — Tier 2 integrations for popular agent frameworks.

Provides thin wrappers that convert framework-native tool calls into official
MCP executions for ASCP validation, without requiring frameworks to understand
the transport details.

Tier 1: Native MCP
  - Use directly with MCP-compatible clients
  - No adapter needed

Tier 2: Framework Adapters
  - LangChain: Tool wrappers
  - CrewAI: Task output hooks
  - OpenAI: Function call interceptors

Tier 3: Optional Hooks
  - Full reasoning-loop supervision
  - Memory tracking
  - Planner inspection
"""
from __future__ import annotations

from apps.adapters.base import (
    ASCPAdapter,
    CrewAIAdapter,
    LangChainAdapter,
    OpenAIAdapter,
    crewai_adapter_tool,
    langchain_adapter_wrapper,
    openai_adapter_tools,
)
from apps.adapters.hooks import (
    ASCPMemoryHook,
    ASCPPlannerHook,
    ASCPReasoningLoop,
    LoopOutputGuardResult,
    LoopRunResult,
    ToolDecisionType,
    ToolValidationResult,
)

__all__ = [
    "ASCPAdapter",
    "LangChainAdapter",
    "CrewAIAdapter",
    "OpenAIAdapter",
    "langchain_adapter_wrapper",
    "crewai_adapter_tool",
    "openai_adapter_tools",
    "ASCPMemoryHook",
    "ASCPPlannerHook",
    "ASCPReasoningLoop",
    "LoopOutputGuardResult",
    "LoopRunResult",
    "ToolDecisionType",
    "ToolValidationResult",
]
