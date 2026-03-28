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

from importlib import import_module

_EXPORTS: dict[str, tuple[str, str]] = {
    "ASCPAdapter": ("apps.adapters.base", "ASCPAdapter"),
    "LangChainAdapter": ("apps.adapters.base", "LangChainAdapter"),
    "CrewAIAdapter": ("apps.adapters.base", "CrewAIAdapter"),
    "OpenAIAdapter": ("apps.adapters.base", "OpenAIAdapter"),
    "langchain_adapter_wrapper": ("apps.adapters.base", "langchain_adapter_wrapper"),
    "crewai_adapter_tool": ("apps.adapters.base", "crewai_adapter_tool"),
    "openai_adapter_tools": ("apps.adapters.base", "openai_adapter_tools"),
    "ASCPMemoryHook": ("apps.adapters.hooks", "ASCPMemoryHook"),
    "ASCPPlannerHook": ("apps.adapters.hooks", "ASCPPlannerHook"),
    "ASCPReasoningLoop": ("apps.adapters.hooks", "ASCPReasoningLoop"),
    "LoopOutputGuardResult": ("apps.adapters.hooks", "LoopOutputGuardResult"),
    "LoopRunResult": ("apps.adapters.hooks", "LoopRunResult"),
    "ToolDecisionType": ("apps.adapters.hooks", "ToolDecisionType"),
    "ToolValidationResult": ("apps.adapters.hooks", "ToolValidationResult"),
}


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, attribute_name = _EXPORTS[name]
    module = import_module(module_name)
    value = getattr(module, attribute_name)
    globals()[name] = value
    return value

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
