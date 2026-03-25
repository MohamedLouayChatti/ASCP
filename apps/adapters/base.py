"""
ASCP Adapter SDK — Tier 2 framework integrations.

Converts framework-native tool calls into official MCP SDK tool executions.
Provides minimal boilerplate for LangChain, CrewAI, OpenAI, and custom
frameworks.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from apps.adapters.runtime_registry import register_runtime_tool, resolve_tool_path
from apps.mcp.client import ApprovalRequiredError, MCPProxyClient, ToolBlockedError
from apps.telemetry.observed import get_observed_registry


class ASCPAdapter(ABC):
    """
    Base adapter for converting framework tool calls to MCP + ASCP validation.

    Subclasses implement framework-specific wrapping logic.
    """

    def __init__(
        self,
        proxy_client: MCPProxyClient,
        agent_id: str = "unknown",
        framework: str = "custom",
    ):
        self.proxy_client = proxy_client
        self.agent_id = agent_id
        self.framework = framework

    @abstractmethod
    async def validate_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        """
        Execute a tool call through the ASCP MCP server.

        Raises:
            ApprovalRequiredError: Tool requires approval
            ToolBlockedError: Tool is blocked
        """
        pass

    async def handle_approval(
        self,
        tool_name: str,
        approval_token: str,
        arguments: dict[str, Any],
    ) -> Any:
        """
        Retry a blocked tool call with approval token.

        This is called after a user/human approves the action.
        """
        return await self.proxy_client.call_tool(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=self.agent_id,
            framework=self.framework,
            approval_token=approval_token,
        )


class LangChainAdapter(ASCPAdapter):
    """
    LangChain tool wrapper for ASCP validation.

    Usage:
        from ascp.adapters import langchain_adapter_wrapper

        tools = [
            langchain_adapter_wrapper(web_fetch_tool, proxy_client),
            langchain_adapter_wrapper(db_query_tool, proxy_client),
        ]
        agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
    """

    async def validate_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        """Execute tool call and return result or raise error."""
        return await self.proxy_client.call_tool(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=self.agent_id,
            framework=self.framework,
        )


def langchain_adapter_wrapper(
    langchain_tool,
    proxy_client: MCPProxyClient,
    agent_id: str = "langchain_agent",
):
    """
    Wrap a LangChain Tool to validate through ASCP proxy.

    Example:
        from langchain.tools import Tool
        from ascp.adapters import langchain_adapter_wrapper

        web_fetch = Tool(
            name="web_fetch",
            func=lambda url: fetch_impl(url),
            description="Fetch a web page"
        )

        safe_web_fetch = langchain_adapter_wrapper(web_fetch, proxy_client)
        # Now when LLM calls web_fetch, it goes through ASCP
    """
    try:
        from langchain_core.tools import StructuredTool, Tool
    except ImportError:  # pragma: no cover - compatibility fallback
        from langchain.tools import Tool
        StructuredTool = None  # type: ignore[assignment]

    get_observed_registry().observe(
        "tool",
        langchain_tool.name,
        source="wrap",
        framework="langchain",
        description=getattr(langchain_tool, "description", ""),
        args_schema=getattr(langchain_tool, "args", {}),
        tool_path=resolve_tool_path(
            getattr(langchain_tool, "coroutine", None) or getattr(langchain_tool, "func", None)
        ),
    )
    register_runtime_tool(
        langchain_tool.name,
        getattr(langchain_tool, "coroutine", None) or getattr(langchain_tool, "func", None),
        description=getattr(langchain_tool, "description", ""),
        framework="langchain",
        args_schema=getattr(langchain_tool, "args", {}),
    )

    def normalize_arguments(args: Sequence[Any], kwargs: dict[str, Any]) -> dict[str, Any]:
        if kwargs:
            return dict(kwargs)

        if not args:
            return {}

        arg_schema = getattr(langchain_tool, "args", {}) or {}
        arg_names = list(arg_schema.keys())
        if len(args) == 1 and len(arg_names) == 1:
            return {arg_names[0]: args[0]}

        return {f"arg_{index}": value for index, value in enumerate(args)}

    async def wrapped_func(*args: Any, **kwargs: Any):
        try:
            return await proxy_client.call_tool(
                tool_name=langchain_tool.name,
                arguments=normalize_arguments(args, kwargs),
                agent_id=agent_id,
                framework="langchain",
            )
        except ApprovalRequiredError as e:
            return f"[APPROVAL REQUIRED] {e.tool_name} requires approval. Token: {e.approval_token}"
        except ToolBlockedError as e:
            return f"[BLOCKED] {e.tool_name}: {e.reason}"

    args_schema = getattr(langchain_tool, "args_schema", None)
    if args_schema is not None and StructuredTool is not None:
        return StructuredTool.from_function(
            coroutine=wrapped_func,
            name=langchain_tool.name,
            description=langchain_tool.description,
            args_schema=args_schema,
        )

    return Tool.from_function(
        func=None,
        coroutine=wrapped_func,
        name=langchain_tool.name,
        description=langchain_tool.description,
        args_schema=args_schema,
    )


class CrewAIAdapter(ASCPAdapter):
    """
    CrewAI tool wrapper for ASCP validation.

    Usage:
        from ascp.adapters import crewai_adapter_tool

        @crewai_adapter_tool(proxy_client)
        def web_fetch(url: str) -> str:
            '''Fetch a URL.'''
            return requests.get(url).text
    """

    async def validate_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        """Execute tool call and return result or raise error."""
        return await self.proxy_client.call_tool(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=self.agent_id,
            framework=self.framework,
        )


def crewai_adapter_tool(
    proxy_client: MCPProxyClient,
    agent_id: str = "crewai_agent",
):
    """
    Decorator to add ASCP validation to CrewAI @tool functions.

    Example:
        from ascp.adapters import crewai_adapter_tool

        @crewai_adapter_tool(proxy_client)
        def fetch_data(url: str) -> str:
            '''Fetch data from URL.'''
            return requests.get(url).text

        # Now when crew executes this tool, it validates through ASCP
    """

    def decorator(func):
        get_observed_registry().observe(
            "tool",
            func.__name__,
            source="wrap",
            framework="crewai",
            description=func.__doc__ or "",
            tool_path=resolve_tool_path(func),
        )
        register_runtime_tool(
            func.__name__,
            func,
            description=func.__doc__ or "",
            framework="crewai",
        )

        async def wrapper(**kwargs):
            try:
                return await proxy_client.call_tool(
                    tool_name=func.__name__,
                    arguments=kwargs,
                    agent_id=agent_id,
                    framework="crewai",
                )
            except ApprovalRequiredError as e:
                return (
                    f"[APPROVAL REQUIRED] {e.tool_name} requires approval. "
                    f"Token: {e.approval_token}"
                )
            except ToolBlockedError as e:
                return f"[BLOCKED] {e.tool_name}: {e.reason}"

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper

    return decorator


class OpenAIAdapter(ASCPAdapter):
    """
    OpenAI function_call wrapper for ASCP validation.

    Usage:
        from ascp.adapters import openai_adapter_tools

        tools = openai_adapter_tools(
            [
                {"name": "web_fetch", "description": "...", "parameters": {...}},
            ],
            proxy_client
        )
    """

    async def validate_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        """Execute tool call and return result or raise error."""
        return await self.proxy_client.call_tool(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=self.agent_id,
            framework=self.framework,
        )


def openai_adapter_tools(
    tool_schemas: list[dict],
    proxy_client: MCPProxyClient,
    agent_id: str = "openai_agent",
):
    """
    Wrap OpenAI function_call tools with ASCP validation.

    Example:
        from ascp.adapters import openai_adapter_tools

        base_tools = [
            {
                "type": "function",
                "function": {
                    "name": "web_fetch",
                    "description": "Fetch a web page",
                    "parameters": {...}
                }
            }
        ]

        validated_tools = openai_adapter_tools(base_tools, proxy_client)
        # Use validated_tools in OpenAI chat completion
    """
    # OpenAI tool schemas remain unchanged; execution is enforced through MCP.
    return tool_schemas
