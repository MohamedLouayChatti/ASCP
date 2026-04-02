"""
Runtime registry for framework-wrapped tools.
"""

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable
from typing import Any

_lock = threading.Lock()
_runtime_tools: dict[str, dict[str, Any]] = {}


def resolve_tool_path(fn: Callable[..., Any] | None) -> str | None:
    if fn is None:
        return None
    try:
        path = inspect.getsourcefile(fn) or inspect.getfile(fn)
    except (OSError, TypeError):
        return None
    return str(path) if path else None


def register_runtime_tool(
    name: str,
    fn: Callable[..., Any],
    *,
    description: str = "",
    framework: str = "custom",
    args_schema: dict[str, Any] | None = None,
) -> None:
    if fn is None:
        return
    tool_path = resolve_tool_path(fn)
    with _lock:
        _runtime_tools[name] = {
            "callable": fn,
            "description": description,
            "framework": framework,
            "args_schema": args_schema or {},
            "tool_path": tool_path,
        }


def get_runtime_tool(name: str) -> dict[str, Any] | None:
    with _lock:
        tool = _runtime_tools.get(name)
        return dict(tool) if tool is not None else None


def list_runtime_tools() -> dict[str, dict[str, Any]]:
    with _lock:
        return {name: dict(entry) for name, entry in _runtime_tools.items()}
