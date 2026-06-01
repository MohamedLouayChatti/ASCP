"""
DLP — Data Leakage & Policy Guard
==================================

Public API
----------
  init(config)                          — initialise with a policy file or DLPConfig
  inject_canary_into_system_prompt(...) — seed system prompt before every LLM call
  inject_canaries_into_context(...)     — seed RAG docs before retrieval-augmented calls
  inject_canary_into_tool_result(...)   — seed tool results before handing back to agent
  scan_output(text)                     — scan final LLM response (OUTPUT surface)
  scan_tool_args(tool_name, args)       — scan tool arguments before execution (TOOL_ARGS)
  scan_tool_result(tool_name, data)     — scan tool return value before agent sees it (TOOL_RESULT)

Canary workflow
---------------
  ┌─ inject_canary_into_system_prompt ─────────────────────────────────┐
  │  inject_canaries_into_context                                       │
  │  inject_canary_into_tool_result  ──► LLM / Agent                   │
  └─────────────────────────────────────────────────────────────────────┘
                                ↓
              scan_output   ─ scan final LLM response
              scan_tool_args ─ scan args before tool executes
                                ↓
                    BLOCK on any canary detection (always)
                    LOG + ALERT (logger.critical)
"""

import json
from pathlib import Path
from typing import Any, Union

from .models import ScanSurface, EnforcementDecision, DLPResult
from .config import load_dlp_config, DLPConfig
from .canary import CanaryEngine
from .scanner import DLPScanner
from .enforcer import PolicyEnforcer

_scanner: DLPScanner | None = None
_enforcer: PolicyEnforcer | None = None
_canary_engine: CanaryEngine | None = None
_config: DLPConfig | None = None


def init(config: Union[Path, DLPConfig, None] = None) -> None:
    """
    Initialise the DLP module with a given policy file or DLPConfig object.
    If config is None or the file does not exist, built-in safe defaults are used.
    """
    global _scanner, _enforcer, _canary_engine, _config

    if isinstance(config, DLPConfig):
        loaded_config = config
    else:
        path = config if config is not None else Path("nonexistent_default.yaml")
        loaded_config = load_dlp_config(path)

    _canary_engine = CanaryEngine(loaded_config)
    _scanner = DLPScanner(loaded_config, _canary_engine)
    _enforcer = PolicyEnforcer(loaded_config)
    _config = loaded_config


def _ensure_initialized() -> None:
    if _scanner is None:
        init(Path("nonexistent_default.yaml"))


def warmup_ml() -> None:
    """
    Load the ML classifier once during application startup.

    This avoids paying model-load latency on the first request and fails fast if
    CUDA, model dependencies, or the bundled LoRA adapter are not available.
    """
    _ensure_initialized()
    from .ml import warmup

    warmup(_config)


# ── Injection API ─────────────────────────────────────────────────────────────

def inject_canary_into_system_prompt(
    system_prompt: str,
) -> tuple[str, str, str]:
    """
    Append a canary credential to the system prompt.

    Call this once per LLM request, BEFORE sending to the model.

    Returns
    -------
    (modified_prompt, token, label)
      modified_prompt — pass this to the LLM instead of the original
      token           — the planted canary string (for your records)
      label           — the human-readable label (e.g. "api_credential_mock")

    Detection
    ---------
    If the model echoes the token in its output or in any tool argument,
    scan_output / scan_tool_args will return should_block=True.
    """
    _ensure_initialized()
    assert _canary_engine is not None
    return _canary_engine.inject_system_prompt(system_prompt)


def inject_canaries_into_context(
    docs: list[dict],
) -> tuple[list[dict], str | None, str | None]:
    """
    Inject a canary token into one of the retrieved RAG documents.

    Call this after retrieval, BEFORE passing docs to the model.

    Returns
    -------
    (modified_docs, token, label)
    """
    _ensure_initialized()
    assert _canary_engine is not None
    return _canary_engine.inject_context(docs)


def inject_canary_into_tool_result(
    tool_name: str,
    result_data: Any,
) -> tuple[Any, str | None, str | None]:
    """
    Embed a canary token into a tool's return value.

    Call this after the tool executes, BEFORE the agent sees the result.

    Parameters
    ----------
    tool_name   — name of the tool (for logging; not used in detection)
    result_data — raw tool result (dict, list, str, or other)

    Returns
    -------
    (modified_result, token, label)
      modified_result — pass this to the agent instead of the original
    """
    _ensure_initialized()
    assert _canary_engine is not None
    return _canary_engine.inject_tool_result(result_data)


# ── Scan API ──────────────────────────────────────────────────────────────────

def scan_output(text: str) -> EnforcementDecision:
    """
    Scan the final LLM output (OUTPUT surface).

    Call this before returning the model's response to the user.
    """
    _ensure_initialized()
    assert _scanner is not None and _enforcer is not None
    result = _scanner.scan(text, ScanSurface.OUTPUT)
    return _enforcer.enforce(result)


def scan_tool_args(tool_name: str, args: dict[str, Any]) -> EnforcementDecision:
    """
    Scan pending tool arguments before execution (TOOL_ARGS surface).

    Serialises to JSON and scans the flat string.
    Catches exfiltration via tool calls (e.g. canary in a URL or body).
    """
    _ensure_initialized()
    assert _scanner is not None and _enforcer is not None

    serialized = json.dumps(args, default=str)
    result = _scanner.scan(serialized, ScanSurface.TOOL_ARGS)
    return _enforcer.enforce(result)


def scan_tool_result(tool_name: str, result_data: Any) -> EnforcementDecision:
    """
    Scan the result of a tool execution before passing back to the agent
    (TOOL_RESULT surface).

    Note: if you called inject_canary_into_tool_result on this result, the
    canary token will be present here — that is expected and intentional.
    Only use scan_tool_result on *uninstrumented* tool results (i.e. results
    that come from external services you don't control) to detect unexpected
    leakage of secrets or PII.
    """
    _ensure_initialized()
    assert _scanner is not None and _enforcer is not None

    if isinstance(result_data, (dict, list)):
        text_to_scan = json.dumps(result_data, default=str)
    else:
        text_to_scan = str(result_data)

    result = _scanner.scan(text_to_scan, ScanSurface.TOOL_RESULT)
    return _enforcer.enforce(result)
