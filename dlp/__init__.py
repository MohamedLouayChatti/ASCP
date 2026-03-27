import json
from pathlib import Path
from typing import Any

from .models import ScanSurface, EnforcementDecision, DLPResult
from .config import load_dlp_config
from .canary import CanaryEngine
from .scanner import DLPScanner
from .enforcer import PolicyEnforcer

_scanner: DLPScanner | None = None
_enforcer: PolicyEnforcer | None = None
_canary_engine: CanaryEngine | None = None


def init(config_path: Path | None = None) -> None:
    """Initialize the DLP module with a given policy file.

    If ``config_path`` is None or the file does not exist, built-in safe
    defaults are used automatically.
    """
    global _scanner, _enforcer, _canary_engine
    path = config_path if config_path is not None else Path("nonexistent_default.yaml")
    config = load_dlp_config(path)
    _canary_engine = CanaryEngine(config)
    _scanner = DLPScanner(config, _canary_engine)
    # Pass config so the enforcer reads surface_overrides from policy, not hardcode.
    _enforcer = PolicyEnforcer(config)


def _ensure_initialized() -> None:
    if _scanner is None:
        # Fallback to safe defaults if init() wasn't called manually
        init(Path("nonexistent_default.yaml"))


def inject_canaries_into_context(docs: list[dict[str, str]]) -> tuple[list[dict[str, str]], str | None, str | None]:
    """Injects canary tokens into retrieved context to track potential leakage."""
    _ensure_initialized()
    assert _canary_engine is not None
    return _canary_engine.inject_into_context(docs)


def scan_output(text: str) -> EnforcementDecision:
    """Scans the final LLM output."""
    _ensure_initialized()
    assert _scanner is not None and _enforcer is not None
    result = _scanner.scan(text, ScanSurface.OUTPUT)
    return _enforcer.enforce(result)


def scan_tool_args(tool_name: str, args: dict[str, Any]) -> EnforcementDecision:
    """Scans pending tool arguments before execution.

    Serialization is performed here (not inside PatternEngine) so that the
    scanner always receives a plain string regardless of the args structure,
    and so scan() can apply canary detection and NER to the same serialized
    representation in a single pass.
    """
    _ensure_initialized()
    assert _scanner is not None and _enforcer is not None
    serialized = json.dumps(args, default=str)
    result = _scanner.scan(serialized, ScanSurface.TOOL_ARGS)
    return _enforcer.enforce(result)


def scan_tool_result(tool_name: str, result: Any) -> EnforcementDecision:
    """Scans the result of a tool execution before passing back to the agent."""
    _ensure_initialized()
    assert _scanner is not None and _enforcer is not None

    if isinstance(result, (dict, list)):
        text_to_scan = json.dumps(result, default=str)
    else:
        text_to_scan = str(result)

    res = _scanner.scan(text_to_scan, ScanSurface.TOOL_RESULT)
    return _enforcer.enforce(res)
