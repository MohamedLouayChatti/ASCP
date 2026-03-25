import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ScanSurface, EnforcementDecision, DLPResult
from .config import load_dlp_config
from .canary import CanaryEngine
from .scanner import DLPScanner
from .enforcer import PolicyEnforcer

_scanner: Optional[DLPScanner] = None
_enforcer: Optional[PolicyEnforcer] = None
_canary_engine: Optional[CanaryEngine] = None


def init(config_path: Path) -> None:
    """Initialize the DLP module with a given policy file."""
    global _scanner, _enforcer, _canary_engine
    if _scanner is not None:
        return
    config = load_dlp_config(config_path)
    _canary_engine = CanaryEngine(config)
    _scanner = DLPScanner(config, _canary_engine)
    _enforcer = PolicyEnforcer()


def _ensure_initialized() -> None:
    if _scanner is None:
        # Fallback to safe defaults if init() wasn't called manually
        init(Path("nonexistent_default.yaml"))


def inject_canaries_into_context(docs: List[Dict[str, str]]) -> List[Dict[str, str]]:
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


def scan_tool_args(tool_name: str, args: Dict[str, Any]) -> EnforcementDecision:
    """Scans pending tool arguments before execution."""
    _ensure_initialized()
    assert _scanner is not None and _enforcer is not None
    # Serialize to string to properly scan embedded secrets
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

