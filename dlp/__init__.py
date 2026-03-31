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


def init(config: Union[Path, DLPConfig, None] = None) -> None:
    """
    Initialise the DLP module with a given policy file or DLPConfig object.
    If config is None or the file does not exist, built-in safe defaults are used.
    """
    global _scanner, _enforcer, _canary_engine
    
    if isinstance(config, DLPConfig):
         loaded_config = config
    else:
         path = config if config is not None else Path("nonexistent_default.yaml")
         loaded_config = load_dlp_config(path)
         
    _canary_engine = CanaryEngine(loaded_config)
    _scanner = DLPScanner(loaded_config, _canary_engine)
    _enforcer = PolicyEnforcer(loaded_config)


def _ensure_initialized() -> None:
    if _scanner is None:
        init(Path("nonexistent_default.yaml"))


def inject_canaries_into_context(
    docs: list[dict[str, str]],
) -> tuple[list[dict[str, str]], str | None, str | None]:
    """
    Inject canary tokens into retrieved context documents and optionally fingerprint
    them for verbatim-reproduction detection later.
    """
    _ensure_initialized()
    assert _canary_engine is not None and _scanner is not None

    injected, token, label = _canary_engine.inject_into_context(docs)

    # Fingerprint the original docs (before injection) so the fingerprinter
    # doesn't accidentally match on the canary token itself.
    _scanner.fingerprint_docs(docs)

    return injected, token, label


def scan_output(text: str) -> EnforcementDecision:
    """Scan the final LLM output."""
    _ensure_initialized()
    assert _scanner is not None and _enforcer is not None
    result = _scanner.scan(text, ScanSurface.OUTPUT)
    return _enforcer.enforce(result)


def scan_tool_args(tool_name: str, args: dict[str, Any]) -> EnforcementDecision:
    """
    Scan pending tool arguments before execution.

    When enable_structured_scan=True, walks the dict recursively so each
    violation carries a precise JSON path (e.g. "secret_leak:openai_key@body.creds").
    Otherwise serialises to JSON and scans the flat string (backward-compatible).
    """
    _ensure_initialized()
    assert _scanner is not None and _enforcer is not None

    if _scanner.config.enable_structured_scan:
        result = _scanner.scan_structured(args, ScanSurface.TOOL_ARGS)
    else:
        serialized = json.dumps(args, default=str)
        result = _scanner.scan(serialized, ScanSurface.TOOL_ARGS)

    return _enforcer.enforce(result)


def scan_tool_result(tool_name: str, result_data: Any) -> EnforcementDecision:
    """Scan the result of a tool execution before passing back to the agent."""
    _ensure_initialized()
    assert _scanner is not None and _enforcer is not None

    if _scanner.config.enable_structured_scan and isinstance(result_data, (dict, list)):
        result = _scanner.scan_structured(result_data, ScanSurface.TOOL_RESULT)
    elif isinstance(result_data, (dict, list)):
        text_to_scan = json.dumps(result_data, default=str)
        result = _scanner.scan(text_to_scan, ScanSurface.TOOL_RESULT)
    else:
        result = _scanner.scan(str(result_data), ScanSurface.TOOL_RESULT)

    return _enforcer.enforce(result)
