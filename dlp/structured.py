"""
Structured data scanner with JSON path attribution.

Instead of serialising dicts to a flat JSON string and scanning that,
scan_dict() recurses into every leaf string independently, attributing
each match to its precise JSON path (e.g. "records[2].user.email").

This gives telemetry like:
  pii_leak:email@records[2].user.email

rather than:
  pii_leak:email   (somewhere in this blob)

redact_dict() reconstructs the original data structure with matched
leaf values replaced by their redacted equivalents.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from .models import DLPMatch, ScanSurface, DLPAction


def _join_path(parent: str, key: str | int) -> str:
    """Build a dot/bracket JSON path component."""
    if isinstance(key, int):
        return f"{parent}[{key}]" if parent else f"[{key}]"
    return f"{parent}.{key}" if parent else str(key)


def scan_dict(
    data: Any,
    surface: ScanSurface,
    pattern_engine,            # PatternEngine — avoids circular import
    config,                    # DLPConfig
    path: str = "",
    entropy_scanner=None,      # Optional[EntropyScanner]
    match_validator=None,      # Optional[MatchValidator]
    context_analyzer=None,     # Optional[ContextAnalyzer]
) -> list[DLPMatch]:
    """
    Recursively walk a dict/list/scalar and scan every leaf string.

    Each returned DLPMatch has source_path set to the full JSON path of the
    leaf from which it was detected. Nested structures of arbitrary depth are
    supported. Non-string scalars (int, float, bool, None) are skipped.

    Optional scanners (entropy, Luhn, context) are applied to each leaf when
    provided, giving per-leaf path attribution for every detection technique.
    """
    matches: list[DLPMatch] = []

    if isinstance(data, dict):
        for key, value in data.items():
            child_path = _join_path(path, str(key))
            matches.extend(
                scan_dict(data=value, surface=surface, pattern_engine=pattern_engine,
                          config=config, path=child_path, entropy_scanner=entropy_scanner,
                          match_validator=match_validator, context_analyzer=context_analyzer)
            )

    elif isinstance(data, (list, tuple)):
        for idx, item in enumerate(data):
            child_path = _join_path(path, idx)
            matches.extend(
                scan_dict(data=item, surface=surface, pattern_engine=pattern_engine,
                          config=config, path=child_path, entropy_scanner=entropy_scanner,
                          match_validator=match_validator, context_analyzer=context_analyzer)
            )

    elif isinstance(data, str):
        leaf_path = path or "<root>"

        # Regex scan
        leaf_matches, _ = pattern_engine.scan_text(data, surface)

        # Entropy detection on this leaf string
        if entropy_scanner is not None:
            leaf_matches = leaf_matches + entropy_scanner.scan(data, surface)

        # Luhn validation (drop false-positive CC matches)
        if match_validator is not None:
            leaf_matches = match_validator.filter(leaf_matches)

        # Context analysis using the leaf string as the context window
        if context_analyzer is not None:
            leaf_matches = context_analyzer.filter(leaf_matches, data)

        # Annotate every match with its JSON path
        for m in leaf_matches:
            matches.append(replace(m, source_path=leaf_path))

    # Non-string scalars pass through without scanning
    return matches


def redact_dict(
    data: Any,
    matches: list[DLPMatch],
    config,          # DLPConfig
    pattern_engine,  # PatternEngine
) -> Any:
    """
    Reconstruct the data structure with matched leaf values redacted.

    For each leaf string with REDACT-action matches, applies
    PatternEngine.apply_redactions() (with format-preserving or standard
    placeholders depending on config). Leaves without matches are unchanged.
    """
    from collections import defaultdict
    from .patterns import PatternEngine

    # Group redaction tuples by source_path
    path_redactions: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    for m in matches:
        if m.action != DLPAction.REDACT or m.source_path is None:
            continue
        for span in m.spans:
            if config.format_preserving_redaction:
                placeholder = PatternEngine.format_preserve(m.value, m.pattern_name)
            else:
                placeholder = f"[REDACTED_{m.category}_{m.pattern_name}]"
            path_redactions[m.source_path].append((span[0], span[1], placeholder))

    def _rebuild(node: Any, current_path: str) -> Any:
        if isinstance(node, dict):
            return {
                k: _rebuild(v, _join_path(current_path, str(k)))
                for k, v in node.items()
            }
        if isinstance(node, (list, tuple)):
            rebuilt = [
                _rebuild(item, _join_path(current_path, i))
                for i, item in enumerate(node)
            ]
            return type(node)(rebuilt)
        if isinstance(node, str):
            leaf_path = current_path or "<root>"
            redactions = path_redactions.get(leaf_path, [])
            if redactions:
                return PatternEngine.apply_redactions(node, redactions)
            return node
        return node  # int, float, bool, None — unchanged

    return _rebuild(data, "")
