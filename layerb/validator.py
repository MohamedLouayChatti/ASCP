"""
Layer B Ã¢â‚¬â€ C1 Typed Tool Security Contracts.

Runtime enforcement layer that validates every LLM tool call before execution.
Treats all tool calls as security-critical regardless of model intent.

Enforces:
  C1.1  JSON Schema validation
  C1.2  Permission scope enforcement
  C1.3  Argument constraints (path, domain, SQL, regex)
  C1.4  Preconditions (approval, evidence IDs, risk thresholds)
  C1.5  Postconditions (output sanitization, field redaction)
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

from layerb.runtime_registry import get_runtime_tool

try:
    from jsonschema import ValidationError
    from jsonschema import validate as _jsonschema_validate

    _HAS_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    _HAS_JSONSCHEMA = False
    ValidationError = Exception  # type: ignore[misc,assignment]

    def _jsonschema_validate(*_a, **_kw):
        raise RuntimeError("jsonschema is required for Layer B schema enforcement.")  # type: ignore[misc]


def validate(instance, schema):  # type: ignore[misc]
    if not _HAS_JSONSCHEMA:
        raise RuntimeError(
            "jsonschema is not installed; Layer B refuses to start without schema enforcement."
        )
    _jsonschema_validate(instance=instance, schema=schema)


logger = logging.getLogger(__name__)

UnknownCapabilityMode = Literal[
    "strict_block",
    "require_approval",
    "sandbox_allow",
    "auto_allow",
    "discover_only",
]
_UNKNOWN_CAPABILITY_MODES: tuple[UnknownCapabilityMode, ...] = (
    "strict_block",
    "require_approval",
    "sandbox_allow",
    "auto_allow",
    "discover_only",
)
_UNKNOWN_CAPABILITY_MODE_ALIASES: dict[str, str] = {
    "auto_allow": "sandbox_allow",
    "allow": "sandbox_allow",
}
_UNKNOWN_CAPABILITY_BASELINE_MAX_BODY_CHARS = 4000
_DANGEROUS_UNKNOWN_ARG_NAMES = frozenset(
    {
        "command",
        "code",
        "exec",
        "eval",
        "template",
        "script",
    }
)
_SEMANTIC_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "any",
        "by",
        "do",
        "for",
        "from",
        "get",
        "in",
        "of",
        "on",
        "the",
        "to",
        "tool",
        "using",
        "with",
    }
)
_INFERRED_FAMILY_KEYWORDS: dict[str, frozenset[str]] = {
    "shell_exec": frozenset({"bash", "cli", "cmd", "command", "console", "exec", "execute", "powershell", "run", "shell", "terminal"}),
    "db_query": frozenset({"database", "db", "fetch", "query", "record", "row", "select", "sql", "table"}),
    "web_fetch": frozenset({"api", "download", "fetch", "http", "https", "request", "scrape", "site", "url", "web"}),
    "file_write": frozenset({"append", "content", "create", "file", "path", "save", "update", "write", "writer"}),
    "file_read": frozenset({"cat", "document", "file", "load", "open", "path", "read", "reader", "view"}),
}


class PolicyValidationError(ValueError):
    """Raised when the Layer B policy itself is malformed."""


class PermissionScope(StrEnum):
    READ_ONLY = "read_only"
    WRITE = "write"
    NETWORK = "network"
    LOCAL_FS = "local_fs"
    EXTERNAL_API = "external_api"
    CUSTOM = "custom"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ComponentType(StrEnum):
    TOOL = "tool"
    RESOURCE = "resource"
    PROMPT = "prompt"
    RULE_OVERRIDE = "rule_override"


class ContractDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class ContractResult:
    decision: ContractDecision
    tool_name: str
    reason_code: str
    details: str = ""
    violations: list[str] = field(default_factory=list)
    approval_token: str | None = None
    sanitized_args: dict[str, Any] | None = None

    @property
    def capability_name(self) -> str:
        return self.tool_name


class SecurityEventObserver:
    """Best-effort sink for Layer B security decision events."""

    def emit(self, event: dict[str, Any]) -> None:
        raise NotImplementedError


class NoopSecurityEventObserver(SecurityEventObserver):
    def emit(self, event: dict[str, Any]) -> None:  # pragma: no cover - intentionally no-op
        _ = event


class CompositeSecurityEventObserver(SecurityEventObserver):
    """Dispatches Layer B events to multiple sinks."""

    def __init__(self, observers: list[SecurityEventObserver]) -> None:
        self._observers = list(observers)

    def emit(self, event: dict[str, Any]) -> None:
        for observer in self._observers:
            try:
                observer.emit(event)
            except Exception:
                logger.debug("Failed to emit Layer B event to observer %s", observer.__class__.__name__, exc_info=True)


class JsonlSecurityEventObserver(SecurityEventObserver):
    """Durable local event log for Layer B decisions."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    def emit(self, event: dict[str, Any]) -> None:
        payload = copy.deepcopy(event)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(payload, sort_keys=True, default=str)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


def _stringify_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _approval_fingerprint(
    component_type: str,
    component_name: str,
    args: dict[str, Any],
) -> str:
    raw = f"{component_type}:{component_name}:{_stringify_json(args)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _check_path_traversal(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return ".." in normalized.split("/")


def _resolve_policy_path(path: str) -> Path:
    path_obj = Path(path)
    try:
        return path_obj.resolve(strict=False)
    except OSError:
        return path_obj


def _check_path_allowlist(path: str, allowlist: list[str], denylist: list[str]) -> tuple[bool, str]:
    path_obj = _resolve_policy_path(path)
    for denied in denylist:
        try:
            path_obj.relative_to(_resolve_policy_path(denied))
            return False, f"path_in_denylist:{denied}"
        except ValueError:
            pass
    if allowlist:
        for allowed in allowlist:
            try:
                path_obj.relative_to(_resolve_policy_path(allowed))
                return True, ""
            except ValueError:
                pass
        return False, "path_not_in_allowlist"
    return True, ""


def _parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _check_ip_policy(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    cidr_denylist: list[str],
) -> tuple[bool, str]:
    for cidr in cidr_denylist:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return False, f"cidr_denied:{cidr}"
        except ValueError:
            logger.warning("Invalid CIDR in policy: %s", cidr)

    if addr.is_loopback:
        return False, "ip_loopback_blocked"
    if addr.is_link_local:
        return False, "ip_link_local_blocked"
    if addr.is_multicast:
        return False, "ip_multicast_blocked"
    if addr.is_reserved:
        return False, "ip_reserved_blocked"
    if addr.is_unspecified:
        return False, "ip_unspecified_blocked"
    if addr.is_private:
        return False, "ip_private_blocked"
    return True, ""


def _check_resolved_ips(host: str, cidr_denylist: list[str]) -> tuple[bool, str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        # The execution layer should still enforce redirects/final destinations.
        return True, ""

    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_text = str(sockaddr[0])
        if ip_text in seen:
            continue
        seen.add(ip_text)
        addr = _parse_ip_literal(ip_text)
        if addr is None:
            continue
        ok, reason = _check_ip_policy(addr, cidr_denylist)
        if not ok:
            return False, f"{reason}:{ip_text}"
    return True, ""


def _check_domain(
    url: str,
    allowlist: list[str],
    denylist: list[str],
    allowed_schemes: list[str],
    *,
    cidr_denylist: list[str] | None = None,
    resolve_dns: bool = False,
) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "invalid_url"

    if parsed.scheme not in allowed_schemes:
        return False, f"scheme_not_allowed:{parsed.scheme}"

    host = parsed.hostname or ""
    if parsed.scheme in {"http", "https"} and not host:
        return False, "missing_hostname"

    ssrf_patterns = [
        "169.254.",
        "metadata.google.internal",
        "0.0.0.0",
        "localhost",
        "127.",
        "::1",
    ]
    for pattern in ssrf_patterns:
        if pattern in host:
            return False, f"ssrf_blocked:{host}"

    literal_ip = _parse_ip_literal(host)
    if literal_ip is not None:
        ok, reason = _check_ip_policy(literal_ip, cidr_denylist or [])
        if not ok:
            return False, reason

    for denied in denylist:
        if host == denied or host.endswith("." + denied):
            return False, f"domain_denied:{denied}"

    if allowlist:
        for allowed in allowlist:
            if host == allowed or host.endswith("." + allowed):
                if resolve_dns and cidr_denylist:
                    return _check_resolved_ips(host, cidr_denylist)
                return True, ""
        return False, f"domain_not_in_allowlist:{host}"

    if resolve_dns and cidr_denylist:
        return _check_resolved_ips(host, cidr_denylist)

    return True, ""


def _check_sql(sql: str, allowlisted_tables: list[str]) -> tuple[bool, str]:
    normalized = sql.strip().upper()

    if ";" in sql.strip().rstrip(";"):
        return False, "sql_multi_statement"

    forbidden = [
        r"\bINSERT\b",
        r"\bUPDATE\b",
        r"\bDELETE\b",
        r"\bDROP\b",
        r"\bCREATE\b",
        r"\bALTER\b",
        r"\bEXEC\b",
        r"\bEXECUTE\b",
        r"\bXP_\w+",
        r"\bSP_\w+",
    ]
    for kw in forbidden:
        if re.search(kw, normalized):
            return False, f"sql_forbidden_keyword:{kw}"

    if not normalized.startswith("SELECT"):
        return False, "sql_must_start_with_select"

    if allowlisted_tables:
        referenced_tables = _extract_sql_table_names(sql)
        if not referenced_tables:
            return False, "sql_table_not_allowlisted"

        normalized_allowlist = {_normalize_sql_identifier(table) for table in allowlisted_tables}
        for table in referenced_tables:
            leaf_name = table.split(".")[-1]
            if table not in normalized_allowlist and leaf_name not in normalized_allowlist:
                return False, f"sql_table_not_allowlisted:{table}"

    return True, ""


def _deep_merge_dicts(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_dicts(merged[key], value)
        elif isinstance(value, list) and isinstance(merged.get(key), list):
            merged[key] = [*merged[key], *value]
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _merge_policy_dicts(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_policy_dicts(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _tokenize_text(value: str) -> set[str]:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    pieces = re.split(r"[^a-zA-Z0-9]+", normalized.lower())
    return {
        piece
        for piece in pieces
        if piece and len(piece) > 1 and piece not in _SEMANTIC_STOPWORDS
    }


def _strip_sql_comments_and_literals(sql: str) -> str:
    without_block_comments = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    without_line_comments = re.sub(r"--[^\r\n]*", " ", without_block_comments)
    return re.sub(r"'(?:''|[^'])*'", "''", without_line_comments)


def _normalize_sql_identifier(identifier: str) -> str:
    parts = [part.strip() for part in identifier.split(".") if part.strip()]
    normalized_parts: list[str] = []
    for part in parts:
        cleaned = part.strip("`\"")
        if cleaned.startswith("[") and cleaned.endswith("]"):
            cleaned = cleaned[1:-1]
        normalized_parts.append(cleaned.upper())
    return ".".join(part for part in normalized_parts if part)


def _extract_sql_table_names(sql: str) -> set[str]:
    sanitized = _strip_sql_comments_and_literals(sql)
    matches = re.findall(
        r"\b(?:FROM|JOIN)\s+([A-Za-z0-9_.`\[\]\"]+)",
        sanitized,
        flags=re.IGNORECASE,
    )
    return {
        normalized
        for match in matches
        if (normalized := _normalize_sql_identifier(match))
    }


def _schema_semantic_tokens(schema: Any) -> set[str]:
    if not isinstance(schema, dict):
        return set()

    tokens: set[str] = set()
    for key in ("title", "description"):
        value = schema.get(key)
        if isinstance(value, str):
            tokens.update(_tokenize_text(value))

    properties = schema.get("properties")
    if isinstance(properties, dict):
        for field_name, field_schema in properties.items():
            tokens.update(_tokenize_text(str(field_name)))
            tokens.update(_schema_semantic_tokens(field_schema))

    items = schema.get("items")
    if items is not None:
        tokens.update(_schema_semantic_tokens(items))

    return tokens


def _family_names_from_match(match_cfg: dict[str, Any]) -> set[str]:
    families: list[Any] = []
    for key in ("inferred_families", "semantic_families"):
        value = match_cfg.get(key)
        if isinstance(value, list):
            families.extend(value)
        elif value is not None:
            families.append(value)
    for key in ("inferred_family", "semantic_family"):
        value = match_cfg.get(key)
        if value is not None:
            families.append(value)
    return {str(item).strip().lower() for item in families if str(item).strip()}


def _infer_tool_family(
    tool_name: str,
    args: dict[str, Any] | None,
    invocation_context: dict[str, Any] | None,
) -> tuple[str | None, float]:
    args = args if isinstance(args, dict) else {}
    invocation_context = invocation_context if isinstance(invocation_context, dict) else {}

    tokens = _tokenize_text(tool_name)
    for field_name in args:
        tokens.update(_tokenize_text(str(field_name)))

    runtime_tool = get_runtime_tool(tool_name)
    if runtime_tool:
        description = runtime_tool.get("description")
        if isinstance(description, str):
            tokens.update(_tokenize_text(description))
        tool_path = runtime_tool.get("tool_path")
        if isinstance(tool_path, str):
            tokens.update(_tokenize_text(tool_path))
        tokens.update(_schema_semantic_tokens(runtime_tool.get("args_schema")))

    containers: list[dict[str, Any]] = [invocation_context]
    for key in ("tool", "metadata", "tool_metadata", "observed_tool"):
        nested = invocation_context.get(key)
        if isinstance(nested, dict):
            containers.append(nested)

    for container in containers:
        for key in ("argument_schema", "arg_schema", "args_schema", "input_schema", "parameters"):
            if key in container:
                tokens.update(_schema_semantic_tokens(container.get(key)))
        description = container.get("description")
        if isinstance(description, str):
            tokens.update(_tokenize_text(description))

    scored: list[tuple[str, float]] = []
    for family, keywords in _INFERRED_FAMILY_KEYWORDS.items():
        overlap = keywords.intersection(tokens)
        score = len(overlap) / len(keywords) if keywords else 0.0
        scored.append((family, score))

    scored.sort(key=lambda item: item[1], reverse=True)
    best_family, best_score = scored[0] if scored else (None, 0.0)
    if best_family is None or best_score < 0.20:
        return None, 0.0

    runner_up = scored[1][1] if len(scored) > 1 else 0.0
    if runner_up and (best_score - runner_up) < 0.10:
        return None, 0.0
    return best_family, round(best_score, 3)


def _extract_field_values(payload: dict[str, Any], field_path: str) -> list[Any]:
    values: list[Any] = [payload]
    for part in field_path.split("."):
        next_values: list[Any] = []
        for value in values:
            if isinstance(value, dict) and part in value:
                next_values.append(value[part])
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and part in item:
                        next_values.append(item[part])
        values = next_values
    return values


def _match_arg_rule(candidate: Any, rule: dict[str, Any]) -> bool:
    text = "" if candidate is None else str(candidate)
    op = str(rule.get("op", "equals"))
    expected = rule.get("value", "")

    if op == "equals":
        return text == str(expected)
    if op == "contains":
        return str(expected) in text
    if op == "regex":
        return re.search(str(expected), text) is not None
    if op == "starts_with":
        return text.startswith(str(expected))
    if op == "ends_with":
        return text.endswith(str(expected))
    if op == "host_equals":
        return (urlparse(text).hostname or "") == str(expected)
    if op == "host_suffix":
        host = urlparse(text).hostname or ""
        expected_str = str(expected)
        return host == expected_str or host.endswith("." + expected_str)
    return False


def _find_resource_match(resource_uri: str, name: str, contract: dict[str, Any]) -> bool:
    if resource_uri == name:
        return True

    match_cfg = contract.get("match", {})
    for prefix in match_cfg.get("uri_prefixes", []):
        if resource_uri.startswith(prefix):
            return True

    for pattern in match_cfg.get("uri_regexes", []):
        if re.search(pattern, resource_uri):
            return True

    schemes = match_cfg.get("schemes", [])
    if schemes:
        return urlparse(resource_uri).scheme in schemes

    return False


def _normalize_uri_path(path: str) -> str:
    if re.match(r"^/[A-Za-z]:/", path):
        return path[1:]
    return path


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_")}
    return {}


def _normalize_chain_history(history: Any) -> list[str]:
    if not isinstance(history, list):
        return []
    normalized: list[str] = []
    for item in history:
        if isinstance(item, str) and item:
            normalized.append(item)
            continue
        if isinstance(item, dict):
            for key in ("capability", "capability_name", "tool", "tool_name", "name"):
                value = item.get(key)
                if isinstance(value, str) and value:
                    normalized.append(value)
                    break
    return normalized


def _sequence_matches(history: list[str], capability_name: str, expected_chain: list[str]) -> bool:
    if not expected_chain:
        return False
    full_chain = [*history, capability_name]
    if len(expected_chain) > len(full_chain):
        return False
    return full_chain[-len(expected_chain) :] == expected_chain


def _risk_weight(level: str) -> float:
    mapping = {
        RiskLevel.LOW.value: 0.2,
        RiskLevel.MEDIUM.value: 0.5,
        RiskLevel.HIGH.value: 0.8,
        RiskLevel.CRITICAL.value: 1.0,
    }
    return mapping.get(level, 0.4)


@dataclass(frozen=True)
class ResolvedContract:
    contract_name: str
    contract: dict[str, Any]
    match_type: str = "exact_name"
    schema_hash: str | None = None
    inferred_family: str | None = None
    match_score: float | None = None


def _normalize_schema_hash(value: Any) -> str:
    normalized = str(value).strip().lower()
    if normalized.startswith("sha256:"):
        return normalized.split(":", 1)[1]
    return normalized


def _compute_schema_hash(schema: Any) -> str:
    return hashlib.sha256(_stringify_json(schema).encode("utf-8")).hexdigest()


def _normalize_unknown_capability_mode(value: str) -> str:
    normalized = str(value).strip().lower()
    return _UNKNOWN_CAPABILITY_MODE_ALIASES.get(normalized, normalized)


def _schema_hashes_from_match(match_cfg: dict[str, Any]) -> set[str]:
    hashes: list[Any] = []
    for key in ("argument_schema_hashes", "arg_schema_hashes", "schema_hashes"):
        value = match_cfg.get(key)
        if isinstance(value, list):
            hashes.extend(value)
        elif value is not None:
            hashes.append(value)
    for key in ("argument_schema_hash", "arg_schema_hash", "schema_hash"):
        value = match_cfg.get(key)
        if value is not None:
            hashes.append(value)
    return {_normalize_schema_hash(item) for item in hashes if str(item).strip()}


def _is_catch_all_match(name: str, contract: dict[str, Any]) -> bool:
    if name == "*":
        return True
    match_cfg = contract.get("match", {})
    if not isinstance(match_cfg, dict):
        return False
    return bool(match_cfg.get("catch_all") or match_cfg.get("default"))


def _resolve_invocation_schema_hash(invocation_context: dict[str, Any] | None) -> str | None:
    if not isinstance(invocation_context, dict):
        return None

    containers: list[dict[str, Any]] = [invocation_context]
    for key in ("tool", "metadata", "tool_metadata", "observed_tool"):
        nested = invocation_context.get(key)
        if isinstance(nested, dict):
            containers.append(nested)

    for container in containers:
        for key in (
            "argument_schema_hash",
            "arg_schema_hash",
            "args_schema_hash",
            "schema_hash",
            "input_schema_hash",
        ):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                return _normalize_schema_hash(value)

        for key in ("argument_schema", "arg_schema", "args_schema", "input_schema", "parameters"):
            if key in container and container[key] is not None:
                return _compute_schema_hash(container[key])

    return None


class ContractValidator:
    """
    Loads tool, resource, and prompt contracts from YAML policy and enforces them
    at runtime. The policy file is hot-reloaded when it changes so dynamic rules
    can be updated without restarting the gateway.
    """

    def __init__(
        self,
        tool_permissions_path: str | Path,
        schemas_dir: str | Path,
        *,
        base_policy_path: str | Path | None = None,
        unknown_capability_mode: UnknownCapabilityMode = "auto_allow",
        security_observer: SecurityEventObserver | None = None,
        event_log_path: str | Path | None = None,
        audit_log_path: str | Path | None = None,
    ) -> None:
        if not _HAS_JSONSCHEMA:
            raise RuntimeError(
                "jsonschema is not installed; Layer B refuses to start without schema enforcement."
            )
        normalized_unknown_mode = _normalize_unknown_capability_mode(unknown_capability_mode)
        if normalized_unknown_mode not in _UNKNOWN_CAPABILITY_MODES:
            expected = ", ".join(_UNKNOWN_CAPABILITY_MODES)
            raise ValueError(
                "unknown_capability_mode must be one of "
                f"{expected}; got {unknown_capability_mode!r}."
            )
        self._permissions_path = Path(tool_permissions_path)
        self._base_policy_path = Path(base_policy_path) if base_policy_path else None
        self._schemas_dir = Path(schemas_dir)
        self._unknown_capability_mode = normalized_unknown_mode
        self._raw_policy: dict[str, Any] = {}
        self._capability_permissions: dict[str, Any] = {}
        self._resource_permissions: dict[str, Any] = {}
        self._prompt_permissions: dict[str, Any] = {}
        self._capability_sequences: dict[str, Any] = {}
        self._runtime_rules: dict[str, Any] = {}
        self._schemas: dict[tuple[str, str], Any] = {}
        self._schema_paths: dict[tuple[str, str], Path] = {}
        self._pending_approvals: dict[str, dict[str, Any]] = {}
        self._loaded_mtimes_ns: tuple[int | None, int | None] | None = None
        self._loaded_schema_mtimes_ns: dict[tuple[str, str], str | None] = {}
        self._event_log_path = Path(event_log_path or audit_log_path) if (event_log_path or audit_log_path) else None
        if security_observer is not None:
            self._security_observer = security_observer
        else:
            observers: list[SecurityEventObserver] = []
            if self._event_log_path is not None:
                observers.append(JsonlSecurityEventObserver(self._event_log_path))
            if not observers:
                self._security_observer = NoopSecurityEventObserver()
            elif len(observers) == 1:
                self._security_observer = observers[0]
            else:
                self._security_observer = CompositeSecurityEventObserver(observers)
        self._load()

    def _emit_security_event(
        self,
        *,
        component_type: str,
        component_name: str,
        args: dict[str, Any],
        result: ContractResult,
        agent_id: str,
        framework: str,
        invocation_context: dict[str, Any] | None = None,
        decision_metadata: dict[str, Any] | None = None,
    ) -> None:
        trace = copy.deepcopy(decision_metadata or {})
        invocation_copy = copy.deepcopy(invocation_context or {})
        schema_hash = _resolve_invocation_schema_hash(invocation_copy)
        if schema_hash is not None and "input_schema_hash" not in trace:
            trace["input_schema_hash"] = schema_hash
        self._security_observer.emit(
            {
                "event_id": str(uuid.uuid4()),
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "component_type": component_type,
                "component_name": component_name,
                "decision": result.decision.value,
                "reason_code": result.reason_code,
                "details": result.details,
                "violations": list(result.violations),
                "approval_token": result.approval_token,
                "approval_token_issued": bool(result.approval_token),
                "sanitized_args": copy.deepcopy(result.sanitized_args),
                "operation_fingerprint": _approval_fingerprint(component_type, component_name, args),
                "agent_id": agent_id,
                "framework": framework,
                "args": copy.deepcopy(args),
                "invocation_context": invocation_copy,
                "trace": trace,
            }
        )

    def _finalize_result(
        self,
        *,
        component_type: str,
        component_name: str,
        args: dict[str, Any],
        result: ContractResult,
        agent_id: str,
        framework: str,
        invocation_context: dict[str, Any] | None = None,
        decision_metadata: dict[str, Any] | None = None,
    ) -> ContractResult:
        self._emit_security_event(
            component_type=component_type,
            component_name=component_name,
            args=args,
            result=result,
            agent_id=agent_id,
            framework=framework,
            invocation_context=invocation_context,
            decision_metadata=decision_metadata,
        )
        return result

    def _finalize_component_result(
        self,
        *,
        component_type: str,
        component_name: str,
        args: dict[str, Any],
        result: ContractResult,
        agent_id: str,
        framework: str,
        invocation_context: dict[str, Any] | None = None,
        decision_metadata: dict[str, Any] | None = None,
    ) -> ContractResult:
        return self._finalize_result(
            component_type=component_type,
            component_name=component_name,
            args=args,
            result=result,
            agent_id=agent_id,
            framework=framework,
            invocation_context=invocation_context,
            decision_metadata=decision_metadata,
        )

    def _block_result(
        self,
        name: str,
        reason_code: str,
        details: str,
        *,
        violation: str = "I1",
    ) -> ContractResult:
        return ContractResult(
            decision=ContractDecision.BLOCK,
            tool_name=name,
            reason_code=reason_code,
            details=details,
            violations=[violation],
        )

    def _run_component_checks(
        self,
        *,
        component_type: str,
        component_name: str,
        args: dict[str, Any],
        agent_id: str,
        framework: str,
        checks: list[Callable[[], ContractResult | None]],
        success_result: ContractResult,
        invocation_context: dict[str, Any] | None = None,
        decision_metadata: dict[str, Any] | None = None,
    ) -> ContractResult:
        for check in checks:
            result = check()
            if result is not None:
                return self._finalize_component_result(
                    component_type=component_type,
                    component_name=component_name,
                    args=args,
                    result=result,
                    agent_id=agent_id,
                    framework=framework,
                    invocation_context=invocation_context,
                    decision_metadata=decision_metadata,
                )
        return self._finalize_component_result(
            component_type=component_type,
            component_name=component_name,
            args=args,
            result=success_result,
            agent_id=agent_id,
            framework=framework,
            invocation_context=invocation_context,
            decision_metadata=decision_metadata,
        )

    def _get_capability_contracts(self, policy: dict[str, Any]) -> dict[str, Any]:
        capabilities = policy.get("capabilities")
        if isinstance(capabilities, dict) and capabilities:
            return capabilities
        tools = policy.get("tools", {})
        return tools if isinstance(tools, dict) else {}

    def _get_runtime_capability_rules(self) -> dict[str, Any]:
        rules = self._runtime_rules.get("capabilities")
        if isinstance(rules, dict) and rules:
            return rules
        tools = self._runtime_rules.get("tools", {})
        return tools if isinstance(tools, dict) else {}

    def _get_capability_sequence_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        sequences = policy.get("capability_sequences", {})
        return sequences if isinstance(sequences, dict) else {}

    def _validate_policy_shape(self, policy: dict[str, Any]) -> None:
        for top_level in (
            "capabilities",
            "tools",
            "resources",
            "prompts",
            "runtime_rules",
            "capability_sequences",
        ):
            value = policy.get(top_level, {})
            if value is None:
                continue
            if not isinstance(value, dict):
                raise PolicyValidationError(f"Policy section '{top_level}' must be a mapping.")

        valid_scopes = {item.value for item in PermissionScope}
        valid_risks = {item.value for item in RiskLevel}
        for name, contract in self._get_capability_contracts(policy).items():
            if not isinstance(contract, dict):
                raise PolicyValidationError(f"Capability contract '{name}' must be a mapping.")
            risk = contract.get("risk", RiskLevel.UNKNOWN.value)
            if risk not in valid_risks:
                raise PolicyValidationError(f"Capability '{name}' has invalid risk '{risk}'.")
            scopes = contract.get("scopes", [])
            if not isinstance(scopes, list):
                raise PolicyValidationError(f"Capability '{name}' scopes must be a list.")
            invalid_scopes = [scope for scope in scopes if scope not in valid_scopes]
            if invalid_scopes:
                joined = ", ".join(map(str, invalid_scopes))
                raise PolicyValidationError(f"Capability '{name}' has invalid scopes: {joined}.")
            if "approval_required" in contract and not isinstance(contract["approval_required"], bool):
                raise PolicyValidationError(
                    f"Capability '{name}' approval_required must be boolean."
                )
            if "match" in contract and not isinstance(contract["match"], dict):
                raise PolicyValidationError(f"Capability '{name}' match must be a mapping.")

        schema_hash_owners: dict[str, str] = {}
        catch_all_names: list[str] = []
        inferred_family_owners: dict[str, str] = {}
        for name, contract in self._get_capability_contracts(policy).items():
            if not isinstance(contract, dict):
                continue
            match_cfg = contract.get("match", {})
            if not isinstance(match_cfg, dict):
                continue
            for schema_hash in _schema_hashes_from_match(match_cfg):
                owner = schema_hash_owners.get(schema_hash)
                if owner is not None and owner != name:
                    raise PolicyValidationError(
                        "Capability schema hash matches must be unique; "
                        f"'{name}' and '{owner}' both declare '{schema_hash}'."
                    )
                schema_hash_owners[schema_hash] = name
            for family_name in _family_names_from_match(match_cfg):
                owner = inferred_family_owners.get(family_name)
                if owner is not None and owner != name:
                    raise PolicyValidationError(
                        "Capability inferred family matches must be unique; "
                        f"'{name}' and '{owner}' both declare '{family_name}'."
                    )
                inferred_family_owners[family_name] = name
            if _is_catch_all_match(name, contract):
                catch_all_names.append(name)
        if len(catch_all_names) > 1:
            joined = ", ".join(catch_all_names)
            raise PolicyValidationError(
                f"Only one catch-all capability is allowed; found {joined}."
            )

    def _load(self) -> None:
        self._schemas = {}
        self._schema_paths = {}

        raw: dict[str, Any] = {}
        base_mtime: int | None = None
        policy_mtime: int | None = None
        loaded_any_policy = False

        if yaml is not None and self._base_policy_path and self._base_policy_path.exists():
            base_raw = yaml.safe_load(self._base_policy_path.read_text(encoding="utf-8")) or {}
            raw = _merge_policy_dicts(raw, base_raw)
            base_mtime = self._base_policy_path.stat().st_mtime_ns
            loaded_any_policy = True

        if yaml is not None and self._permissions_path.exists():
            project_raw = yaml.safe_load(self._permissions_path.read_text(encoding="utf-8")) or {}
            raw = _merge_policy_dicts(raw, project_raw)
            policy_mtime = self._permissions_path.stat().st_mtime_ns
            loaded_any_policy = True

        if loaded_any_policy:
            self._validate_policy_shape(raw)
            self._raw_policy = raw
            self._capability_permissions = self._get_capability_contracts(raw)
            self._resource_permissions = raw.get("resources", {})
            self._prompt_permissions = raw.get("prompts", {})
            self._capability_sequences = self._get_capability_sequence_policy(raw)
            self._runtime_rules = raw.get("runtime_rules", {})
            self._loaded_mtimes_ns = (policy_mtime, base_mtime)
        else:
            logger.warning("Tool permissions file not found: %s", self._permissions_path)
            self._raw_policy = {}
            self._capability_permissions = {}
            self._resource_permissions = {}
            self._prompt_permissions = {}
            self._capability_sequences = {}
            self._runtime_rules = {}
            self._loaded_mtimes_ns = None

        self._preload_schemas("tool", self._capability_permissions)
        self._preload_schemas("resource", self._resource_permissions)
        self._preload_schemas("prompt", self._prompt_permissions)
        self._loaded_schema_mtimes_ns = self._current_schema_mtimes()
        logger.info(
            "Loaded contracts capabilities=%d resources=%d prompts=%d",
            len(self._capability_permissions),
            len(self._resource_permissions),
            len(self._prompt_permissions),
        )

    def _preload_schemas(self, kind: str, contracts: dict[str, Any]) -> None:
        for name, config in contracts.items():
            schema_rel = config.get("schema")
            if not schema_rel:
                continue
            schema_path = self._schemas_dir / Path(schema_rel).name
            alt = Path(schema_rel)
            selected_path: Path | None = None
            if schema_path.exists():
                selected_path = schema_path
            elif alt.exists():
                selected_path = alt

            if selected_path is None:
                raise PolicyValidationError(f"Schema not found for {kind} '{name}': {schema_rel}")

            self._schema_paths[(kind, name)] = selected_path
            self._schemas[(kind, name)] = json.loads(selected_path.read_text(encoding="utf-8"))

    def _current_schema_mtimes(self) -> dict[tuple[str, str], str | None]:
        return {
            key: hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
            for key, path in self._schema_paths.items()
        }

    def _maybe_reload(self) -> None:
        policy_mtime = self._permissions_path.stat().st_mtime_ns if self._permissions_path.exists() else None
        base_mtime = (
            self._base_policy_path.stat().st_mtime_ns
            if self._base_policy_path is not None and self._base_policy_path.exists()
            else None
        )
        current_schema_mtimes = self._current_schema_mtimes()
        if (
            self._loaded_mtimes_ns != (policy_mtime, base_mtime)
            or self._loaded_schema_mtimes_ns != current_schema_mtimes
        ):
            self._load()

    def _merged_contract(self, kind: str, name: str, base_contract: dict[str, Any]) -> dict[str, Any]:
        if kind == "tool":
            runtime = self._get_runtime_capability_rules().get(name, {})
        else:
            runtime = self._runtime_rules.get(f"{kind}s", {}).get(name, {})
        if not runtime:
            return copy.deepcopy(base_contract)
        return _deep_merge_dicts(base_contract, runtime)

    def _resolve_capability_contract(
        self,
        tool_name: str,
        *,
        args: dict[str, Any] | None = None,
        invocation_context: dict[str, Any] | None = None,
    ) -> ResolvedContract | None:
        exact_contract = self._capability_permissions.get(tool_name)
        if isinstance(exact_contract, dict):
            return ResolvedContract(
                contract_name=tool_name,
                contract=self._merged_contract("tool", tool_name, exact_contract),
                match_type="exact_name",
            )

        schema_hash = _resolve_invocation_schema_hash(invocation_context)
        if schema_hash is not None:
            for name, contract in self._capability_permissions.items():
                if not isinstance(contract, dict):
                    continue
                match_cfg = contract.get("match", {})
                if not isinstance(match_cfg, dict):
                    continue
                if schema_hash in _schema_hashes_from_match(match_cfg):
                    return ResolvedContract(
                        contract_name=name,
                        contract=self._merged_contract("tool", name, contract),
                        match_type="argument_schema_hash",
                        schema_hash=schema_hash,
                    )

        inferred_family, match_score = _infer_tool_family(tool_name, args, invocation_context)
        if inferred_family is not None:
            for name, contract in self._capability_permissions.items():
                if not isinstance(contract, dict):
                    continue
                match_cfg = contract.get("match", {})
                if not isinstance(match_cfg, dict):
                    continue
                if inferred_family in _family_names_from_match(match_cfg):
                    return ResolvedContract(
                        contract_name=name,
                        contract=self._merged_contract("tool", name, contract),
                        match_type="inferred_family",
                        inferred_family=inferred_family,
                        match_score=match_score,
                    )

        for name, contract in self._capability_permissions.items():
            if not isinstance(contract, dict):
                continue
            if _is_catch_all_match(name, contract):
                return ResolvedContract(
                    contract_name=name,
                    contract=self._merged_contract("tool", name, contract),
                    match_type="catch_all_default",
                )

        return None

    def _resolve_resource_contract(self, resource_uri: str) -> ResolvedContract | None:
        for name, contract in self._resource_permissions.items():
            if _find_resource_match(resource_uri, name, contract):
                return ResolvedContract(
                    contract_name=name,
                    contract=self._merged_contract("resource", name, contract),
                )
        return None

    def _validate_schema(
        self,
        kind: str,
        schema_name: str,
        payload: dict[str, Any],
        *,
        result_name: str | None = None,
    ) -> ContractResult | None:
        schema = self._schemas.get((kind, schema_name))
        if not schema:
            return None
        try:
            validate(instance=payload, schema=schema)
        except ValidationError as exc:
            return ContractResult(
                decision=ContractDecision.BLOCK,
                tool_name=result_name or schema_name,
                reason_code="SCHEMA_VIOLATION",
                details=exc.message,
                violations=["I2"],
            )
        return None

    def _issue_or_validate_approval(
        self,
        *,
        component_type: str,
        component_name: str,
        args: dict[str, Any],
        approval_token: str | None,
        approval_required: bool,
        details: str | None = None,
    ) -> ContractResult | None:
        if not approval_required:
            return None

        fingerprint = _approval_fingerprint(component_type, component_name, args)

        if approval_token and approval_token in self._pending_approvals:
            pending = self._pending_approvals[approval_token]
            if (
                pending.get("component_type") == component_type
                and pending.get("component_name") == component_name
                and pending.get("fingerprint") == fingerprint
            ):
                del self._pending_approvals[approval_token]
                logger.info(
                    "Approval granted for %s=%s token=%s",
                    component_type,
                    component_name,
                    approval_token,
                )
                return None
            return ContractResult(
                decision=ContractDecision.BLOCK,
                tool_name=component_name,
                reason_code="APPROVAL_TOKEN_MISMATCH",
                details="Approval token was issued for a different operation or arguments.",
                violations=["I1"],
            )

        token = str(uuid.uuid4())
        self._pending_approvals[token] = {
            "component_type": component_type,
            "component_name": component_name,
            "fingerprint": fingerprint,
            "args": copy.deepcopy(args),
        }
        return ContractResult(
            decision=ContractDecision.REQUIRE_APPROVAL,
            tool_name=component_name,
            reason_code="APPROVAL_REQUIRED",
            details=details
            or f"{component_type.title()} '{component_name}' requires human approval before access.",
            approval_token=token,
        )

    def _apply_dynamic_arg_rules(
        self,
        name: str,
        args: dict[str, Any],
        constraints: dict[str, Any],
        *,
        approval_token: str | None = None,
    ) -> ContractResult | None:
        for rule in constraints.get("arg_rules", []):
            field = str(rule.get("field", "")).strip()
            if not field:
                continue
            for candidate in _extract_field_values(args, field):
                if not _match_arg_rule(candidate, rule):
                    continue
                action = str(rule.get("action", "block"))
                reason = str(rule.get("reason", "ARG_RULE_BLOCKED"))
                details = str(
                    rule.get(
                        "details",
                        f"Dynamic arg rule matched field '{field}' for {name}.",
                    )
                )
                if action == ContractDecision.REQUIRE_APPROVAL.value:
                    return self._issue_or_validate_approval(
                        component_type=ComponentType.RULE_OVERRIDE.value,
                        component_name=name,
                        args=args,
                        approval_token=approval_token,
                        approval_required=True,
                        details=details,
                    )
                return ContractResult(
                    decision=ContractDecision.BLOCK,
                    tool_name=name,
                    reason_code=reason,
                    details=details,
                    violations=["I2"],
                )
        return None

    def _validate_identity_constraints(
        self,
        name: str,
        *,
        agent_id: str,
        framework: str,
        constraints: dict[str, Any],
    ) -> ContractResult | None:
        allowed_agents = constraints.get("allowed_agents", [])
        if allowed_agents and agent_id not in allowed_agents:
            return ContractResult(
                decision=ContractDecision.BLOCK,
                tool_name=name,
                reason_code="AGENT_NOT_AUTHORIZED",
                details=f"Agent '{agent_id}' is not authorized for '{name}'.",
                violations=["I1"],
            )

        allowed_frameworks = constraints.get("allowed_frameworks", [])
        if allowed_frameworks and framework not in allowed_frameworks:
            return ContractResult(
                decision=ContractDecision.BLOCK,
                tool_name=name,
                reason_code="FRAMEWORK_NOT_AUTHORIZED",
                details=f"Framework '{framework}' is not authorized for '{name}'.",
                violations=["I1"],
            )
        return None

    def _validate_preconditions(
        self,
        name: str,
        *,
        constraints: dict[str, Any],
        evidence_ids: list[str] | None,
        trust_vector: Any | None,
    ) -> ContractResult | None:
        if constraints.get("require_evidence", False):
            min_evidence_ids = int(constraints.get("min_evidence_ids", 1))
            if not evidence_ids or len(evidence_ids) < min_evidence_ids:
                return ContractResult(
                    decision=ContractDecision.BLOCK,
                    tool_name=name,
                    reason_code="EVIDENCE_REQUIRED",
                    details=f"Tool '{name}' requires at least {min_evidence_ids} evidence IDs.",
                    violations=["I2"],
                )

        if trust_vector is not None:
            trust_payload = _as_dict(trust_vector)
            min_grounding_score = constraints.get("min_grounding_score")
            if min_grounding_score is not None:
                score = float(trust_payload.get("grounding_score", 0.0))
                if score < float(min_grounding_score):
                    return ContractResult(
                        decision=ContractDecision.BLOCK,
                        tool_name=name,
                        reason_code="GROUNDING_THRESHOLD_NOT_MET",
                        details=(
                            f"Tool '{name}' requires grounding_score >= {min_grounding_score}, "
                            f"received {score:.2f}."
                        ),
                        violations=["I2"],
                    )

            max_hallucination_risk = constraints.get("max_hallucination_risk")
            if max_hallucination_risk is not None:
                risk = float(trust_payload.get("hallucination_risk", 1.0))
                if risk > float(max_hallucination_risk):
                    return ContractResult(
                        decision=ContractDecision.BLOCK,
                        tool_name=name,
                        reason_code="HALLUCINATION_RISK_TOO_HIGH",
                        details=(
                            f"Tool '{name}' requires hallucination_risk <= {max_hallucination_risk}, "
                            f"received {risk:.2f}."
                        ),
                        violations=["I2"],
                    )
        return None

    def _validate_field_lengths(
        self,
        name: str,
        args: dict[str, Any],
        constraints: dict[str, Any],
    ) -> ContractResult | None:
        max_arg_lengths = constraints.get("max_arg_lengths", {})
        if not isinstance(max_arg_lengths, dict):
            return None
        for field_name, max_length in max_arg_lengths.items():
            if field_name not in args:
                continue
            if len(str(args[field_name])) > int(max_length):
                return ContractResult(
                    decision=ContractDecision.BLOCK,
                    tool_name=name,
                    reason_code="ARGUMENT_TOO_LARGE",
                    details=f"Argument '{field_name}' exceeds maximum length {max_length}.",
                    violations=["I2"],
                )
        return None

    def _sequence_policy_for_workflow(self, workflow: str | None) -> dict[str, Any]:
        if not workflow:
            return {}
        workflows = self._capability_sequences.get("workflows", {})
        if not isinstance(workflows, dict):
            return {}
        policy = workflows.get(workflow, {})
        return policy if isinstance(policy, dict) else {}

    def _validate_transition_graph(
        self,
        capability_name: str,
        history: list[str],
        graph: dict[str, Any],
        *,
        reason_code: str,
    ) -> ContractResult | None:
        if not isinstance(graph, dict) or not graph:
            return None

        previous = history[-1] if history else "__start__"
        modeled_nodes: set[str] = set()
        for source, targets in graph.items():
            if isinstance(source, str):
                modeled_nodes.add(source)
            if isinstance(targets, list):
                modeled_nodes.update(str(target) for target in targets if isinstance(target, str))

        if capability_name not in modeled_nodes and "*" not in graph:
            return None

        allowed_next = graph.get(previous)
        if allowed_next is None:
            if previous != "__start__":
                wildcard_next = graph.get("*")
                if wildcard_next is not None:
                    allowed_next = wildcard_next
                elif previous in modeled_nodes:
                    allowed_next = []

        if allowed_next is None:
            return None
        normalized_allowed = [
            str(target) for target in allowed_next if isinstance(target, (str, int, float))
        ]
        if capability_name in normalized_allowed or "*" in normalized_allowed:
            return None
        return ContractResult(
            decision=ContractDecision.BLOCK,
            tool_name=capability_name,
            reason_code=reason_code,
            details=f"Capability '{capability_name}' cannot follow '{previous}'.",
            violations=["I1"],
        )

    def _validate_allowed_capabilities(
        self,
        capability_name: str,
        workflow_policy: dict[str, Any],
    ) -> ContractResult | None:
        allowed_capabilities = workflow_policy.get("allowed_capabilities", [])
        if allowed_capabilities and capability_name not in allowed_capabilities:
            return ContractResult(
                decision=ContractDecision.BLOCK,
                tool_name=capability_name,
                reason_code="WORKFLOW_CAPABILITY_NOT_ALLOWED",
                details=f"Capability '{capability_name}' is not allowed for this workflow.",
                violations=["I1"],
            )

        denied_capabilities = workflow_policy.get("denied_capabilities", [])
        if capability_name in denied_capabilities:
            return ContractResult(
                decision=ContractDecision.BLOCK,
                tool_name=capability_name,
                reason_code="WORKFLOW_CAPABILITY_DENIED",
                details=f"Capability '{capability_name}' is denied for this workflow.",
                violations=["I1"],
            )
        return None

    def _validate_required_evidence_for_chain(
        self,
        capability_name: str,
        history: list[str],
        evidence_ids: list[str] | None,
        sequence_policy: dict[str, Any],
    ) -> ContractResult | None:
        required_evidence = sequence_policy.get("required_evidence", [])
        if not isinstance(required_evidence, list):
            return None
        for item in required_evidence:
            if not isinstance(item, dict):
                continue
            chain = item.get("chain", [])
            if not isinstance(chain, list) or not all(isinstance(part, str) for part in chain):
                continue
            if not _sequence_matches(history, capability_name, chain):
                continue
            min_evidence_ids = int(item.get("min_evidence_ids", 1))
            if not evidence_ids or len(evidence_ids) < min_evidence_ids:
                return ContractResult(
                    decision=ContractDecision.BLOCK,
                    tool_name=capability_name,
                    reason_code="CHAIN_EVIDENCE_REQUIRED",
                    details=(
                        f"Capability chain {chain} requires at least "
                        f"{min_evidence_ids} evidence IDs."
                    ),
                    violations=["I2"],
                )
        return None

    def _validate_cumulative_risk(
        self,
        capability_name: str,
        history: list[str],
        workflow_policy: dict[str, Any],
        contract: dict[str, Any],
        approval_token: str | None,
    ) -> ContractResult | None:
        max_cumulative_risk = workflow_policy.get("max_cumulative_risk")
        if max_cumulative_risk is None:
            return None

        cumulative_risk = 0.0
        for previous_name in history:
            cumulative_risk += _risk_weight(self.get_capability_risk_level(previous_name))
        cumulative_risk += _risk_weight(str(contract.get("risk", RiskLevel.UNKNOWN.value)))

        if cumulative_risk <= float(max_cumulative_risk):
            return None

        action = str(workflow_policy.get("risk_escalation_action", ContractDecision.REQUIRE_APPROVAL.value))
        details = (
            f"Cumulative capability risk {cumulative_risk:.2f} exceeded workflow threshold "
            f"{float(max_cumulative_risk):.2f}."
        )
        if action == ContractDecision.BLOCK.value:
            return ContractResult(
                decision=ContractDecision.BLOCK,
                tool_name=capability_name,
                reason_code="CUMULATIVE_RISK_BLOCKED",
                details=details,
                violations=["I2"],
            )

        return self._issue_or_validate_approval(
            component_type=ComponentType.RULE_OVERRIDE.value,
            component_name=capability_name,
            args={"history": history, "capability": capability_name},
            approval_token=approval_token,
            approval_required=True,
            details=details,
        )

    def _validate_intent_and_state(
        self,
        capability_name: str,
        workflow_policy: dict[str, Any],
        invocation_context: dict[str, Any],
    ) -> ContractResult | None:
        intent_policy = workflow_policy.get("intent_requirements", {})
        if isinstance(intent_policy, dict):
            capability_intent = intent_policy.get(capability_name, {})
            if isinstance(capability_intent, dict):
                intent_text = " ".join(
                    str(invocation_context.get(key, ""))
                    for key in ("user_intent", "query", "prompt")
                    if invocation_context.get(key)
                ).lower()
                any_of = [str(item).lower() for item in capability_intent.get("any_of", [])]
                if any_of and not any(token in intent_text for token in any_of):
                    return ContractResult(
                        decision=ContractDecision.BLOCK,
                        tool_name=capability_name,
                        reason_code="INTENT_MISMATCH",
                        details=(
                            f"Capability '{capability_name}' does not match the current user intent."
                        ),
                        violations=["I2"],
                    )

        state_policy = workflow_policy.get("state_requirements", {})
        if isinstance(state_policy, dict):
            capability_state = state_policy.get(capability_name, {})
            state = invocation_context.get("state", {})
            if isinstance(capability_state, dict) and isinstance(state, dict):
                for key in capability_state.get("required_keys", []):
                    if key not in state:
                        return ContractResult(
                            decision=ContractDecision.BLOCK,
                            tool_name=capability_name,
                            reason_code="STATE_REQUIREMENT_MISSING",
                            details=f"Capability '{capability_name}' requires state key '{key}'.",
                            violations=["I2"],
                        )
                equals = capability_state.get("equals", {})
                if isinstance(equals, dict):
                    for key, expected in equals.items():
                        if state.get(key) != expected:
                            return ContractResult(
                                decision=ContractDecision.BLOCK,
                                tool_name=capability_name,
                                reason_code="STATE_REQUIREMENT_NOT_MET",
                                details=(
                                    f"Capability '{capability_name}' requires state '{key}' "
                                    f"to equal {expected!r}."
                                ),
                                violations=["I2"],
                            )
        return None

    def _validate_capability_sequence(
        self,
        capability_name: str,
        contract: dict[str, Any],
        *,
        evidence_ids: list[str] | None,
        invocation_context: dict[str, Any] | None,
        approval_token: str | None,
    ) -> ContractResult | None:
        context = invocation_context or {}
        history = _normalize_chain_history(context.get("history") or context.get("chain"))
        workflow = context.get("workflow")
        workflow_str = str(workflow) if isinstance(workflow, str) and workflow else None
        workflow_policy = self._sequence_policy_for_workflow(workflow_str)

        if workflow_str is None and not history:
            return None

        allowed_capability_result = self._validate_allowed_capabilities(capability_name, workflow_policy)
        if allowed_capability_result is not None:
            return allowed_capability_result

        evidence_result = self._validate_required_evidence_for_chain(
            capability_name,
            history,
            evidence_ids,
            self._capability_sequences,
        )
        if evidence_result is not None:
            return evidence_result

        workflow_evidence_result = self._validate_required_evidence_for_chain(
            capability_name,
            history,
            evidence_ids,
            workflow_policy,
        )
        if workflow_evidence_result is not None:
            return workflow_evidence_result

        if history and workflow_policy:
            workflow_transition_result = self._validate_transition_graph(
                capability_name,
                history,
                workflow_policy.get("transition_graph", {}),
                reason_code="WORKFLOW_TRANSITION_NOT_ALLOWED",
            )
            if workflow_transition_result is not None:
                return workflow_transition_result

        transition_result = self._validate_transition_graph(
            capability_name,
            history,
            self._capability_sequences.get("transition_graph", {}),
            reason_code="TRANSITION_NOT_ALLOWED",
        )
        if transition_result is not None:
            return transition_result

        if not history or not workflow_policy:
            workflow_transition_result = self._validate_transition_graph(
                capability_name,
                history,
                workflow_policy.get("transition_graph", {}),
                reason_code="WORKFLOW_TRANSITION_NOT_ALLOWED",
            )
            if workflow_transition_result is not None:
                return workflow_transition_result

        risk_result = self._validate_cumulative_risk(
            capability_name,
            history,
            workflow_policy,
            contract,
            approval_token,
        )
        if risk_result is not None:
            return risk_result

        return self._validate_intent_and_state(capability_name, workflow_policy, context)

    def _validate_common_constraints(
        self,
        name: str,
        args: dict[str, Any],
        constraints: dict[str, Any],
        *,
        approval_token: str | None = None,
    ) -> ContractResult | None:
        arg_rule_result = self._apply_dynamic_arg_rules(
            name,
            args,
            constraints,
            approval_token=approval_token,
        )
        if arg_rule_result is not None:
            return arg_rule_result

        field_length_result = self._validate_field_lengths(name, args, constraints)
        if field_length_result is not None:
            return field_length_result

        for key in ("path", "filepath", "file_path"):
            if key not in args:
                continue
            path_val = str(args[key])
            if constraints.get("deny_path_traversal", True) and _check_path_traversal(path_val):
                return ContractResult(
                    decision=ContractDecision.BLOCK,
                    tool_name=name,
                    reason_code="PATH_TRAVERSAL",
                    details=f"Path traversal detected in arg '{key}': {path_val}",
                    violations=["I2"],
                )
            allowlist = list(constraints.get("path_allowlist", []))
            denylist = list(constraints.get("path_denylist", []))
            ok, reason = _check_path_allowlist(path_val, allowlist, denylist)
            if not ok:
                return ContractResult(
                    decision=ContractDecision.BLOCK,
                    tool_name=name,
                    reason_code="PATH_POLICY_VIOLATION",
                    details=f"Path constraint failed ({reason}): {path_val}",
                    violations=["I2"],
                )

        url_fields = set(constraints.get("url_fields", [])) | {"url", "endpoint", "webhook", "uri"}
        for key in url_fields:
            if key not in args:
                continue
            url_val = str(args[key])
            allowed_schemes = constraints.get(
                "allowed_schemes",
                ["http", "https"] if key != "uri" else ["file", "https", "http"],
            )
            ok, reason = _check_domain(
                url_val,
                list(constraints.get("domain_allowlist", [])),
                list(constraints.get("domain_denylist", [])),
                list(allowed_schemes),
                cidr_denylist=list(constraints.get("cidr_denylist", [])),
                resolve_dns=bool(constraints.get("resolve_dns", False)),
            )
            if not ok:
                return ContractResult(
                    decision=ContractDecision.BLOCK,
                    tool_name=name,
                    reason_code="DOMAIN_POLICY_VIOLATION",
                    details=f"Domain constraint failed ({reason}): {url_val}",
                    violations=["I2"],
                )

        if "recipient" in args:
            recipient = str(args["recipient"])
            recipient_domain_allowlist = constraints.get("recipient_domain_allowlist", [])
            if recipient_domain_allowlist:
                domain = recipient.split("@")[-1] if "@" in recipient else ""
                allowed = False
                for allowed_domain in recipient_domain_allowlist:
                    if domain == allowed_domain or domain.endswith("." + str(allowed_domain)):
                        allowed = True
                        break
                if not allowed:
                    return ContractResult(
                        decision=ContractDecision.BLOCK,
                        tool_name=name,
                        reason_code="RECIPIENT_DOMAIN_NOT_ALLOWED",
                        details=f"Recipient domain '{domain}' not in allowlist",
                        violations=["I2"],
                    )

        if "sql" in args:
            sql_mode = constraints.get("sql_mode", "select_only")
            if sql_mode == "select_only":
                allowlisted_tables = list(constraints.get("allowlisted_tables", []))
                ok, reason = _check_sql(str(args["sql"]), allowlisted_tables)
                if not ok:
                    return ContractResult(
                        decision=ContractDecision.BLOCK,
                        tool_name=name,
                        reason_code="SQL_POLICY_VIOLATION",
                        details=f"SQL constraint failed ({reason})",
                        violations=["I2"],
                    )

        max_body = constraints.get("max_body_chars")
        if max_body and "body" in args and len(str(args["body"])) > max_body:
            return ContractResult(
                decision=ContractDecision.BLOCK,
                tool_name=name,
                reason_code="CONTENT_TOO_LARGE",
                details=f"Body exceeds max_body_chars={max_body}",
                violations=["I2"],
            )

        regex_rules = constraints.get("regex_rules", {})
        if isinstance(regex_rules, dict):
            for field_name, pattern in regex_rules.items():
                if field_name not in args:
                    continue
                if re.fullmatch(str(pattern), str(args[field_name])) is None:
                    return ContractResult(
                        decision=ContractDecision.BLOCK,
                        tool_name=name,
                        reason_code="REGEX_CONSTRAINT_FAILED",
                        details=f"Field '{field_name}' did not satisfy the required pattern.",
                        violations=["I2"],
                    )

        return None

    def _allow_result(
        self,
        name: str,
        args: dict[str, Any],
        *,
        reason_code: str = "ALLOWED",
        details: str = "",
    ) -> ContractResult:
        return ContractResult(
            decision=ContractDecision.ALLOW,
            tool_name=name,
            reason_code=reason_code,
            details=details,
            sanitized_args=copy.deepcopy(args),
        )

    def _dangerous_unknown_arg_names(self, args: dict[str, Any]) -> list[str]:
        return sorted(
            {
                str(key).strip().lower()
                for key in args
                if str(key).strip().lower() in _DANGEROUS_UNKNOWN_ARG_NAMES
            }
        )

    def _apply_baseline_guardrails(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        approval_token: str | None = None,
    ) -> ContractResult | None:
        baseline_result = self._validate_common_constraints(
            tool_name,
            args,
            {"max_body_chars": _UNKNOWN_CAPABILITY_BASELINE_MAX_BODY_CHARS},
            approval_token=approval_token,
        )
        if baseline_result is not None:
            return baseline_result

        dangerous_args = self._dangerous_unknown_arg_names(args)
        if not dangerous_args:
            return None

        if self._unknown_capability_mode not in ("sandbox_allow", "discover_only"):
            return None

        logger.warning(
            "Capability '%s' is not registered and includes dangerous args=%s; approval required.",
            tool_name,
            dangerous_args,
        )
        return self._issue_or_validate_approval(
            component_type=ComponentType.TOOL.value,
            component_name=tool_name,
            args=args,
            approval_token=approval_token,
            approval_required=True,
            details=(
                f"Capability '{tool_name}' is not registered and includes dangerous "
                f"arguments: {', '.join(dangerous_args)}."
            ),
        )

    def _handle_unknown_capability(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        approval_token: str | None = None,
    ) -> ContractResult:
        mode = self._unknown_capability_mode
        if mode == "strict_block":
            logger.warning(
                "Capability '%s' is not registered; blocking execution in strict mode.",
                tool_name,
            )
            return ContractResult(
                decision=ContractDecision.BLOCK,
                tool_name=tool_name,
                reason_code="UNKNOWN_CAPABILITY_BLOCKED",
                details=(
                    f"Capability '{tool_name}' is not registered and strict mode blocks execution."
                ),
                violations=["I1"],
            )

        if mode == "sandbox_allow":
            logger.warning(
                "Capability '%s' is not registered; allowing execution in sandbox_allow mode.",
                tool_name,
            )
            return self._allow_result(
                tool_name,
                args,
                reason_code="UNKNOWN_CAPABILITY_SANDBOX_ALLOWED",
                details=(
                    f"Capability '{tool_name}' is not registered but sandbox_allow mode permits it."
                ),
            )

        if mode == "discover_only":
            logger.info(
                "Capability '%s' is not registered; allowing execution in discover_only mode.",
                tool_name,
            )
            return self._allow_result(
                tool_name,
                args,
                reason_code="UNKNOWN_CAPABILITY_DISCOVERED",
                details=(
                    f"Capability '{tool_name}' is not registered but discover_only mode permits it."
                ),
            )

        logger.warning(
            "Capability '%s' is not registered; approval required before execution.",
            tool_name,
        )
        unregistered_approval = self._issue_or_validate_approval(
            component_type=ComponentType.TOOL.value,
            component_name=tool_name,
            args=args,
            approval_token=approval_token,
            approval_required=True,
            details=f"Capability '{tool_name}' is not registered and requires human approval.",
        )
        if unregistered_approval is not None:
            return unregistered_approval
        return self._allow_result(
            tool_name,
            args,
            reason_code="UNREGISTERED_TOOL_APPROVED",
            details=f"Capability '{tool_name}' was not registered but was explicitly approved.",
        )

    def validate_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        approval_token: str | None = None,
        evidence_ids: list[str] | None = None,
        trust_vector: Any | None = None,
        agent_id: str = "unknown",
        framework: str = "custom",
        invocation_context: dict[str, Any] | None = None,
    ) -> ContractResult:
        self._maybe_reload()
        component_type = ComponentType.TOOL.value

        resolved_contract = self._resolve_capability_contract(
            tool_name,
            args=args,
            invocation_context=invocation_context,
        )
        if resolved_contract is None:
            baseline_result = self._apply_baseline_guardrails(
                tool_name,
                args,
                approval_token=approval_token,
            )
            if baseline_result is not None:
                return self._finalize_component_result(
                    component_type=component_type,
                    component_name=tool_name,
                    args=args,
                    result=baseline_result,
                    agent_id=agent_id,
                    framework=framework,
                    invocation_context=invocation_context,
                    decision_metadata={"policy_match": "unknown_baseline"},
                )
            return self._finalize_component_result(
                component_type=component_type,
                component_name=tool_name,
                args=args,
                result=self._handle_unknown_capability(
                    tool_name,
                    args,
                    approval_token=approval_token,
                ),
                agent_id=agent_id,
                framework=framework,
                invocation_context=invocation_context,
                decision_metadata={"policy_match": "unknown_capability"},
            )

        contract = resolved_contract.contract
        decision_metadata = {
            "policy_match": resolved_contract.match_type,
            "contract_name": resolved_contract.contract_name,
        }
        if resolved_contract.schema_hash is not None:
            decision_metadata["contract_schema_hash"] = resolved_contract.schema_hash
        if resolved_contract.inferred_family is not None:
            decision_metadata["inferred_family"] = resolved_contract.inferred_family
        if resolved_contract.match_score is not None:
            decision_metadata["match_score"] = resolved_contract.match_score
        schema_result = self._validate_schema(
            "tool",
            resolved_contract.contract_name,
            args,
            result_name=tool_name,
        )
        constraints = contract.get("constraints", {})
        return self._run_component_checks(
            component_type=component_type,
            component_name=tool_name,
            args=args,
            agent_id=agent_id,
            framework=framework,
            invocation_context=invocation_context,
            checks=[
                lambda: schema_result,
                lambda: self._validate_identity_constraints(
                    tool_name,
                    agent_id=agent_id,
                    framework=framework,
                    constraints=constraints,
                ),
                lambda: self._validate_capability_sequence(
                    tool_name,
                    contract,
                    evidence_ids=evidence_ids,
                    invocation_context=invocation_context,
                    approval_token=approval_token,
                ),
                lambda: self._validate_preconditions(
                    tool_name,
                    constraints=constraints,
                    evidence_ids=evidence_ids,
                    trust_vector=trust_vector,
                ),
                lambda: self._validate_common_constraints(
                    tool_name,
                    args,
                    constraints,
                    approval_token=approval_token,
                ),
                lambda: self._issue_or_validate_approval(
                    component_type="tool",
                    component_name=tool_name,
                    args=args,
                    approval_token=approval_token,
                    approval_required=contract.get("approval_required", False),
                ),
            ],
            success_result=self._allow_result(tool_name, args),
            decision_metadata=decision_metadata,
        )

    def validate_capability_call(
        self,
        capability_name: str,
        args: dict[str, Any],
        *,
        approval_token: str | None = None,
        evidence_ids: list[str] | None = None,
        trust_vector: Any | None = None,
        agent_id: str = "unknown",
        framework: str = "custom",
        invocation_context: dict[str, Any] | None = None,
    ) -> ContractResult:
        return self.validate_call(
            capability_name,
            args,
            approval_token=approval_token,
            evidence_ids=evidence_ids,
            trust_vector=trust_vector,
            agent_id=agent_id,
            framework=framework,
            invocation_context=invocation_context,
        )

    def validate_resource_read(
        self,
        resource_uri: str,
        *,
        approval_token: str | None = None,
        agent_id: str = "unknown",
        framework: str = "custom",
    ) -> ContractResult:
        self._maybe_reload()
        component_type = ComponentType.RESOURCE.value

        resolved_contract = self._resolve_resource_contract(resource_uri)
        if resolved_contract is None:
            return self._finalize_component_result(
                component_type=component_type,
                component_name=resource_uri,
                args={"uri": resource_uri},
                result=self._block_result(
                    resource_uri,
                    "RESOURCE_NOT_REGISTERED",
                    f"Resource '{resource_uri}' is not in the registry.",
                ),
                agent_id=agent_id,
                framework=framework,
                decision_metadata={"policy_match": "resource_unregistered"},
            )

        matched_name = resolved_contract.contract_name
        matched_contract = resolved_contract.contract
        payload = {"uri": resource_uri}
        schema_result = self._validate_schema("resource", matched_name, payload)
        parsed = urlparse(resource_uri)
        constraint_payload = {
            "uri": resource_uri,
            "url": resource_uri,
            "path": _normalize_uri_path(parsed.path or resource_uri),
        }
        constraints = matched_contract.get("constraints", {})
        return self._run_component_checks(
            component_type=component_type,
            component_name=matched_name,
            args=payload,
            agent_id=agent_id,
            framework=framework,
            checks=[
                lambda: schema_result,
                lambda: self._validate_identity_constraints(
                    matched_name,
                    agent_id=agent_id,
                    framework=framework,
                    constraints=constraints,
                ),
                lambda: self._validate_common_constraints(
                    matched_name,
                    constraint_payload,
                    constraints,
                    approval_token=approval_token,
                ),
                lambda: self._issue_or_validate_approval(
                    component_type="resource",
                    component_name=matched_name,
                    args=payload,
                    approval_token=approval_token,
                    approval_required=matched_contract.get("approval_required", False),
                ),
            ],
            success_result=self._allow_result(matched_name, payload),
            decision_metadata={
                "policy_match": resolved_contract.match_type,
                "contract_name": matched_name,
            },
        )

    def validate_prompt_get(
        self,
        prompt_name: str,
        args: dict[str, Any],
        *,
        approval_token: str | None = None,
        agent_id: str = "unknown",
        framework: str = "custom",
    ) -> ContractResult:
        self._maybe_reload()
        component_type = ComponentType.PROMPT.value

        if prompt_name not in self._prompt_permissions:
            return self._finalize_component_result(
                component_type=component_type,
                component_name=prompt_name,
                args=args,
                result=self._block_result(
                    prompt_name,
                    "PROMPT_NOT_REGISTERED",
                    f"Prompt '{prompt_name}' is not in the prompt registry.",
                ),
                agent_id=agent_id,
                framework=framework,
                decision_metadata={"policy_match": "prompt_unregistered"},
            )

        contract = self._merged_contract("prompt", prompt_name, self._prompt_permissions[prompt_name])
        schema_result = self._validate_schema("prompt", prompt_name, args)
        constraints = contract.get("constraints", {})
        return self._run_component_checks(
            component_type=component_type,
            component_name=prompt_name,
            args=args,
            agent_id=agent_id,
            framework=framework,
            checks=[
                lambda: schema_result,
                lambda: self._validate_identity_constraints(
                    prompt_name,
                    agent_id=agent_id,
                    framework=framework,
                    constraints=constraints,
                ),
                lambda: self._validate_common_constraints(
                    prompt_name,
                    args,
                    constraints,
                    approval_token=approval_token,
                ),
                lambda: self._issue_or_validate_approval(
                    component_type="prompt",
                    component_name=prompt_name,
                    args=args,
                    approval_token=approval_token,
                    approval_required=contract.get("approval_required", False),
                ),
            ],
            success_result=self._allow_result(prompt_name, args),
            decision_metadata={
                "policy_match": "exact_name",
                "contract_name": prompt_name,
            },
        )

    def sanitize_output(self, tool_name: str, output: Any) -> Any:
        sensitive_terms = {
            "password",
            "secret",
            "token",
            "api_key",
            "private_key",
            "credential",
            "authorization",
        }

        def _scrub(value: Any) -> Any:
            if isinstance(value, dict):
                redacted: dict[str, Any] = {}
                for key, item in value.items():
                    lowered = key.lower()
                    if lowered in sensitive_terms or any(term in lowered for term in sensitive_terms):
                        redacted[key] = "[REDACTED-POSTCONDITION]"
                    else:
                        redacted[key] = _scrub(item)
                return redacted
            if isinstance(value, list):
                return [_scrub(item) for item in value]
            return value

        sanitized = _scrub(output)
        logger.debug("Sanitized output for %s", tool_name)
        self._security_observer.emit(
            {
                "event_id": str(uuid.uuid4()),
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "component_type": ComponentType.TOOL.value,
                "component_name": tool_name,
                "decision": ContractDecision.ALLOW.value,
                "reason_code": "OUTPUT_SANITIZED",
                "details": "Output postconditions applied.",
                "approval_token": None,
                "violations": [],
                "sanitized_args": None,
                "approval_token_issued": False,
                "operation_fingerprint": _approval_fingerprint(ComponentType.TOOL.value, tool_name, {}),
                "agent_id": "postcondition",
                "framework": "layer_b",
                "args": {},
                "invocation_context": {},
                "trace": {
                    "policy_match": "postcondition",
                    "contract_name": tool_name,
                },
            }
        )
        return sanitized

    def list_tools(self) -> list[str]:
        return self.list_capabilities()

    def list_capabilities(self) -> list[str]:
        self._maybe_reload()
        return list(self._capability_permissions.keys())

    def list_resources(self) -> list[str]:
        self._maybe_reload()
        return list(self._resource_permissions.keys())

    def list_prompts(self) -> list[str]:
        self._maybe_reload()
        return list(self._prompt_permissions.keys())

    def get_risk_level(self, tool_name: str) -> str:
        return self.get_capability_risk_level(tool_name)

    def get_capability_risk_level(self, capability_name: str) -> str:
        self._maybe_reload()
        return self._capability_permissions.get(capability_name, {}).get(
            "risk", RiskLevel.UNKNOWN.value
        )

    def get_tool_contract(self, tool_name: str) -> dict[str, Any]:
        return self.get_capability_contract(tool_name)

    def get_capability_contract(self, capability_name: str) -> dict[str, Any]:
        self._maybe_reload()
        base = self._capability_permissions.get(capability_name, {})
        return (
            copy.deepcopy(self._merged_contract("tool", capability_name, base))
            if base
            else {}
        )

    def get_resource_contract(self, resource_name: str) -> dict[str, Any]:
        self._maybe_reload()
        base = self._resource_permissions.get(resource_name, {})
        return copy.deepcopy(self._merged_contract("resource", resource_name, base)) if base else {}

    def get_prompt_contract(self, prompt_name: str) -> dict[str, Any]:
        self._maybe_reload()
        base = self._prompt_permissions.get(prompt_name, {})
        return copy.deepcopy(self._merged_contract("prompt", prompt_name, base)) if base else {}

    def get_schema(self, kind: str, name: str) -> dict[str, Any] | None:
        self._maybe_reload()
        if kind == "capability":
            kind = "tool"
        schema = self._schemas.get((kind, name))
        return copy.deepcopy(schema) if schema is not None else None

    @property
    def event_log_path(self) -> Path | None:
        return Path(self._event_log_path) if self._event_log_path is not None else None

    def get_capability_schema(self, capability_name: str) -> dict[str, Any] | None:
        return self.get_schema("capability", capability_name)

    def policy_snapshot(self) -> dict[str, Any]:
        self._maybe_reload()
        return copy.deepcopy(self._raw_policy)

    def pending_approvals_snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(self._pending_approvals)

    def reload(self) -> None:
        self._load()


__all__ = [
    "CompositeSecurityEventObserver",
    "ComponentType",
    "ContractDecision",
    "ContractResult",
    "ContractValidator",
    "JsonlSecurityEventObserver",
    "NoopSecurityEventObserver",
    "PermissionScope",
    "PolicyValidationError",
    "RiskLevel",
    "SecurityEventObserver",
    "_check_domain",
    "_check_path_traversal",
    "_check_sql",
]



