from __future__ import annotations

import argparse
import json
import mimetypes
import os
import threading
import time
import webbrowser
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from socket import error as SocketError
from typing import Any
from urllib.parse import parse_qs, urlparse

from layerd.telemetry.paths import dashboard_beacon_path, default_telemetry_path


DEFAULT_DASHBOARD_HOST = "127.0.0.1"
DEFAULT_DASHBOARD_PORT = 8765
DEFAULT_EVENT_LIMIT = 500


@dataclass(frozen=True)
class DashboardOptions:
    host: str = DEFAULT_DASHBOARD_HOST
    port: int = DEFAULT_DASHBOARD_PORT
    log_paths: tuple[Path, ...] = ()
    open_browser: bool = True
    event_limit: int = DEFAULT_EVENT_LIMIT


def run_dashboard(options: DashboardOptions) -> int:
    server = _bind_server(options)
    url = f"http://{server.server_address[0]}:{server.server_address[1]}"
    _write_dashboard_beacon(url)

    print("ASCP local dashboard")
    print(f"Serving: {url}")
    print("Live stream: enabled for local ASCP apps")
    watched = _resolve_log_paths(options.log_paths)
    if watched:
        print("Watching telemetry:")
        for path in watched:
            print(f"- {path}")
    else:
        print("Watching telemetry: no JSONL files found yet")
        print(f"Default ASCP telemetry path: {default_telemetry_path()}")
        print("Start an ASCP-enabled client, then refresh the dashboard.")
    print("Press Ctrl+C to stop.")

    if options.open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print("Stopping ASCP local dashboard.")
    finally:
        _remove_dashboard_beacon(url)
        server.server_close()
    return 0


def build_dashboard_options(args: argparse.Namespace) -> DashboardOptions:
    log_paths = tuple(Path(value).expanduser() for value in args.log_path or ())
    return DashboardOptions(
        host=args.host,
        port=args.port,
        log_paths=log_paths,
        open_browser=not args.no_open,
        event_limit=max(1, args.limit),
    )


class _DashboardServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], options: DashboardOptions) -> None:
        self.options = options
        self.live_events: list[dict[str, Any]] = []
        self.live_lock = threading.Lock()
        super().__init__(server_address, _DashboardHandler)

    def add_live_event(self, event: dict[str, Any]) -> None:
        normalized = _normalize_event(dict(event))
        normalized["_source"] = "live"
        normalized["_file"] = "live stream"
        normalized["_line"] = 0
        with self.live_lock:
            self.live_events.append(normalized)
            if len(self.live_events) > self.options.event_limit * 2:
                del self.live_events[: len(self.live_events) - self.options.event_limit * 2]

    def snapshot_live_events(self) -> list[dict[str, Any]]:
        with self.live_lock:
            return [dict(event) for event in self.live_events]


class _DashboardHandler(BaseHTTPRequestHandler):
    server: _DashboardServer

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self._send_html(_load_dashboard_html())
            return
        if parsed.path == "/api/events":
            query = parse_qs(parsed.query)
            limit = _query_int(query, "limit", self.server.options.event_limit)
            payload = load_event_snapshot(
                self.server.options.log_paths,
                limit=limit,
                live_events=self.server.snapshot_live_events(),
            )
            self._send_json(payload)
            return
        if parsed.path == "/api/health":
            self._send_json({"status": "ok", "time": _now_iso()})
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        if parsed.path != "/api/ingest":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 256_000:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid telemetry payload")
            return

        raw = self.rfile.read(length)
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid JSON")
            return

        if not isinstance(event, dict):
            self.send_error(HTTPStatus.BAD_REQUEST, "Telemetry event must be an object")
            return

        self.server.add_live_event(event)
        self._send_json({"status": "ok"})

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_html(self, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_json(self, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def load_event_snapshot(
    configured_paths: tuple[Path, ...] = (),
    *,
    limit: int = DEFAULT_EVENT_LIMIT,
    live_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    paths = _resolve_log_paths(configured_paths)
    events: list[dict[str, Any]] = []
    malformed_lines: list[dict[str, Any]] = []

    for path in paths:
        file_events, file_errors = _read_jsonl(path)
        events.extend(file_events)
        malformed_lines.extend(file_errors)

    if live_events:
        events = _merge_live_events(events, live_events)

    events.sort(key=_event_sort_key)
    if limit > 0:
        events = events[-limit:]

    return {
        "generated_at": _now_iso(),
        "files": [_file_info(path) for path in paths],
        "events": events,
        "malformed_lines": malformed_lines[-20:],
        "summary": _summarize(events),
        "live": {
            "enabled": True,
            "event_count": len(live_events or []),
            "beacon": str(dashboard_beacon_path()),
        },
    }


def _bind_server(options: DashboardOptions) -> _DashboardServer:
    last_error: SocketError | None = None
    for offset in range(25):
        port = options.port + offset
        try:
            return _DashboardServer((options.host, port), options)
        except SocketError as exc:
            last_error = exc
            continue
    raise RuntimeError(
        f"Could not bind ASCP dashboard on {options.host}:{options.port}-"
        f"{options.port + 24}: {last_error}"
    )


def _resolve_log_paths(configured_paths: tuple[Path, ...]) -> list[Path]:
    if configured_paths:
        candidates = list(configured_paths)
    else:
        cwd = Path.cwd()
        candidates = [
            default_telemetry_path(),
            cwd / "ascp_logs.jsonl",
            *sorted((cwd / "logs").glob("*.jsonl")),
        ]

    paths: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        path = candidate.resolve()
        if path in seen or not path.is_file():
            continue
        if path.suffix.lower() != ".jsonl":
            continue
        seen.add(path)
        paths.append(path)
    return paths


def _read_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    event = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    malformed.append(
                        {
                            "file": str(path),
                            "line": line_number,
                            "error": str(exc),
                            "excerpt": stripped[:160],
                        }
                    )
                    continue
                if isinstance(event, dict):
                    event["_file"] = str(path)
                    event["_line"] = line_number
                    events.append(_normalize_event(event))
    except OSError as exc:
        malformed.append({"file": str(path), "line": 0, "error": str(exc), "excerpt": ""})
    return events, malformed


def _merge_live_events(
    file_events: list[dict[str, Any]],
    live_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    seen = {str(event.get("event_id") or "") for event in file_events if event.get("event_id")}
    merged = list(file_events)
    for event in live_events:
        event_id = str(event.get("event_id") or "")
        if event_id and event_id in seen:
            continue
        merged.append(event)
        if event_id:
            seen.add(event_id)
    return merged


def _normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    event.setdefault("event_type", "unknown")
    event.setdefault("severity", "info")
    event.setdefault("reason_code", "")
    event.setdefault("risk_score", 0.0)
    event.setdefault("details", {})
    event["_timestamp_ms"] = _parse_timestamp_ms(event.get("timestamp"))
    event["_risk_band"] = _risk_band(event.get("risk_score"))
    event["_layer"] = _layer_for_event(event.get("event_type"))
    return event


def _summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    correlations: set[str] = set()
    sessions: set[str] = set()
    max_risk = 0.0

    for event in events:
        event_type = str(event.get("event_type") or "unknown")
        severity = str(event.get("severity") or "info")
        by_type[event_type] = by_type.get(event_type, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
        if event.get("correlation_id"):
            correlations.add(str(event["correlation_id"]))
        if event.get("session_id"):
            sessions.add(str(event["session_id"]))
        try:
            max_risk = max(max_risk, float(event.get("risk_score") or 0.0))
        except (TypeError, ValueError):
            pass

    return {
        "total_events": len(events),
        "correlations": len(correlations),
        "sessions": len(sessions),
        "max_risk": round(max_risk, 4),
        "by_type": by_type,
        "by_severity": by_severity,
    }


def _file_info(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path),
        "name": path.name,
        "size": stat.st_size,
        "modified_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
    }


def _load_dashboard_html() -> str:
    return resources.files("ascp_integration").joinpath("dashboard.html").read_text(
        encoding="utf-8"
    )


def _write_dashboard_beacon(base_url: str) -> None:
    path = dashboard_beacon_path()
    payload = {
        "url": base_url,
        "ingest_url": f"{base_url}/api/ingest",
        "pid": os.getpid(),
        "started_at": _now_iso(),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass


def _remove_dashboard_beacon(base_url: str) -> None:
    path = dashboard_beacon_path()
    try:
        if not path.is_file():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("url") == base_url:
            path.unlink()
    except (OSError, json.JSONDecodeError):
        pass


def _event_sort_key(event: dict[str, Any]) -> tuple[int, str]:
    return int(event.get("_timestamp_ms") or 0), str(event.get("event_id") or "")


def _parse_timestamp_ms(value: Any) -> int:
    if not isinstance(value, str) or not value:
        return 0
    try:
        normalized = value.replace("Z", "+00:00")
        return int(datetime.fromisoformat(normalized).timestamp() * 1000)
    except ValueError:
        return 0


def _risk_band(value: Any) -> str:
    try:
        score = float(value or 0.0)
    except (TypeError, ValueError):
        return "low"
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.3:
        return "moderate"
    return "low"


def _layer_for_event(event_type: Any) -> str:
    name = str(event_type or "")
    if name == "retrieval_event":
        return "A/C"
    if name in {"tool_call_attempt", "tool_call_result", "approval_required"}:
        return "B"
    if name in {"dlp_hit", "policy_block"}:
        return "C/D"
    if name == "eval_vector":
        return "D"
    return "SDK"


def _query_int(query: dict[str, list[str]], key: str, default: int) -> int:
    values = query.get(key)
    if not values:
        return default
    try:
        return max(1, int(values[0]))
    except ValueError:
        return default


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


if mimetypes.guess_type("dashboard.html")[0] is None:
    mimetypes.add_type("text/html", ".html")
