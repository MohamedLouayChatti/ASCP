from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from urllib import error, request

from layerd.telemetry.paths import dashboard_beacon_path


logger = logging.getLogger(__name__)

_BEACON_MAX_AGE_SECONDS = 60 * 60 * 8
_PUBLISH_TIMEOUT_SECONDS = 0.08
_last_failure_at = 0.0
_failure_backoff_seconds = 2.0


def publish_to_local_dashboard(event_json: str) -> None:
    """Best-effort push to a running local dashboard.

    The durable JSONL sink remains the source of truth. This live path is only
    a UI acceleration layer and must never break or noticeably slow the app.
    """

    global _last_failure_at

    now = time.monotonic()
    if now - _last_failure_at < _failure_backoff_seconds:
        return

    endpoint = _read_ingest_endpoint(dashboard_beacon_path())
    if not endpoint:
        return

    body = event_json.encode("utf-8")
    req = request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    try:
        with request.urlopen(req, timeout=_PUBLISH_TIMEOUT_SECONDS) as response:
            if response.status >= 400:
                _last_failure_at = now
    except (OSError, error.URLError, TimeoutError) as exc:
        _last_failure_at = now
        logger.debug("ASCP dashboard live publish skipped: %s", exc)


def _read_ingest_endpoint(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        if time.time() - path.stat().st_mtime > _BEACON_MAX_AGE_SECONDS:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    endpoint = data.get("ingest_url")
    if not isinstance(endpoint, str):
        return None
    if not endpoint.startswith("http://127.0.0.1:") and not endpoint.startswith(
        "http://localhost:"
    ):
        return None
    return endpoint
