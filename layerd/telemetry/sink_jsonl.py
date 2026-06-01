

import asyncio
import logging
from pathlib import Path

from layerd.telemetry.events import TelemetryEvent
from layerd.telemetry.live import publish_to_local_dashboard


logger = logging.getLogger(__name__)

_lock = asyncio.Lock()


async def emit_jsonl(event: TelemetryEvent, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    event_json = event.model_dump_json()
    line = event_json + "\n"
    async with _lock:
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            logger.error("Telemetry JSONL write error: %s", exc)
    await asyncio.to_thread(publish_to_local_dashboard, event_json)
