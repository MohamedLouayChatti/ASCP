

import asyncio
import logging
from pathlib import Path

from layerd.telemetry.events import TelemetryEvent


logger = logging.getLogger(__name__)

_lock = asyncio.Lock()


async def emit_jsonl(event: TelemetryEvent, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = event.model_dump_json() + "\n"
    async with _lock:
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            logger.error("Telemetry JSONL write error: %s", exc)
