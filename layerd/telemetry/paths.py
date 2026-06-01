from __future__ import annotations

import os
from pathlib import Path


TELEMETRY_FILENAME = "ascp_events.jsonl"
DASHBOARD_BEACON_FILENAME = "dashboard.json"


def default_telemetry_path() -> Path:
    """Return ASCP's per-user telemetry file path.

    Applications can override this with ASCP_TELEMETRY_PATH. The default lives
    outside the client project so SDK users do not need to create a logs folder.
    """

    explicit = os.environ.get("ASCP_TELEMETRY_PATH")
    if explicit:
        return Path(explicit).expanduser().resolve()

    return _default_state_dir() / "telemetry" / TELEMETRY_FILENAME


def dashboard_beacon_path() -> Path:
    """Return the local discovery file used by the dashboard live stream."""

    return _default_state_dir() / "dashboard" / DASHBOARD_BEACON_FILENAME


def _default_state_dir() -> Path:
    home = Path.home()

    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "ASCP"
        return home / "AppData" / "Local" / "ASCP"

    if os.name == "posix" and os.uname().sysname == "Darwin":
        return home / "Library" / "Application Support" / "ASCP"

    xdg_state_home = os.environ.get("XDG_STATE_HOME")
    if xdg_state_home:
        return Path(xdg_state_home) / "ascp"
    return home / ".local" / "state" / "ascp"
