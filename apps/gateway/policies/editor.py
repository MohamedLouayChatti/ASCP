"""
Developer-facing policy mutation helpers.
"""

from __future__ import annotations

import copy
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


class PolicyEditor:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    def _load(self) -> dict[str, Any]:
        if not self._path.exists():
            return {}
        return yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}

    def _save(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._load())

    def upsert_permission(self, kind: str, name: str, contract: dict[str, Any]) -> dict[str, Any]:
        section = "capabilities" if kind == "tool" else f"{kind}s"
        with self._lock:
            data = self._load()
            data.setdefault(section, {})
            data[section][name] = contract
            self._save(data)
            return copy.deepcopy(data[section][name])

    def remove_permission(self, kind: str, name: str) -> bool:
        section = "capabilities" if kind == "tool" else f"{kind}s"
        with self._lock:
            data = self._load()
            if name not in data.get(section, {}):
                return False
            del data[section][name]
            self._save(data)
            return True

    def build_default_contract(
        self,
        kind: str,
        name: str,
        observed: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        observed = observed or {}
        meta = observed.get("last_metadata", {})
        if kind == "tool":
            return {
                "risk": "medium",
                "scopes": ["custom"],
                "approval_required": False,
                "description": (observed.get("descriptions") or [f"Developer-added tool '{name}'."])[0],
                "constraints": {},
            }

        if kind == "resource":
            uri = str(meta.get("uri") or "")
            parsed = urlparse(uri) if uri else None
            match: dict[str, Any]
            if parsed and parsed.scheme:
                match = {"schemes": [parsed.scheme]}
                if parsed.scheme == "file" and uri:
                    prefix = uri.rsplit("/", 1)[0] + "/"
                    match = {"uri_prefixes": [prefix]}
            else:
                match = {"uri_prefixes": []}
            return {
                "risk": "medium",
                "approval_required": False,
                "description": (observed.get("descriptions") or [f"Developer-added resource '{name}'."])[0],
                "match": match,
                "constraints": {},
            }

        return {
            "risk": "low",
            "approval_required": False,
            "description": (observed.get("descriptions") or [f"Developer-added prompt '{name}'."])[0],
            "constraints": {
                "max_body_chars": 4000,
            },
        }
