"""
Policy-as-code loader.
Loads and validates YAML policy files.  All components reference this singleton.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class PolicyLoader:
    """Load and provide access to global ASCP policies."""

    def __init__(self, policy_path: str | Path) -> None:
        self._path = Path(policy_path)
        self._policy: dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        if self._path.exists():
            self._policy = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
            logger.info(
                "Policy loaded from %s (version=%s)", self._path, self._policy.get("version")
            )
        else:
            logger.warning("Policy file not found: %s — using defaults", self._path)
            self._policy = {}

    def get(self, *keys: str, default: Any = None) -> Any:
        """Nested key access: loader.get('grounding', 'min_grounding_score')"""
        node: Any = self._policy
        for key in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(key, default)
        return node

    @property
    def enforcement_mode(self) -> str:
        return self._policy.get("enforcement_mode", "strict")

    @property
    def grounding(self) -> dict[str, Any]:
        return self._policy.get("grounding", {})

    @property
    def dlp(self) -> dict[str, Any]:
        return self._policy.get("dlp", {})

    @property
    def sanitization(self) -> dict[str, Any]:
        return self._policy.get("sanitization", {})

    @property
    def safe_failure(self) -> dict[str, Any]:
        return self._policy.get("safe_failure", {})
