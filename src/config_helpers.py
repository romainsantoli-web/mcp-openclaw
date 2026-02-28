"""
config_helpers.py — Shared helpers used across multiple MCP tool modules.

Centralises _load_config, _get_nested, and _mask_secret so they are
defined once (DRY) and tested in a single place.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Default OpenClaw config location
DEFAULT_CONFIG_PATH = Path.home() / ".openclaw" / "config.json"


def load_config(
    config_path: str | None,
    default_path: Path | None = None,
) -> tuple[dict[str, Any], str]:
    """Return (config_dict, resolved_path_str). Returns empty dict if file missing."""
    base = default_path or DEFAULT_CONFIG_PATH
    p = Path(config_path) if config_path else base
    resolved = str(p.resolve())
    if not p.exists():
        return {}, resolved
    with p.open("r", encoding="utf-8") as fh:
        return json.load(fh), resolved


def get_nested(d: dict, *keys: str, default: Any = None) -> Any:
    """Safe nested dict accessor: ``get_nested(d, 'a', 'b')`` → ``d['a']['b']``."""
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur


def mask_secret(val: str | None, visible: int = 4) -> str:
    """Mask a secret string — show only the last *visible* chars. Never log full secrets."""
    if not val or len(val) <= visible:
        return "****"
    return f"****{val[-visible:]}"
