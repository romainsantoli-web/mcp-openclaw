"""
config_helpers.py — Shared helpers used across multiple MCP tool modules.

Centralises load_config, get_nested, mask_secret, check_ssrf, and
no_path_traversal so they are defined once (DRY) and tested in a single place.
"""

from __future__ import annotations

import json
import re
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Default config location — centralized in platform.py
from src.platform_compat import FIRM_CONFIG
DEFAULT_CONFIG_PATH = FIRM_CONFIG

# ── I-H3: Centralized SSRF guard ────────────────────────────────────────────
_BLOCKED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "[::1]", "[::ffff:127.0.0.1]",
})

_PRIVATE_RANGES_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.)"
)


def check_ssrf(url: str) -> str | None:
    """Return error message if URL points to a private/loopback address, else None."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip("[]")
    except Exception:
        return f"Invalid URL: {url!r}"

    if not host:
        return "URL has no host"

    if host in _BLOCKED_HOSTS:
        return f"URL must not point to {host} (SSRF protection)"

    if _PRIVATE_RANGES_RE.match(host):
        return f"URL must not point to private range {host} (SSRF protection)"

    # Check raw IP
    try:
        addr = ip_address(host)
        if addr.is_loopback or addr.is_private or addr.is_reserved:
            return f"URL must not point to {host} (SSRF protection — {addr} is private/loopback)"
    except ValueError:
        pass  # Not an IP — hostname is fine

    return None


# ── I-H4: Centralized path traversal guard ──────────────────────────────────

_TRAVERSAL_PATTERNS = re.compile(r"\.\./|/\.\./|%2e%2e|%252e%252e", re.IGNORECASE)


def no_path_traversal(path: str, label: str = "path") -> str | None:
    """Return error message if path contains traversal patterns, else None."""
    if ".." in path or _TRAVERSAL_PATTERNS.search(path):
        return f"{label} must not contain path traversal (..)"
    return None


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
