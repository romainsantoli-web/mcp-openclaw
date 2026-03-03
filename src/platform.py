"""
platform.py — Platform abstraction layer for generic MCP server compatibility.

Makes the MCP server work with ANY AI infrastructure:
Claude Code, Codex, VS Code, Antigravity, Cursor, Windsurf, etc.

All platform-specific constants are centralized here and configurable via env vars.
Modules import from this file instead of hardcoding paths/names.

Environment variables:
    FIRM_DIR            Base directory (default: ~/.firm/)
    FIRM_CONFIG         Config file path (default: ~/.firm/config.json)
    FIRM_TOOL_PREFIX    Tool name prefix (default: "firm")
    FIRM_URI_SCHEME     URI scheme for MCP resources (default: "firm")
    FIRM_PLATFORM       Target platform hint (claude-code|codex|vscode|antigravity|cursor|generic)
"""

from __future__ import annotations

import os
from pathlib import Path

# ── Platform identity ────────────────────────────────────────────────────────

SERVER_NAME = "firm-mcp-server"
SERVER_DISPLAY_NAME = "Firm MCP Server"
SERVER_DESCRIPTION = (
    "138-tool MCP server for AI agent firms: security, A2A, Hebbian memory, fleet mgmt"
)

# ── Configurable base directory ──────────────────────────────────────────────

FIRM_DIR: Path = Path(os.getenv("FIRM_DIR", str(Path.home() / ".firm")))
FIRM_CONFIG: Path = Path(os.getenv("FIRM_CONFIG", str(FIRM_DIR / "config.json")))

# Subdirectories
SESSIONS_DIR: Path = FIRM_DIR / "sessions"
LOCKS_DIR: Path = FIRM_DIR / "locks"
CREDS_DIR: Path = Path(os.getenv("FIRM_CREDS", str(FIRM_DIR / "credentials")))
WORKSPACE_DIR: Path = Path(os.getenv("FIRM_WORKSPACE", str(FIRM_DIR / "workspace")))
PLUGINS_DIR: Path = FIRM_DIR / "plugins"
PLUGIN_MANIFEST: Path = PLUGINS_DIR / "plugin-manifest.json"
TRACES_DB: Path = FIRM_DIR / "traces.db"
EXPORTS_DIR: Path = FIRM_DIR / "exports"
FLEET_STORE: Path = FIRM_DIR / "fleet.json"
CRON_STORE: Path = FIRM_DIR / "cron_schedules.json"
SESSIONS_STORE: Path = FIRM_DIR / "sessions.json"
MARKET_CACHE: Path = FIRM_DIR / "market-research"

# ── Tool naming ──────────────────────────────────────────────────────────────

TOOL_PREFIX: str = os.getenv("FIRM_TOOL_PREFIX", "firm")


def tool_name(base: str) -> str:
    """Build a tool name: ``firm_security_scan``, ``firm_hebbian_harvest``, etc."""
    return f"{TOOL_PREFIX}_{base}"


# ── URI scheme ───────────────────────────────────────────────────────────────

URI_SCHEME: str = os.getenv("FIRM_URI_SCHEME", "firm")


def resource_uri(path: str) -> str:
    """Build a resource URI: ``firm://config/main``, ``firm://health``, etc."""
    return f"{URI_SCHEME}://{path}"


# ── Environment variable names ───────────────────────────────────────────────
# Modules use these instead of hardcoded OPENCLAW_* env vars.

ENV_PREFIX: str = "FIRM"

# Gateway / VS Bridge
GATEWAY_WS_URL: str = os.getenv(
    "FIRM_GATEWAY_URL",
    os.getenv("OPENCLAW_GATEWAY_URL", "ws://127.0.0.1:18789"),  # backward compat
)
GATEWAY_HTTP_URL: str = os.getenv(
    "FIRM_GATEWAY_HTTP",
    os.getenv("OPENCLAW_GATEWAY_HTTP", "http://127.0.0.1:18789"),
)
GATEWAY_TOKEN: str | None = os.getenv(
    "FIRM_GATEWAY_TOKEN",
    os.getenv("OPENCLAW_GATEWAY_TOKEN"),
)
WS_TIMEOUT: int = int(os.getenv(
    "FIRM_TIMEOUT_SECONDS",
    os.getenv("OPENCLAW_TIMEOUT_SECONDS", "30"),
))

# Env allowlist for session injection (ACP bridge)
ENV_ALLOWLIST_PATTERNS: list[str] = [
    r"ANTHROPIC_API_KEY",
    r"OPENAI_API_KEY",
    r"FIRM_MODEL",
    r"FIRM_PROVIDER",
    r"FIRM_MAX_TOKENS",
    # Backward compat with OPENCLAW_* vars
    r"OPENCLAW_MODEL",
    r"OPENCLAW_PROVIDER",
    r"OPENCLAW_MAX_TOKENS",
]

# ── Platform detection ───────────────────────────────────────────────────────

PLATFORM: str = os.getenv("FIRM_PLATFORM", "generic")

# Platform-specific defaults
_PLATFORM_DEFAULTS: dict[str, dict[str, str]] = {
    "claude-code": {
        "config_hint": "Add to ~/.claude/mcp_servers.json",
        "doc_url": "https://docs.anthropic.com/en/docs/claude-code/mcp",
    },
    "codex": {
        "config_hint": "Add to codex_config.yaml under mcp_servers",
        "doc_url": "https://github.com/openai/codex",
    },
    "vscode": {
        "config_hint": "Add to .vscode/mcp.json or VS Code settings (mcp.servers)",
        "doc_url": "https://code.visualstudio.com/docs/copilot/chat/mcp-servers",
    },
    "cursor": {
        "config_hint": "Add to ~/.cursor/mcp.json",
        "doc_url": "https://docs.cursor.com/context/model-context-protocol",
    },
    "windsurf": {
        "config_hint": "Add to ~/.windsurf/mcp_config.json",
        "doc_url": "https://docs.windsurf.com/mcp",
    },
    "antigravity": {
        "config_hint": "Add to antigravity.config.json under mcp_servers",
        "doc_url": "https://antigravity.dev/docs/mcp",
    },
    "generic": {
        "config_hint": "Use MCP stdio or SSE transport",
        "doc_url": "https://modelcontextprotocol.io/quickstart/server",
    },
}


def platform_config() -> dict[str, str]:
    """Return platform-specific configuration hints."""
    return _PLATFORM_DEFAULTS.get(PLATFORM, _PLATFORM_DEFAULTS["generic"])


# ── Backward compatibility ───────────────────────────────────────────────────
# These mappings allow existing OPENCLAW_* env vars to still work.

_COMPAT_ENV_MAP: dict[str, str] = {
    "OPENCLAW_DIR": "FIRM_DIR",
    "OPENCLAW_CONFIG": "FIRM_CONFIG",
    "OPENCLAW_CREDS": "FIRM_CREDS",
    "OPENCLAW_WORKSPACE": "FIRM_WORKSPACE",
    "OPENCLAW_GATEWAY_URL": "FIRM_GATEWAY_URL",
    "OPENCLAW_GATEWAY_HTTP": "FIRM_GATEWAY_HTTP",
    "OPENCLAW_GATEWAY_TOKEN": "FIRM_GATEWAY_TOKEN",
    "OPENCLAW_TIMEOUT_SECONDS": "FIRM_TIMEOUT_SECONDS",
    "OPENCLAW_MODEL": "FIRM_MODEL",
    "OPENCLAW_PROVIDER": "FIRM_PROVIDER",
    "OPENCLAW_MAX_TOKENS": "FIRM_MAX_TOKENS",
    "OPENCLAW_SHELL": "FIRM_SHELL",
}


def resolve_env(new_key: str, old_key: str | None = None, default: str = "") -> str:
    """Resolve an env var with backward compat: check FIRM_*, fall back to OPENCLAW_*."""
    val = os.getenv(new_key)
    if val is not None:
        return val
    if old_key:
        val = os.getenv(old_key)
        if val is not None:
            return val
    return default
