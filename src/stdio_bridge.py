"""
stdio_bridge.py — MCP SDK stdio bridge for VS Code Copilot.

Uses the official MCP Python SDK (mcp>=1.0) to expose all 138 firm-openclaw
tools via the standard stdio transport. VS Code Copilot, Claude Desktop,
Codex CLI, and any MCP-compatible client can connect to this.

Usage:
    python -u src/stdio_bridge.py

Config (.vscode/mcp.json or User/mcp.json):
    {
      "servers": {
        "firm-openclaw": {
          "command": "/path/to/.venv/bin/python3",
          "args": ["-u", "src/stdio_bridge.py"],
          "env": {"PYTHONPATH": "/path/to/mcp-openclaw-extensions"}
        }
      }
    }
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import sys
import time
from typing import Any

# Redirect logging to stderr BEFORE any import that might log
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("mcp_ext.stdio_bridge")

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# ── Import the existing tool registry and models ─────────────────────────────
from src.main import TOOL_REGISTRY, __version__, _mcp_tools_list, _mcp_call_tool

logger.info("stdio_bridge loaded — %d tools from firm-openclaw v%s", len(TOOL_REGISTRY), __version__)

# ── Create MCP SDK Server ────────────────────────────────────────────────────
server = Server("firm-openclaw")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """Expose all 138 firm-openclaw tools via MCP SDK."""
    tools = []
    for t in _mcp_tools_list():
        tools.append(Tool(
            name=t["name"],
            description=t.get("description", ""),
            inputSchema=t.get("inputSchema", {"type": "object", "properties": {}}),
        ))
    return tools


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Dispatch tool calls to the existing firm-openclaw handlers."""
    try:
        result = await _mcp_call_tool(name, arguments)

        # Extract text content from the standard result format
        content_list = result.get("content", [])
        if content_list:
            text = content_list[0].get("text", "{}")
        else:
            text = json.dumps(result, ensure_ascii=False, indent=2)

        is_error = result.get("isError", False)
        if is_error:
            logger.warning("Tool %s returned error: %s", name, text[:200])

        return [TextContent(type="text", text=text)]

    except Exception as e:
        logger.error("Tool %s failed: %s", name, e, exc_info=True)
        error_result = {"ok": False, "error": str(e), "tool": name}
        return [TextContent(type="text", text=json.dumps(error_result, ensure_ascii=False))]


# ── Entry point ──────────────────────────────────────────────────────────────

async def main():
    logger.info("Starting firm-openclaw stdio bridge — %d tools", len(TOOL_REGISTRY))
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
