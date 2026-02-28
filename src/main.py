"""
main.py — MCP OpenClaw Extensions server
Exposes: VS Code bridge · Fleet manager · Delivery export

Starts a streamable HTTP MCP server on MCP_HOST:MCP_PORT (default 127.0.0.1:8012)
so it can run alongside the existing mcp-openclaw server (port 8011).

Run:
  python -m src.main

Or via scripts:
  ./scripts/start.sh
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import signal
import sys
import time
from typing import Any

from aiohttp import web
from pydantic import ValidationError

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("mcp_ext.main")

# ── Configuration ────────────────────────────────────────────────────────────
MCP_HOST: str = os.getenv("MCP_EXT_HOST", "127.0.0.1")
MCP_PORT: int = int(os.getenv("MCP_EXT_PORT", "8012"))
MCP_AUTH_TOKEN: str | None = os.getenv("MCP_AUTH_TOKEN")  # Optional Bearer auth

# ── Import tool modules ───────────────────────────────────────────────────────
from src import (  # noqa: E402
    acp_bridge,
    advanced_security,
    config_migration,
    delivery_export,
    gateway_fleet,
    gateway_hardening,
    memory_audit,
    observability,
    reliability_probe,
    runtime_audit,
    security_audit,
    vs_bridge,
)
from src.models import TOOL_MODELS  # noqa: E402

_ALL_MODULES = [vs_bridge, gateway_fleet, delivery_export, security_audit, acp_bridge, reliability_probe, gateway_hardening, runtime_audit, advanced_security, config_migration, observability, memory_audit]

# Build registry: tool_name → {handler, inputSchema, description, category}
TOOL_REGISTRY: dict[str, dict[str, Any]] = {}
for _mod in _ALL_MODULES:
    for _tool in _mod.TOOLS:
        TOOL_REGISTRY[_tool["name"]] = _tool

logger.info("Registered %d tools from %d modules", len(TOOL_REGISTRY), len(_ALL_MODULES))

# ── MCP protocol helpers ─────────────────────────────────────────────────────

def _mcp_tools_list() -> list[dict[str, Any]]:
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "inputSchema": t["inputSchema"],
        }
        for t in TOOL_REGISTRY.values()
    ]


async def _mcp_call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name not in TOOL_REGISTRY:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
        }

    # ── Pydantic validation ───────────────────────────────────────────────────
    model_cls = TOOL_MODELS.get(name)
    if model_cls is not None:
        try:
            validated = model_cls.model_validate(arguments)
            # Use validated + coerced values for the handler call
            arguments = validated.model_dump(exclude_unset=False)
        except ValidationError as exc:
            errors = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
            return {
                "isError": True,
                "content": [{
                    "type": "text",
                    "text": json.dumps({"error": "Validation failed", "details": errors}),
                }],
            }

    handler = TOOL_REGISTRY[name]["handler"]

    # Filter to only kwargs the handler actually accepts
    sig = inspect.signature(handler)
    filtered: dict[str, Any] = {
        k: v for k, v in arguments.items() if k in sig.parameters
    }

    try:
        if asyncio.iscoroutinefunction(handler):
            result = await handler(**filtered)
        else:
            result = handler(**filtered)
    except TypeError as exc:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Invalid arguments: {exc}"}],
        }
    except Exception as exc:
        logger.exception("Tool %s raised an error", name)
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Tool error: {exc}"}],
        }

    return {
        "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}],
    }


# ── Request router ───────────────────────────────────────────────────────────


def _check_auth(request: web.Request) -> web.Response | None:
    """Verify Bearer token if MCP_AUTH_TOKEN is set. Returns error response or None."""
    if not MCP_AUTH_TOKEN:
        return None  # Auth disabled — no token configured
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return web.json_response(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "Missing Authorization: Bearer <token>"}},
            status=401,
        )
    token = auth_header[7:]
    if token != MCP_AUTH_TOKEN:
        return web.json_response(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "Invalid token"}},
            status=403,
        )
    return None


async def _handle_mcp(request: web.Request) -> web.Response:
    """
    Streamable HTTP MCP endpoint — handles all MCP JSON-RPC 2.0 messages.
    Supports: initialize, tools/list, tools/call, ping.
    Protected by Bearer auth when MCP_AUTH_TOKEN is set.
    """
    auth_error = _check_auth(request)
    if auth_error is not None:
        return auth_error

    try:
        body = await request.json()
    except Exception:
        return web.Response(status=400, text="Invalid JSON")

    method: str = body.get("method", "")
    msg_id = body.get("id")
    params: dict[str, Any] = body.get("params", {})

    async def respond(result: Any) -> web.Response:
        return web.json_response({"jsonrpc": "2.0", "id": msg_id, "result": result})

    async def error(code: int, message: str) -> web.Response:
        return web.json_response(
            {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
        )

    # ── MCP methods ──────────────────────────────────────────────────────────
    if method == "initialize":
        return await respond({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": "mcp-openclaw-extensions",
                "version": "1.0.0",
                "description": (
                    "VS Code↔OpenClaw bridge · Fleet manager · "
                    "Delivery export pipeline"
                ),
            },
        })

    elif method == "tools/list":
        return await respond({"tools": _mcp_tools_list()})

    elif method == "tools/call":
        tool_name: str = params.get("name", "")
        arguments: dict[str, Any] = params.get("arguments", {})
        result = await _mcp_call_tool(tool_name, arguments)
        return await respond(result)

    elif method == "ping":
        return await respond({"pong": True, "ts": time.time()})

    else:
        return await error(-32601, f"Method not found: {method}")


async def _handle_health(request: web.Request) -> web.Response:
    categories: dict[str, int] = {}
    for t in TOOL_REGISTRY.values():
        cat = t.get("category", "other")
        categories[cat] = categories.get(cat, 0) + 1
    return web.json_response({
        "status": "ok",
        "version": "1.0.0",
        "tools": len(TOOL_REGISTRY),
        "categories": categories,
        "ts": time.time(),
    })


# ── Server lifecycle ──────────────────────────────────────────────────────────

async def _build_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/mcp", _handle_mcp)
    app.router.add_get("/mcp", _handle_mcp)   # For SSE-style discovery
    app.router.add_get("/health", _handle_health)
    app.router.add_get("/healthz", _handle_health)
    return app


async def _main() -> None:
    app = await _build_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, MCP_HOST, MCP_PORT)
    await site.start()

    logger.info("MCP OpenClaw Extensions server started")
    logger.info("  MCP endpoint : http://%s:%d/mcp", MCP_HOST, MCP_PORT)
    logger.info("  Health check : http://%s:%d/health", MCP_HOST, MCP_PORT)
    logger.info("  Tools registered: %d", len(TOOL_REGISTRY))

    # Graceful shutdown on SIGTERM / SIGINT
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _on_signal():
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except (NotImplementedError, RuntimeError):
            pass  # Windows fallback

    await stop_event.wait()
    logger.info("Shutting down...")
    await runner.cleanup()


def main() -> None:
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
