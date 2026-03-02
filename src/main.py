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
import hmac
import inspect
import json
import logging
import os
import signal
import sys
import time
from typing import Any

__version__ = "3.1.0"

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
TOOL_TIMEOUT_S: float = float(os.getenv("TOOL_TIMEOUT_S", "120"))  # Per-tool timeout

# ── Import tool modules ───────────────────────────────────────────────────────
from src import (  # noqa: E402
    a2a_bridge,
    acp_bridge,
    advanced_security,
    agent_orchestration,
    auth_compliance,
    browser_audit,
    compliance_medium,
    config_migration,
    delivery_export,
    ecosystem_audit,
    gateway_fleet,
    gateway_hardening,
    hebbian_memory,
    i18n_audit,
    market_research,
    memory_audit,
    n8n_bridge,
    observability,
    platform_audit,
    prompt_security,
    reliability_probe,
    runtime_audit,
    security_audit,
    skill_loader,
    spec_compliance,
    vs_bridge,
)
from src.models import TOOL_MODELS  # noqa: E402

_ALL_MODULES = [vs_bridge, gateway_fleet, delivery_export, security_audit, acp_bridge, reliability_probe, gateway_hardening, runtime_audit, advanced_security, config_migration, observability, memory_audit, hebbian_memory, agent_orchestration, i18n_audit, skill_loader, n8n_bridge, browser_audit, a2a_bridge, platform_audit, ecosystem_audit, spec_compliance, prompt_security, auth_compliance, compliance_medium, market_research]

# ── M-C1: Category → icon mapping (MCP 2025-11-25 SEP-973) ──────────────────
CATEGORY_ICONS: dict[str, str] = {
    "a2a":                 "🔗",
    "acp":                 "💾",
    "auth_compliance":     "🔐",
    "browser_automation":  "🌐",
    "compliance_medium":   "📋",
    "ecosystem":           "🌍",
    "export":              "📤",
    "fleet":               "🚀",
    "hebbian_memory":      "🧠",
    "i18n":                "🌎",
    "memory":              "💽",
    "observability":       "📊",
    "orchestration":       "🎯",
    "other":               "🔧",
    "performance":         "⚡",
    "platform":            "🏗️",
    "prompt_security":     "🛡️",
    "reliability":         "✅",
    "security":            "🔒",
    "spec_compliance":     "📜",
    "vs_bridge":           "🔌",
    "workflow_automation":  "⚙️",
    "market_research":      "📊",
}

# Build registry: tool_name → {handler, inputSchema, description, category}
TOOL_REGISTRY: dict[str, dict[str, Any]] = {}
for _mod in _ALL_MODULES:
    for _tool in _mod.TOOLS:
        TOOL_REGISTRY[_tool["name"]] = _tool

logger.info("Registered %d tools from %d modules", len(TOOL_REGISTRY), len(_ALL_MODULES))

# ── MCP Resources registry (M-C3) ───────────────────────────────────────────
_MCP_RESOURCES: list[dict[str, Any]] = [
    {
        "uri": "openclaw://config/main",
        "name": "OpenClaw Configuration",
        "description": "Main OpenClaw gateway configuration file",
        "mimeType": "application/json",
    },
    {
        "uri": "openclaw://health",
        "name": "Server Health",
        "description": "MCP extensions server health status and tool inventory",
        "mimeType": "application/json",
    },
]

# ── MCP Prompts registry (M-H1) ─────────────────────────────────────────────
_MCP_PROMPTS: list[dict[str, Any]] = [
    {
        "name": "security-audit",
        "description": "Run a comprehensive security audit on an OpenClaw configuration",
        "arguments": [
            {"name": "config_path", "description": "Path to OpenClaw config file", "required": False},
            {"name": "severity_filter", "description": "Minimum severity: CRITICAL, HIGH, MEDIUM, LOW", "required": False},
        ],
    },
    {
        "name": "compliance-check",
        "description": "Check MCP spec compliance for a given OpenClaw installation",
        "arguments": [
            {"name": "config_path", "description": "Path to OpenClaw config file", "required": False},
            {"name": "spec_version", "description": "MCP spec version to check against (default: 2025-11-25)", "required": False},
        ],
    },
    {
        "name": "fleet-status",
        "description": "Get the status of all gateway instances in the fleet",
        "arguments": [],
    },
    {
        "name": "hebbian-analysis",
        "description": "Analyze memory patterns using Hebbian learning layers",
        "arguments": [
            {"name": "session_id", "description": "Session ID to analyze", "required": False},
            {"name": "min_weight", "description": "Minimum connection weight threshold", "required": False},
        ],
    },
]

# ── MCP protocol helpers ─────────────────────────────────────────────────────

def _mcp_tools_list() -> list[dict[str, Any]]:
    """Return MCP tools/list payload with icons (MCP 2025-11-25)."""
    tools = []
    for t in TOOL_REGISTRY.values():
        cat = t.get("category", "other")
        icon_emoji = CATEGORY_ICONS.get(cat, "🔧")
        entry: dict[str, Any] = {
            "name": t["name"],
            "description": t["description"],
            "inputSchema": t["inputSchema"],
            "icons": [{"uri": f"data:text/plain,{icon_emoji}", "mediaType": "text/plain"}],
        }
        # Include optional MCP 2025-11-25 fields if present
        if "annotations" in t:
            entry["annotations"] = t["annotations"]
        if "outputSchema" in t:
            entry["outputSchema"] = t["outputSchema"]
        if "title" in t:
            entry["title"] = t["title"]
        tools.append(entry)
    return tools


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
            result = await asyncio.wait_for(handler(**filtered), timeout=TOOL_TIMEOUT_S)
        else:
            result = handler(**filtered)
    except asyncio.TimeoutError:
        logger.error("Tool %s timed out after %.0fs", name, TOOL_TIMEOUT_S)
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Tool timed out after {TOOL_TIMEOUT_S}s"}],
        }
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
        # M-C2: structuredContent alongside content (MCP 2025-06-18)
        "structuredContent": result if isinstance(result, dict) else {"result": result},
        # M-H5: resource links in tool responses (MCP 2025-11-25)
        **(_resource_links_for_tool(name) or {}),
    }


# ── MCP Resources handlers (M-C3) ───────────────────────────────────────────

# M-H5: Map tool name patterns → related resource URIs
_TOOL_RESOURCE_LINKS: dict[str, list[dict[str, str]]] = {}
for _tool_name in TOOL_REGISTRY:
    _links: list[dict[str, str]] = []
    # Config-related tools link to the config resource
    if any(kw in _tool_name for kw in ("config", "audit", "check", "scan", "security", "compliance", "hardening", "runtime", "migration")):
        _links.append({"uri": "openclaw://config/main", "name": "OpenClaw Configuration"})
    # All tools link to health
    _links.append({"uri": "openclaw://health", "name": "Server Health"})
    _TOOL_RESOURCE_LINKS[_tool_name] = _links


def _resource_links_for_tool(name: str) -> dict[str, Any] | None:
    """Return resource links dict for a tool response (M-H5)."""
    links = _TOOL_RESOURCE_LINKS.get(name)
    if links:
        return {"_meta": {"resourceLinks": links}}
    return None

async def _read_resource(uri: str) -> dict[str, Any]:
    """Read a resource by URI."""
    if uri == "openclaw://config/main":
        from src.config_helpers import load_config
        config, path = load_config(None)
        return {
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps(config, indent=2, default=str),
            }],
        }
    elif uri == "openclaw://health":
        categories: dict[str, int] = {}
        for t in TOOL_REGISTRY.values():
            cat = t.get("category", "other")
            categories[cat] = categories.get(cat, 0) + 1
        health = {
            "status": "ok", "version": __version__,
            "tools": len(TOOL_REGISTRY), "categories": categories,
            "ts": time.time(),
        }
        return {
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps(health, indent=2),
            }],
        }
    return {"contents": [], "error": f"Unknown resource: {uri}"}


# ── MCP Prompts handler (M-H1) ──────────────────────────────────────────────

_PROMPT_TOOL_MAP: dict[str, list[str]] = {
    "security-audit": [
        "openclaw_security_scan", "openclaw_sandbox_audit",
        "openclaw_session_config_check", "openclaw_rate_limit_check",
        "openclaw_secrets_lifecycle_check", "openclaw_gateway_auth_check",
    ],
    "compliance-check": [
        "openclaw_elicitation_audit", "openclaw_tasks_audit",
        "openclaw_resources_prompts_audit", "openclaw_json_schema_dialect_check",
        "openclaw_sse_transport_audit", "openclaw_icon_metadata_audit",
    ],
    "fleet-status": ["firm_gateway_fleet_status", "firm_gateway_fleet_list"],
    "hebbian-analysis": [
        "openclaw_hebbian_analyze", "openclaw_hebbian_status",
        "openclaw_hebbian_weight_update",
    ],
}


async def _get_prompt(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Generate prompt messages for a named prompt template."""
    tools = _PROMPT_TOOL_MAP.get(name, [])
    if not tools:
        return {"messages": [], "error": f"Unknown prompt: {name}"}

    tool_list = ", ".join(tools)
    messages = [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": (
                    f"Run the following {name} audit using these tools: {tool_list}. "
                    f"Parameters: {json.dumps(arguments)}. "
                    f"Provide a structured report with severity levels."
                ),
            },
        }
    ]
    return {"messages": messages}


# ── Request router ───────────────────────────────────────────────────────────

# M-H2: Pending elicitation requests
_PENDING_ELICITATIONS: dict[str, dict[str, Any]] = {}

# M-H3: Durable task store
_MCP_TASKS: dict[str, dict[str, Any]] = {}


async def _run_durable_task(task_id: str, tool_name: str, arguments: dict[str, Any]) -> None:
    """Execute a tool as a durable/long-running task (M-H3)."""
    try:
        result = await _mcp_call_tool(tool_name, arguments)
        _MCP_TASKS[task_id]["result"] = result
        _MCP_TASKS[task_id]["status"] = "completed"
        _MCP_TASKS[task_id]["completed_at"] = time.time()
    except Exception as exc:
        _MCP_TASKS[task_id]["status"] = "failed"
        _MCP_TASKS[task_id]["error"] = str(exc)
        _MCP_TASKS[task_id]["completed_at"] = time.time()


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
    if not hmac.compare_digest(token, MCP_AUTH_TOKEN):
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

    # M-M1: Protocol-Version header (MCP 2025-11-25)
    _MCP_HEADERS = {"MCP-Protocol-Version": "2025-11-25"}

    async def respond(result: Any) -> web.Response:
        return web.json_response({"jsonrpc": "2.0", "id": msg_id, "result": result}, headers=_MCP_HEADERS)

    async def error(code: int, message: str) -> web.Response:
        return web.json_response(
            {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}},
            headers=_MCP_HEADERS,
        )

    # ── MCP methods ──────────────────────────────────────────────────────────
    if method == "initialize":
        # M-H4: listChanged True for dynamic tool loading
        # M-C3: resources capability
        # M-H1: prompts capability
        return await respond({
            "protocolVersion": "2025-11-25",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
                "elicitation": {},  # M-H2
            },
            "serverInfo": {
                "name": "mcp-openclaw-extensions",
                "version": __version__,
                "description": (
                    "OpenClaw MCP extensions server — 115 tools across 22 categories: "
                    "security audit, compliance, A2A bridge (RC v1.0), Hebbian memory, fleet management, "
                    "delivery export, observability, and more."
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

    # ── M-C3: Resources ─────────────────────────────────────────────────────
    elif method == "resources/list":
        return await respond({"resources": _MCP_RESOURCES})

    elif method == "resources/read":
        uri = params.get("uri", "")
        result = await _read_resource(uri)
        return await respond(result)

    # ── M-H1: Prompts ───────────────────────────────────────────────────────
    elif method == "prompts/list":
        return await respond({"prompts": _MCP_PROMPTS})

    elif method == "prompts/get":
        prompt_name = params.get("name", "")
        prompt_args = params.get("arguments", {})
        result = await _get_prompt(prompt_name, prompt_args)
        return await respond(result)

    # ── M-H2: Elicitation — request user input during tool execution ────────
    elif method == "elicitation/create":
        # Server-side: accept elicitation requests from tools, store pending
        elicit_id = f"elicit-{int(time.time()*1000)}"
        _PENDING_ELICITATIONS[elicit_id] = {
            "id": elicit_id,
            "message": params.get("message", ""),
            "requestedSchema": params.get("requestedSchema", {}),
            "status": "pending",
            "created_at": time.time(),
        }
        return await respond({"id": elicit_id, "action": "accept", "content": {}})

    # ── M-H3: Tasks / durable requests — long-running operations ────────────
    elif method == "tasks/create":
        task_id = f"task-{int(time.time()*1000)}"
        tool_name = params.get("toolName", "")
        arguments = params.get("arguments", {})
        _MCP_TASKS[task_id] = {
            "id": task_id,
            "toolName": tool_name,
            "status": "running",
            "created_at": time.time(),
            "result": None,
        }
        # Run tool in background
        asyncio.create_task(_run_durable_task(task_id, tool_name, arguments))
        return await respond({"taskId": task_id, "status": "running"})

    elif method == "tasks/get":
        task_id = params.get("taskId", "")
        task = _MCP_TASKS.get(task_id)
        if not task:
            return await error(-32602, f"Task not found: {task_id}")
        return await respond(task)

    elif method == "tasks/list":
        return await respond({"tasks": list(_MCP_TASKS.values())})

    elif method == "tasks/cancel":
        task_id = params.get("taskId", "")
        task = _MCP_TASKS.get(task_id)
        if not task:
            return await error(-32602, f"Task not found: {task_id}")
        task["status"] = "cancelled"
        return await respond({"taskId": task_id, "status": "cancelled"})

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
        "version": __version__,
        "tools": len(TOOL_REGISTRY),
        "categories": categories,
        "ts": time.time(),
    })


# ── Server lifecycle ──────────────────────────────────────────────────────────

# M-H6: SSE event queue for streaming
_SSE_EVENTS: list[dict[str, Any]] = []


async def _handle_sse(request: web.Request) -> web.StreamResponse:
    """SSE endpoint for MCP event streaming (M-H6)."""
    auth_error = _check_auth(request)
    if auth_error is not None:
        return auth_error

    response = web.StreamResponse(
        status=200,
        reason="OK",
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "MCP-Protocol-Version": "2025-11-25",
        },
    )
    await response.prepare(request)

    # Send current task statuses as initial events
    for task in _MCP_TASKS.values():
        event_data = json.dumps({"type": "task/status", "task": task})
        await response.write(f"data: {event_data}\n\n".encode())

    # Keep-alive ping every 15s until client disconnects
    last_event_idx = len(_SSE_EVENTS)
    try:
        while True:
            # Send any new events
            while last_event_idx < len(_SSE_EVENTS):
                event = _SSE_EVENTS[last_event_idx]
                await response.write(f"data: {json.dumps(event)}\n\n".encode())
                last_event_idx += 1
            # Ping
            await response.write(f": ping {time.time()}\n\n".encode())
            await asyncio.sleep(15)
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    return response

async def _build_app() -> web.Application:
    app = web.Application(client_max_size=2 * 1024 * 1024)  # 2 MB request limit
    app.router.add_post("/mcp", _handle_mcp)
    app.router.add_get("/mcp/sse", _handle_sse)  # M-H6: SSE streaming
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
