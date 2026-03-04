"""
main.py — Firm MCP Server
Generic MCP server compatible with all AI platforms:
Claude Code, Codex, VS Code Copilot, Cursor, Windsurf, Antigravity, etc.

Starts a streamable HTTP MCP server on MCP_HOST:MCP_PORT (default 127.0.0.1:8012).

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
import uuid
from typing import Any

__version__ = "4.1.2"

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

# ── Metrics counters (Prometheus-compatible) ─────────────────────────────────
_METRICS: dict[str, int | float] = {
    "mcp_requests_total": 0,
    "mcp_tool_calls_total": 0,
    "mcp_tool_errors_total": 0,
    "mcp_tool_timeouts_total": 0,
    "mcp_auth_failures_total": 0,
}
_TOOL_CALL_COUNTS: dict[str, int] = {}
_TOOL_ERROR_COUNTS: dict[str, int] = {}
_TOOL_LATENCY_SUM: dict[str, float] = {}
_SERVER_START_TIME: float = time.time()

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
    legal_status,
    location_strategy,
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
    supplier_management,
    vs_bridge,
)
from src.models import TOOL_MODELS  # noqa: E402

_ALL_MODULES = [vs_bridge, gateway_fleet, delivery_export, security_audit, acp_bridge, reliability_probe, gateway_hardening, runtime_audit, advanced_security, config_migration, observability, memory_audit, hebbian_memory, agent_orchestration, i18n_audit, skill_loader, n8n_bridge, browser_audit, a2a_bridge, platform_audit, ecosystem_audit, spec_compliance, prompt_security, auth_compliance, compliance_medium, market_research, legal_status, location_strategy, supplier_management]

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
    "legal_status":         "⚖️",
    "location_strategy":    "📍",
    "procurement":          "🏭",
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
        "uri": "firm://config/main",
        "name": "Server Configuration",
        "description": "Main gateway configuration file",
        "mimeType": "application/json",
    },
    {
        "uri": "firm://health",
        "name": "Server Health",
        "description": "MCP extensions server health status and tool inventory",
        "mimeType": "application/json",
    },
]

# ── MCP Prompts registry (M-H1) ─────────────────────────────────────────────
_MCP_PROMPTS: list[dict[str, Any]] = [
    {
        "name": "security-audit",
        "description": "Run a comprehensive security audit on an server configuration",
        "arguments": [
            {"name": "config_path", "description": "Path to config file", "required": False},
            {"name": "severity_filter", "description": "Minimum severity: CRITICAL, HIGH, MEDIUM, LOW", "required": False},
        ],
    },
    {
        "name": "compliance-check",
        "description": "Check MCP spec compliance for a given server installation",
        "arguments": [
            {"name": "config_path", "description": "Path to config file", "required": False},
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

    _METRICS["mcp_tool_calls_total"] += 1
    _TOOL_CALL_COUNTS[name] = _TOOL_CALL_COUNTS.get(name, 0) + 1
    t0 = time.monotonic()

    try:
        if asyncio.iscoroutinefunction(handler):
            result = await asyncio.wait_for(handler(**filtered), timeout=TOOL_TIMEOUT_S)
        else:
            result = handler(**filtered)
    except asyncio.TimeoutError:
        _METRICS["mcp_tool_timeouts_total"] += 1
        _TOOL_ERROR_COUNTS[name] = _TOOL_ERROR_COUNTS.get(name, 0) + 1
        logger.error("Tool %s timed out after %.0fs", name, TOOL_TIMEOUT_S)
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Tool timed out after {TOOL_TIMEOUT_S}s"}],
        }
    except TypeError as exc:
        _METRICS["mcp_tool_errors_total"] += 1
        _TOOL_ERROR_COUNTS[name] = _TOOL_ERROR_COUNTS.get(name, 0) + 1
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Invalid arguments: {exc}"}],
        }
    except Exception as exc:
        _METRICS["mcp_tool_errors_total"] += 1
        _TOOL_ERROR_COUNTS[name] = _TOOL_ERROR_COUNTS.get(name, 0) + 1
        logger.exception("Tool %s raised an error", name)
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Tool error: {exc}"}],
        }

    elapsed = time.monotonic() - t0
    _TOOL_LATENCY_SUM[name] = _TOOL_LATENCY_SUM.get(name, 0.0) + elapsed

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
        _links.append({"uri": "firm://config/main", "name": "Server Configuration"})
    # All tools link to health
    _links.append({"uri": "firm://health", "name": "Server Health"})
    _TOOL_RESOURCE_LINKS[_tool_name] = _links


def _resource_links_for_tool(name: str) -> dict[str, Any] | None:
    """Return resource links dict for a tool response (M-H5)."""
    links = _TOOL_RESOURCE_LINKS.get(name)
    if links:
        return {"_meta": {"resourceLinks": links}}
    return None

async def _read_resource(uri: str) -> dict[str, Any]:
    """Read a resource by URI."""
    if uri == "firm://config/main":
        from src.config_helpers import load_config
        config, path = load_config(None)
        return {
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps(config, indent=2, default=str),
            }],
        }
    elif uri == "firm://health":
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
        "firm_security_scan", "firm_sandbox_audit",
        "firm_session_config_check", "firm_rate_limit_check",
        "firm_secrets_lifecycle_check", "firm_gateway_auth_check",
    ],
    "compliance-check": [
        "firm_elicitation_audit", "firm_tasks_audit",
        "firm_resources_prompts_audit", "firm_json_schema_dialect_check",
        "firm_sse_transport_audit", "firm_icon_metadata_audit",
    ],
    "fleet-status": ["firm_gateway_fleet_status", "firm_gateway_fleet_list"],
    "hebbian-analysis": [
        "firm_hebbian_analyze", "firm_hebbian_status",
        "firm_hebbian_weight_update",
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
        _METRICS["mcp_auth_failures_total"] += 1
        return auth_error

    _METRICS["mcp_requests_total"] += 1

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
                "name": "firm-mcp-server",
                "version": __version__,
                "description": (
                    "Firm MCP server — 138 tools across 29 modules. "
                    "Compatible with Claude Code, Codex, VS Code, Cursor, Windsurf, Antigravity. "
                    "Security, A2A, Hebbian memory, fleet mgmt, and more."
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


async def _handle_metrics(request: web.Request) -> web.Response:
    """Prometheus-compatible /metrics endpoint."""
    lines = [
        "# HELP mcp_server_info MCP server metadata",
        "# TYPE mcp_server_info gauge",
        f'mcp_server_info{{version="{__version__}"}} 1',
        "",
        "# HELP mcp_tools_registered_total Total number of registered tools",
        "# TYPE mcp_tools_registered_total gauge",
        f"mcp_tools_registered_total {len(TOOL_REGISTRY)}",
        "",
        "# HELP mcp_uptime_seconds Server uptime in seconds",
        "# TYPE mcp_uptime_seconds gauge",
        f"mcp_uptime_seconds {time.time() - _SERVER_START_TIME:.1f}",
        "",
    ]

    # Global counters
    for metric, value in sorted(_METRICS.items()):
        lines.append(f"# HELP {metric} {metric.replace('_', ' ')}")
        lines.append(f"# TYPE {metric} counter")
        lines.append(f"{metric} {value}")
        lines.append("")

    # Per-tool call counts
    if _TOOL_CALL_COUNTS:
        lines.append("# HELP mcp_tool_calls_by_name Tool calls by tool name")
        lines.append("# TYPE mcp_tool_calls_by_name counter")
        for name, count in sorted(_TOOL_CALL_COUNTS.items()):
            lines.append(f'mcp_tool_calls_by_name{{tool="{name}"}} {count}')
        lines.append("")

    # Per-tool error counts
    if _TOOL_ERROR_COUNTS:
        lines.append("# HELP mcp_tool_errors_by_name Tool errors by tool name")
        lines.append("# TYPE mcp_tool_errors_by_name counter")
        for name, count in sorted(_TOOL_ERROR_COUNTS.items()):
            lines.append(f'mcp_tool_errors_by_name{{tool="{name}"}} {count}')
        lines.append("")

    # Per-tool latency sums
    if _TOOL_LATENCY_SUM:
        lines.append("# HELP mcp_tool_latency_seconds_total Cumulative tool latency")
        lines.append("# TYPE mcp_tool_latency_seconds_total counter")
        for name, total in sorted(_TOOL_LATENCY_SUM.items()):
            lines.append(f'mcp_tool_latency_seconds_total{{tool="{name}"}} {total:.4f}')
        lines.append("")

    body = "\n".join(lines) + "\n"
    return web.Response(text=body, content_type="text/plain", charset="utf-8")


# ── Server lifecycle ──────────────────────────────────────────────────────────

# M-H6: SSE event queue for streaming
_SSE_EVENTS: list[dict[str, Any]] = []

# ── Legacy SSE transport (MCP protocol) ──────────────────────────────────────
# VS Code Copilot, Cursor, etc. connect via GET /sse + POST /messages?session_id=xxx
_SSE_SESSIONS: dict[str, asyncio.Queue] = {}


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

async def _handle_sse_transport(request: web.Request) -> web.StreamResponse:
    """Legacy SSE transport — GET /sse.
    Sends an 'endpoint' event with the POST URL for this session,
    then keeps the connection open for server-to-client messages.
    """
    session_id = uuid.uuid4().hex
    queue: asyncio.Queue = asyncio.Queue()
    _SSE_SESSIONS[session_id] = queue

    response = web.StreamResponse(
        status=200,
        reason="OK",
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )
    await response.prepare(request)

    # Tell the client where to POST JSON-RPC messages
    await response.write(f"event: endpoint\ndata: /messages/?session_id={session_id}\n\n".encode())

    try:
        while True:
            try:
                # Wait for outgoing messages (responses are sent inline via POST,
                # but server-initiated notifications go through here)
                msg = await asyncio.wait_for(queue.get(), timeout=15)
                await response.write(f"event: message\ndata: {json.dumps(msg)}\n\n".encode())
            except asyncio.TimeoutError:
                # Keep-alive ping
                await response.write(f": ping {time.time()}\n\n".encode())
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    finally:
        _SSE_SESSIONS.pop(session_id, None)
    return response


async def _handle_messages(request: web.Request) -> web.Response:
    """Legacy SSE transport — POST /messages/?session_id=xxx.
    Receives JSON-RPC requests from the client, dispatches them,
    then pushes the response into the SSE stream (event: message).
    Returns 202 Accepted immediately (no body).
    """
    session_id = request.query.get("session_id", "")
    if session_id not in _SSE_SESSIONS:
        return web.Response(status=404, text="Session not found")

    try:
        body = await request.json()
    except Exception:
        return web.Response(status=400, text="Invalid JSON")

    method: str = body.get("method", "")
    msg_id = body.get("id")
    params: dict[str, Any] = body.get("params", {})

    _MCP_HEADERS = {"MCP-Protocol-Version": "2025-11-25"}

    # Build the JSON-RPC response
    response_payload: dict[str, Any] | None = None

    if method == "initialize":
        response_payload = {
            "jsonrpc": "2.0", "id": msg_id,
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
                    "elicitation": {},
                },
                "serverInfo": {
                    "name": "firm-mcp-server",
                    "version": __version__,
                    "description": (
                        f"Firm MCP server — {len(TOOL_REGISTRY)} tools across 29 modules. "
                        "Compatible with Claude Code, Codex, VS Code, Cursor, Windsurf, Antigravity."
                    ),
                },
            },
        }
    elif method == "notifications/initialized":
        # Client acknowledgement — no response needed
        return web.Response(status=202)
    elif method == "tools/list":
        response_payload = {
            "jsonrpc": "2.0", "id": msg_id,
            "result": {"tools": _mcp_tools_list()},
        }
    elif method == "tools/call":
        tool_name: str = params.get("name", "")
        arguments: dict[str, Any] = params.get("arguments", {})
        result = await _mcp_call_tool(tool_name, arguments)
        response_payload = {"jsonrpc": "2.0", "id": msg_id, "result": result}
    elif method == "resources/list":
        response_payload = {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": _MCP_RESOURCES}}
    elif method == "resources/read":
        uri = params.get("uri", "")
        result = await _read_resource(uri)
        response_payload = {"jsonrpc": "2.0", "id": msg_id, "result": result}
    elif method == "prompts/list":
        response_payload = {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": _MCP_PROMPTS}}
    elif method == "prompts/get":
        prompt_name = params.get("name", "")
        prompt_args = params.get("arguments", {})
        result = await _get_prompt(prompt_name, prompt_args)
        response_payload = {"jsonrpc": "2.0", "id": msg_id, "result": result}
    elif method == "ping":
        response_payload = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    else:
        response_payload = {
            "jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    # Push the response into the SSE stream for this session
    if response_payload is not None:
        queue = _SSE_SESSIONS.get(session_id)
        if queue is not None:
            await queue.put(response_payload)

    return web.Response(status=202)


async def _build_app() -> web.Application:
    app = web.Application(client_max_size=2 * 1024 * 1024)  # 2 MB request limit
    # HTTP Streamable transport (MCP 2025-11-25)
    app.router.add_post("/mcp", _handle_mcp)
    app.router.add_get("/mcp/sse", _handle_sse)  # M-H6: SSE streaming
    # Legacy SSE transport (VS Code Copilot, Cursor, etc.)
    app.router.add_get("/sse", _handle_sse_transport)
    app.router.add_post("/messages/", _handle_messages)
    app.router.add_post("/messages", _handle_messages)  # without trailing slash
    # Health / metrics
    app.router.add_get("/health", _handle_health)
    app.router.add_get("/healthz", _handle_health)
    app.router.add_get("/metrics", _handle_metrics)
    return app


async def _main() -> None:
    app = await _build_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, MCP_HOST, MCP_PORT)
    await site.start()

    logger.info("Firm MCP Server started")
    logger.info("  MCP endpoint : http://%s:%d/mcp", MCP_HOST, MCP_PORT)
    logger.info("  SSE endpoint : http://%s:%d/sse", MCP_HOST, MCP_PORT)
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


# ── Stdio transport (standard MCP — used by VS Code, Claude Desktop, etc.) ───

async def _stdio_main() -> None:
    """Run the MCP server over stdin/stdout (JSON-RPC line-delimited).

    VS Code launches this process and communicates via pipes.
    All logging goes to stderr to keep stdout clean for the protocol.
    """
    # Redirect logging to stderr so stdout stays clean for JSON-RPC
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    logger.info("Firm MCP Server (stdio) starting — %d tools", len(TOOL_REGISTRY))

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

    w_transport, w_protocol = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(w_transport, w_protocol, reader, asyncio.get_event_loop())

    async def _send(obj: dict) -> None:
        line = json.dumps(obj, separators=(",", ":")) + "\n"
        writer.write(line.encode())
        await writer.drain()

    async def _respond(msg_id: Any, result: Any) -> None:
        await _send({"jsonrpc": "2.0", "id": msg_id, "result": result})

    async def _error(msg_id: Any, code: int, message: str) -> None:
        await _send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})

    logger.info("Firm MCP Server (stdio) ready — reading from stdin")

    while True:
        line = await reader.readline()
        if not line:
            break  # EOF — VS Code closed the pipe
        line_str = line.decode().strip()
        if not line_str:
            continue

        try:
            body = json.loads(line_str)
        except json.JSONDecodeError:
            continue

        method: str = body.get("method", "")
        msg_id = body.get("id")
        params: dict[str, Any] = body.get("params", {})

        if method == "initialize":
            await _respond(msg_id, {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
                    "elicitation": {},
                },
                "serverInfo": {
                    "name": "firm-mcp-server",
                    "version": __version__,
                    "description": (
                        "Firm MCP server — 138 tools across 29 modules. "
                        "Security, A2A, Hebbian memory, fleet mgmt, and more."
                    ),
                },
            })

        elif method == "notifications/initialized":
            pass  # Acknowledgement — no response needed

        elif method == "tools/list":
            await _respond(msg_id, {"tools": _mcp_tools_list()})

        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            result = await _mcp_call_tool(tool_name, arguments)
            await _respond(msg_id, result)

        elif method == "resources/list":
            await _respond(msg_id, {"resources": _MCP_RESOURCES})

        elif method == "resources/read":
            uri = params.get("uri", "")
            result = await _read_resource(uri)
            await _respond(msg_id, result)

        elif method == "prompts/list":
            await _respond(msg_id, {"prompts": _MCP_PROMPTS})

        elif method == "prompts/get":
            prompt_name = params.get("name", "")
            prompt_args = params.get("arguments", {})
            result = await _get_prompt(prompt_name, prompt_args)
            await _respond(msg_id, result)

        elif method == "ping":
            await _respond(msg_id, {"pong": True, "ts": time.time()})

        elif msg_id is not None:
            await _error(msg_id, -32601, f"Method not found: {method}")

        # Notifications (no id) — silently ignore unknown ones


def main() -> None:
    try:
        if "--stdio" in sys.argv:
            asyncio.run(_stdio_main())
        else:
            asyncio.run(_main())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
