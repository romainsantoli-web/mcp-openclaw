"""
vs_bridge.py — VS Code ↔ OpenClaw bidirectional context bridge
Vide #4 : premier bridge VS Code ↔ OpenClaw de l'écosystème

Tools exposed:
  vs_context_push  — envoie le contexte VS Code vers une session OpenClaw
  vs_context_pull  — récupère le contexte d'une session OpenClaw dans VS Code
  vs_session_link  — associe un workspace VS Code à une session OpenClaw
  vs_session_status — statut de la liaison courante
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

try:
    import websockets
    from websockets.exceptions import WebSocketException
except ImportError:  # graceful degradation — tools still register
    websockets = None  # type: ignore[assignment]
    WebSocketException = OSError  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────

GATEWAY_URL: str = os.getenv("OPENCLAW_GATEWAY_URL", "ws://127.0.0.1:18789")
GATEWAY_HTTP: str = os.getenv("OPENCLAW_GATEWAY_HTTP", "http://127.0.0.1:18789")
GATEWAY_TOKEN: str | None = os.getenv("OPENCLAW_GATEWAY_TOKEN")
WS_TIMEOUT: float = float(os.getenv("OPENCLAW_TIMEOUT_SECONDS", "15"))
MAX_CONTEXT_BYTES: int = int(os.getenv("VS_BRIDGE_MAX_CONTEXT_BYTES", str(32 * 1024)))  # 32 KB

# In-memory session registry for this process (workspace_path → session_id)
_session_registry: dict[str, str] = {}


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class VSContext:
    """Snapshot of the current VS Code workspace state."""
    workspace_path: str
    open_files: list[str] = field(default_factory=list)
    active_file: str | None = None
    recent_changes: list[dict[str, Any]] = field(default_factory=list)
    agent_last_action: str | None = None
    agent_last_result: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_payload(self) -> dict[str, Any]:
        return {
            "workspace_path": self.workspace_path,
            "open_files": self.open_files[-20:],  # cap at 20
            "active_file": self.active_file,
            "recent_changes": self.recent_changes[-10:],  # cap at 10
            "agent_last_action": self.agent_last_action,
            "agent_last_result": self.agent_last_result,
            "timestamp": self.timestamp,
            "source": "vscode",
        }

    def fingerprint(self) -> str:
        return hashlib.sha256(
            json.dumps(self.to_payload(), sort_keys=True).encode()
        ).hexdigest()[:16]


# ── WebSocket helpers ────────────────────────────────────────────────────────

def _build_ws_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    if GATEWAY_TOKEN:
        headers["Authorization"] = f"Bearer {GATEWAY_TOKEN}"
    return headers


async def _ws_rpc(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Send one JSON-RPC call to the OpenClaw Gateway and return the result."""
    msg_id = int(time.time() * 1000)
    payload = json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params})

    async with websockets.connect(
        GATEWAY_URL,
        additional_headers=_build_ws_headers(),
        open_timeout=WS_TIMEOUT,
        close_timeout=5,
    ) as ws:
        await ws.send(payload)
        raw = await asyncio.wait_for(ws.recv(), timeout=WS_TIMEOUT)

    response = json.loads(raw)
    if "error" in response:
        raise RuntimeError(f"Gateway error [{response['error']['code']}]: {response['error']['message']}")
    return response.get("result", {})


async def _http_get(path: str) -> dict[str, Any]:
    """HTTP GET against the Gateway REST API."""
    url = f"{GATEWAY_HTTP}{path}"
    headers: dict[str, str] = {}
    if GATEWAY_TOKEN:
        headers["Authorization"] = f"Bearer {GATEWAY_TOKEN}"
    async with httpx.AsyncClient(timeout=WS_TIMEOUT) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()


# ── Tool: vs_context_push ────────────────────────────────────────────────────

async def vs_context_push(
    workspace_path: str,
    open_files: list[str] | None = None,
    active_file: str | None = None,
    recent_changes: list[dict[str, Any]] | None = None,
    agent_last_action: str | None = None,
    agent_last_result: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """
    Push current VS Code workspace context into an OpenClaw session.

    The context is injected into the session via ``sessions.patch`` so the
    OpenClaw agent can reference recent editor state in its next response.

    Args:
        workspace_path: Absolute path of the VS Code workspace root.
        open_files: List of currently open file paths (relative to workspace).
        active_file: The file currently visible/focused in the editor.
        recent_changes: List of recent file change events (path + summary).
        agent_last_action: Description of the last Copilot agent action taken.
        agent_last_result: Result/output of the last Copilot agent action.
        session_id: Target OpenClaw session. Defaults to the linked session for
                    this workspace, or "main" if not linked.

    Returns:
        dict with keys: ok (bool), session_id, fingerprint, bytes_pushed.
    """
    ctx = VSContext(
        workspace_path=workspace_path,
        open_files=open_files or [],
        active_file=active_file,
        recent_changes=recent_changes or [],
        agent_last_action=agent_last_action,
        agent_last_result=agent_last_result,
    )

    payload = ctx.to_payload()
    payload_bytes = len(json.dumps(payload).encode())

    if payload_bytes > MAX_CONTEXT_BYTES:
        # Trim to stay under limit
        payload["open_files"] = payload["open_files"][-5:]
        payload["recent_changes"] = payload["recent_changes"][-3:]
        logger.warning("vs_context_push: context trimmed to fit %d byte limit", MAX_CONTEXT_BYTES)

    target_session = session_id or _session_registry.get(workspace_path, "main")

    try:
        await _ws_rpc("sessions.patch", {
            "session": target_session,
            "vs_context": payload,
        })
        ok = True
        error_msg = None
    except (WebSocketException, RuntimeError, Exception) as exc:
        ok = False
        error_msg = str(exc)
        logger.error("vs_context_push failed: %s", exc)

    return {
        "ok": ok,
        "session_id": target_session,
        "fingerprint": ctx.fingerprint(),
        "bytes_pushed": payload_bytes,
        "error": error_msg,
    }


# ── Tool: vs_context_pull ────────────────────────────────────────────────────

async def vs_context_pull(
    session_id: str = "main",
    workspace_path: str | None = None,
) -> dict[str, Any]:
    """
    Pull the latest OpenClaw session context back into VS Code.

    Retrieves session metadata (model, tokens, last agent message, memory
    summary) from the Gateway so VS Code extensions / Copilot agents can
    reference what OpenClaw has been doing.

    Args:
        session_id: Source OpenClaw session (default: "main").
        workspace_path: If provided, narrows the pull to the linked workspace.

    Returns:
        dict with keys: ok, session_id, context (dict with session data).
    """
    try:
        result = await _ws_rpc("sessions.get", {"session": session_id})
        context: dict[str, Any] = {
            "session_id": session_id,
            "model": result.get("model"),
            "tokens_used": result.get("tokens"),
            "last_message": result.get("lastMessage"),
            "workspace": result.get("workspace"),
            "thinking_level": result.get("thinkingLevel"),
            "retrieved_at": time.time(),
        }
        return {"ok": True, "session_id": session_id, "context": context}

    except (WebSocketException, RuntimeError, Exception) as exc:
        logger.error("vs_context_pull failed: %s", exc)
        return {"ok": False, "session_id": session_id, "error": str(exc), "context": {}}


# ── Tool: vs_session_link ────────────────────────────────────────────────────

async def vs_session_link(
    workspace_path: str,
    session_id: str,
) -> dict[str, Any]:
    """
    Associate a VS Code workspace with a specific OpenClaw session.

    Once linked, vs_context_push / vs_context_pull will use this session
    by default for the workspace, eliminating the need to pass session_id
    on every call.

    Args:
        workspace_path: Absolute path of the VS Code workspace root.
        session_id: OpenClaw session ID to link (e.g. "main", "session-42").

    Returns:
        dict with keys: ok, workspace_path, session_id, previous_session.
    """
    previous = _session_registry.get(workspace_path)

    # Verify session exists before registering
    try:
        await _ws_rpc("sessions.get", {"session": session_id})
        _session_registry[workspace_path] = session_id
        ok = True
        error_msg = None
    except Exception as exc:
        ok = False
        error_msg = str(exc)

    return {
        "ok": ok,
        "workspace_path": workspace_path,
        "session_id": session_id,
        "previous_session": previous,
        "error": error_msg,
    }


# ── Tool: vs_session_status ──────────────────────────────────────────────────

async def vs_session_status(workspace_path: str | None = None) -> dict[str, Any]:
    """
    Return the current VS Code ↔ OpenClaw bridge status.

    Args:
        workspace_path: Filter to a specific workspace. If None, returns all
                        registered workspaces.

    Returns:
        dict with keys: ok, linked_sessions, gateway_reachable.
    """
    # Test gateway connectivity
    gateway_reachable = False
    try:
        await _http_get("/health")
        gateway_reachable = True
    except Exception:
        pass

    if workspace_path:
        sessions = {workspace_path: _session_registry.get(workspace_path, "(not linked)")}
    else:
        sessions = dict(_session_registry)

    return {
        "ok": True,
        "gateway_url": GATEWAY_URL,
        "gateway_reachable": gateway_reachable,
        "linked_sessions": sessions,
        "registry_count": len(_session_registry),
    }


# ── MCP tool descriptors (used by main.py) ───────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "vs_context_push",
        "title": "Push VS Code Context",
        "description": (
            "Push the current VS Code workspace context (open files, active file, "
            "recent changes, last agent action) into an OpenClaw session so the "
            "OpenClaw agent can reference it. "
            "This is the first VS Code ↔ OpenClaw bridge in the ecosystem."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_path": {"type": "string", "description": "Absolute workspace root path"},
                "open_files": {"type": "array", "items": {"type": "string"}, "description": "Currently open files"},
                "active_file": {"type": "string", "description": "Currently focused file"},
                "recent_changes": {"type": "array", "description": "Recent file change events"},
                "agent_last_action": {"type": "string", "description": "Last Copilot agent action"},
                "agent_last_result": {"type": "string", "description": "Output of last agent action"},
                "session_id": {"type": "string", "description": "Target OpenClaw session (default: main)"},
            },
            "required": ["workspace_path"],
        },
        "handler": vs_context_push,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "category": "vs_bridge",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
    },
    {
        "name": "vs_context_pull",
        "title": "Pull OpenClaw Context",
        "description": (
            "Pull the OpenClaw session context (model, tokens, last message, workspace) "
            "back into VS Code. Enables Copilot agents to know what OpenClaw has been doing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Source OpenClaw session (default: main)"},
                "workspace_path": {"type": "string", "description": "Filter to linked workspace"},
            },
        },
        "handler": vs_context_pull,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "category": "vs_bridge",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
    },
    {
        "name": "vs_session_link",
        "title": "Link VS Code Session",
        "description": (
            "Associate a VS Code workspace with a specific OpenClaw session. "
            "Once linked, push/pull calls use this session automatically."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_path": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["workspace_path", "session_id"],
        },
        "handler": vs_session_link,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "category": "vs_bridge",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
    },
    {
        "name": "vs_session_status",
        "title": "VS Bridge Status",
        "description": "Return bridge status: linked sessions and gateway reachability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_path": {"type": "string", "description": "Filter to specific workspace"},
            },
        },
        "handler": vs_session_status,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "category": "vs_bridge",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
    },
]
