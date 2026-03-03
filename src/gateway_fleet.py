"""
gateway_fleet.py — Multi-instance Firm Gateway fleet manager
Vide #5 : gestion centralisée d'une flotte de Gateways pour équipes

Tools exposed:
  firm_gateway_fleet_status    — health check de toutes les instances
  firm_gateway_fleet_add       — ajoute une instance à la flotte
  firm_gateway_fleet_remove    — retire une instance de la flotte
  firm_gateway_fleet_broadcast — diffuse un message à toutes les instances
  firm_gateway_fleet_sync      — synchronise la config/skills sur toutes les instances
  firm_gateway_fleet_list      — liste les instances enregistrées
"""

from __future__ import annotations

import asyncio
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

FLEET_CONFIG_PATH: str = os.getenv(
    "FLEET_CONFIG_PATH",
    os.path.expanduser("~/.firm/fleet.json"),
)
FLEET_HEALTH_TIMEOUT: float = float(os.getenv("FLEET_HEALTH_TIMEOUT_SECONDS", "8"))
FLEET_MAX_INSTANCES: int = int(os.getenv("FLEET_MAX_INSTANCES", "50"))
FLEET_BROADCAST_TIMEOUT: float = float(os.getenv("FLEET_BROADCAST_TIMEOUT_SECONDS", "20"))


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class GatewayInstance:
    name: str
    ws_url: str       # e.g. ws://127.0.0.1:18789
    http_url: str     # e.g. http://127.0.0.1:18789
    token: str | None = None
    department: str | None = None  # link to firm pyramid department
    tags: list[str] = field(default_factory=list)
    added_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ws_url": self.ws_url,
            "http_url": self.http_url,
            "token": self.token,
            "department": self.department,
            "tags": self.tags,
            "added_at": self.added_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GatewayInstance":
        return cls(
            name=d["name"],
            ws_url=d["ws_url"],
            http_url=d["http_url"],
            token=d.get("token"),
            department=d.get("department"),
            tags=d.get("tags", []),
            added_at=d.get("added_at", time.time()),
        )


# ── Fleet persistence ────────────────────────────────────────────────────────

def _load_fleet() -> dict[str, GatewayInstance]:
    path = FLEET_CONFIG_PATH
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            raw: dict[str, Any] = json.load(f)
        return {k: GatewayInstance.from_dict(v) for k, v in raw.items()}
    except Exception as exc:
        logger.error("Failed to load fleet config from %s: %s", path, exc)
        return {}


def _save_fleet(fleet: dict[str, GatewayInstance]) -> None:
    path = FLEET_CONFIG_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({k: v.to_dict() for k, v in fleet.items()}, f, indent=2)
        os.replace(tmp, path)  # atomic rename
    except Exception as exc:
        logger.error("Failed to save fleet config: %s", exc)
        if os.path.exists(tmp):
            os.unlink(tmp)


# ── Instance health check ────────────────────────────────────────────────────

async def _check_instance(inst: GatewayInstance) -> dict[str, Any]:
    """Check a single Gateway instance and return its health status."""
    start = time.time()
    headers: dict[str, str] = {}
    if inst.token:
        headers["Authorization"] = f"Bearer {inst.token}"

    try:
        async with httpx.AsyncClient(timeout=FLEET_HEALTH_TIMEOUT) as client:
            resp = await client.get(f"{inst.http_url}/health", headers=headers)
            resp.raise_for_status()
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    except httpx.TimeoutException:
        return {"name": inst.name, "status": "timeout", "latency_ms": None, "error": "timeout"}
    except httpx.HTTPStatusError as exc:
        return {"name": inst.name, "status": "error", "latency_ms": None, "error": str(exc)}
    except Exception as exc:
        return {"name": inst.name, "status": "unreachable", "latency_ms": None, "error": str(exc)}

    latency = round((time.time() - start) * 1000, 1)
    return {
        "name": inst.name,
        "ws_url": inst.ws_url,
        "http_url": inst.http_url,
        "department": inst.department,
        "tags": inst.tags,
        "status": "ok",
        "latency_ms": latency,
        "gateway_version": body.get("version"),
        "sessions_active": body.get("sessions"),
        "uptime_seconds": body.get("uptime"),
    }


async def _ws_rpc_instance(inst: GatewayInstance, method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Send one JSON-RPC call to a specific Gateway instance."""
    msg_id = int(time.time() * 1000)
    payload = json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params})
    headers: dict[str, str] = {}
    if inst.token:
        headers["Authorization"] = f"Bearer {inst.token}"

    async with websockets.connect(
        inst.ws_url,
        additional_headers=headers,
        open_timeout=FLEET_HEALTH_TIMEOUT,
        close_timeout=5,
    ) as ws:
        await ws.send(payload)
        raw = await asyncio.wait_for(ws.recv(), timeout=FLEET_BROADCAST_TIMEOUT)

    response = json.loads(raw)
    if "error" in response:
        raise RuntimeError(f"[{inst.name}] {response['error']['message']}")
    return response.get("result", {})


# ── Tool: firm_gateway_fleet_status ──────────────────────────────────────────

async def firm_gateway_fleet_status(
    filter_department: str | None = None,
    filter_tag: str | None = None,
) -> dict[str, Any]:
    """
    Health check of all registered Gateway instances in the fleet.

    Runs checks in parallel (concurrent HTTP /health calls).

    Args:
        filter_department: Only check instances linked to this department.
        filter_tag: Only check instances with this tag.

    Returns:
        dict with keys: ok, total, healthy, degraded, unreachable, instances.
    """
    fleet = _load_fleet()
    if not fleet:
        return {"ok": True, "total": 0, "healthy": 0, "degraded": 0, "unreachable": 0, "instances": []}

    # Filter
    instances = list(fleet.values())
    if filter_department:
        instances = [i for i in instances if i.department == filter_department]
    if filter_tag:
        instances = [i for i in instances if filter_tag in i.tags]

    # Parallel health checks
    results = await asyncio.gather(*[_check_instance(inst) for inst in instances], return_exceptions=True)

    healthy = sum(1 for r in results if isinstance(r, dict) and r.get("status") == "ok")
    unreachable = sum(1 for r in results if isinstance(r, dict) and r.get("status") in ("unreachable", "timeout"))
    degraded = len(results) - healthy - unreachable

    return {
        "ok": True,
        "total": len(instances),
        "healthy": healthy,
        "degraded": degraded,
        "unreachable": unreachable,
        "instances": [r if isinstance(r, dict) else {"error": str(r)} for r in results],
    }


# ── Tool: firm_gateway_fleet_add ─────────────────────────────────────────────

async def firm_gateway_fleet_add(
    name: str,
    ws_url: str,
    http_url: str,
    token: str | None = None,
    department: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """
    Register a new Gateway instance in the fleet.

    Verifies connectivity before registering.

    Args:
        name: Unique name for this instance (e.g. "dept-engineering", "prod-eu").
        ws_url: WebSocket URL (e.g. "ws://192.168.1.10:18789").
        http_url: HTTP URL (e.g. "http://192.168.1.10:18789").
        token: Optional Bearer token for authentication.
        department: Link to a firm pyramid department name.
        tags: Optional list of tags for filtering.

    Returns:
        dict with keys: ok, name, health_check.
    """
    fleet = _load_fleet()

    if len(fleet) >= FLEET_MAX_INSTANCES:
        return {"ok": False, "error": f"Fleet limit reached ({FLEET_MAX_INSTANCES} instances)"}

    if name in fleet:
        return {"ok": False, "error": f"Instance '{name}' already exists (use fleet_remove first)"}

    # Validate URL format
    if not ws_url.startswith(("ws://", "wss://")):
        return {"ok": False, "error": "ws_url must start with ws:// or wss://"}
    if not http_url.startswith(("http://", "https://")):
        return {"ok": False, "error": "http_url must start with http:// or https://"}

    inst = GatewayInstance(
        name=name,
        ws_url=ws_url,
        http_url=http_url,
        token=token,
        department=department,
        tags=tags or [],
    )

    # Verify connectivity
    health = await _check_instance(inst)
    if health["status"] not in ("ok",):
        return {
            "ok": False,
            "error": f"Instance not reachable: {health.get('error', health['status'])}",
            "health_check": health,
        }

    fleet[name] = inst
    _save_fleet(fleet)

    return {"ok": True, "name": name, "health_check": health}


# ── Tool: firm_gateway_fleet_remove ──────────────────────────────────────────

async def firm_gateway_fleet_remove(name: str) -> dict[str, Any]:
    """
    Remove a Gateway instance from the fleet registry.

    Args:
        name: Name of the instance to remove.

    Returns:
        dict with keys: ok, name, removed.
    """
    fleet = _load_fleet()
    if name not in fleet:
        return {"ok": False, "error": f"Instance '{name}' not found in fleet"}

    del fleet[name]
    _save_fleet(fleet)
    return {"ok": True, "name": name, "removed": True}


# ── Tool: firm_gateway_fleet_broadcast ───────────────────────────────────────

async def firm_gateway_fleet_broadcast(
    message: str,
    session: str = "main",
    filter_department: str | None = None,
    filter_tag: str | None = None,
    require_all_success: bool = False,
) -> dict[str, Any]:
    """
    Broadcast a message to all (or filtered) Gateway instances in the fleet.

    Useful for fleet-wide announcements, config changes, or multi-department
    orchestration kickoffs (e.g. "Start Q1 planning" to all dept Gateways).

    Args:
        message: Message text to send.
        session: Target session on each instance (default: "main").
        filter_department: Only send to instances linked to this department.
        filter_tag: Only send to instances with this tag.
        require_all_success: If True, fail the whole call if any instance fails.

    Returns:
        dict with keys: ok, sent, failed, results.
    """
    fleet = _load_fleet()
    if not fleet:
        return {"ok": True, "sent": 0, "failed": 0, "results": [], "note": "empty fleet"}

    instances = list(fleet.values())
    if filter_department:
        instances = [i for i in instances if i.department == filter_department]
    if filter_tag:
        instances = [i for i in instances if filter_tag in i.tags]

    async def _send_to(inst: GatewayInstance) -> dict[str, Any]:
        try:
            result = await _ws_rpc_instance(inst, "agent.send", {
                "session": session,
                "message": message,
                "source": "fleet_broadcast",
            })
            return {"name": inst.name, "ok": True, "result": result}
        except Exception as exc:
            return {"name": inst.name, "ok": False, "error": str(exc)}

    results = await asyncio.gather(*[_send_to(inst) for inst in instances])
    sent = sum(1 for r in results if r["ok"])
    failed = len(results) - sent

    overall_ok = (failed == 0) if require_all_success else True
    return {
        "ok": overall_ok,
        "sent": sent,
        "failed": failed,
        "total_targeted": len(instances),
        "results": list(results),
    }


# ── Tool: firm_gateway_fleet_sync ─────────────────────────────────────────────

async def firm_gateway_fleet_sync(
    config_patch: dict[str, Any] | None = None,
    skill_slugs: list[str] | None = None,
    filter_department: str | None = None,
    filter_tag: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Sync configuration or skills across all fleet instances.

    Args:
        config_patch: Partial config dict to apply (e.g. {"agent": {"model": "..."}}).
        skill_slugs: List of ClawHub skill slugs to install on each instance.
        filter_department: Only sync instances linked to this department.
        filter_tag: Only sync instances with this tag.
        dry_run: Preview the sync without applying changes.

    Returns:
        dict with keys: ok, synced, failed, results.
    """
    if not config_patch and not skill_slugs:
        return {"ok": False, "error": "Provide at least config_patch or skill_slugs"}

    fleet = _load_fleet()
    instances = list(fleet.values())
    if filter_department:
        instances = [i for i in instances if i.department == filter_department]
    if filter_tag:
        instances = [i for i in instances if filter_tag in i.tags]

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "would_sync_count": len(instances),
            "would_sync_instances": [i.name for i in instances],
            "config_patch": config_patch,
            "skill_slugs": skill_slugs,
        }

    async def _sync_instance(inst: GatewayInstance) -> dict[str, Any]:
        results: list[str] = []
        error: str | None = None
        try:
            if config_patch:
                await _ws_rpc_instance(inst, "gateway.config.patch", {"patch": config_patch})
                results.append("config_patched")
            if skill_slugs:
                for slug in skill_slugs:
                    await _ws_rpc_instance(inst, "skills.install", {"slug": slug})
                    results.append(f"skill:{slug}")
        except Exception as exc:
            error = str(exc)
        return {"name": inst.name, "ok": error is None, "applied": results, "error": error}

    sync_results = await asyncio.gather(*[_sync_instance(inst) for inst in instances])
    synced = sum(1 for r in sync_results if r["ok"])
    failed = len(sync_results) - synced

    return {
        "ok": failed == 0,
        "synced": synced,
        "failed": failed,
        "results": list(sync_results),
    }


# ── Tool: firm_gateway_fleet_list ────────────────────────────────────────────

async def firm_gateway_fleet_list(
    filter_department: str | None = None,
    filter_tag: str | None = None,
) -> dict[str, Any]:
    """
    List all registered Gateway instances in the fleet.

    Args:
        filter_department: Only list instances linked to this department.
        filter_tag: Only list instances with this tag.

    Returns:
        dict with keys: ok, count, instances.
    """
    fleet = _load_fleet()
    instances = list(fleet.values())
    if filter_department:
        instances = [i for i in instances if i.department == filter_department]
    if filter_tag:
        instances = [i for i in instances if filter_tag in i.tags]

    return {
        "ok": True,
        "count": len(instances),
        "instances": [
            {
                "name": i.name,
                "ws_url": i.ws_url,
                "http_url": i.http_url,
                "department": i.department,
                "tags": i.tags,
                "has_token": bool(i.token),
                "added_at": i.added_at,
            }
            for i in instances
        ],
    }


# ── MCP tool descriptors ─────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "firm_gateway_fleet_status",
        "title": "Fleet Health Check",
        "description": "Health check all registered Firm Gateway instances. Runs parallel /health checks and returns latency, version and session counts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter_department": {"type": "string", "description": "Filter by firm department"},
                "filter_tag": {"type": "string", "description": "Filter by tag"},
            },
        },
        "handler": firm_gateway_fleet_status,
        "category": "fleet",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
    },
    {
        "name": "firm_gateway_fleet_add",
        "title": "Add Fleet Instance",
        "description": "Register a new Firm Gateway instance in the fleet. Verifies connectivity before saving.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "ws_url": {"type": "string"},
                "http_url": {"type": "string"},
                "token": {"type": "string"},
                "department": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["name", "ws_url", "http_url"],
        },
        "handler": firm_gateway_fleet_add,
        "category": "fleet",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
    },
    {
        "name": "firm_gateway_fleet_remove",
        "title": "Remove Fleet Instance",
        "description": "Remove a Gateway instance from the fleet registry.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
        "handler": firm_gateway_fleet_remove,
        "category": "fleet",
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
    },
    {
        "name": "firm_gateway_fleet_broadcast",
        "title": "Fleet Broadcast Message",
        "description": "Broadcast a message to all (or filtered) Gateway instances. Useful for fleet-wide announcements and multi-department orchestration kickoffs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "session": {"type": "string", "default": "main"},
                "filter_department": {"type": "string"},
                "filter_tag": {"type": "string"},
                "require_all_success": {"type": "boolean", "default": False},
            },
            "required": ["message"],
        },
        "handler": firm_gateway_fleet_broadcast,
        "category": "fleet",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
    },
    {
        "name": "firm_gateway_fleet_sync",
        "title": "Fleet Config Sync",
        "description": "Sync configuration or skills across all fleet instances in parallel.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_patch": {"type": "object"},
                "skill_slugs": {"type": "array", "items": {"type": "string"}},
                "filter_department": {"type": "string"},
                "filter_tag": {"type": "string"},
                "dry_run": {"type": "boolean", "default": False},
            },
        },
        "handler": firm_gateway_fleet_sync,
        "category": "fleet",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
    },
    {
        "name": "firm_gateway_fleet_list",
        "title": "List Fleet Instances",
        "description": "List all registered Gateway instances with their configuration.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter_department": {"type": "string"},
                "filter_tag": {"type": "string"},
            },
        },
        "handler": firm_gateway_fleet_list,
        "category": "fleet",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
    },
]
