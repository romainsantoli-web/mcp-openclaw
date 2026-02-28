from __future__ import annotations

from typing import Any

from .openclaw_ws_client import OpenClawError, OpenClawWsClient


async def gateway_health(client: OpenClawWsClient) -> dict[str, Any]:
    try:
        response = await client.request("health.ping", {})
        if response.error:
            return {"ok": False, "error": response.error}
        return {"ok": True, "result": response.result}
    except OpenClawError as exc:
        return {"ok": False, "error": str(exc)}
