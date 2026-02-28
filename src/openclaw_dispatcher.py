from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import Settings
from .openclaw_ws_client import OpenClawError, OpenClawWsClient


@dataclass
class DispatchResult:
    ok: bool
    channel: str | None
    request_id: str | None
    result: dict[str, Any] | None
    error: Any
    attempts: list[dict[str, Any]]


def _derive_webhook_url_from_gateway(gateway_url: str) -> str:
    parsed = urlparse(gateway_url)
    scheme = "https" if parsed.scheme == "wss" else "http"
    host = parsed.netloc
    if not host:
        return "http://127.0.0.1:18789/hooks/agent"
    return f"{scheme}://{host}/hooks/agent"


def _ws_payload_variants(method: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        payload,
        {"input": payload},
        {"task": payload.get("objective"), "context": payload},
        {"objective": payload.get("objective"), "payload": payload, "mode": method},
    ]


def _webhook_payload_variants(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        payload,
        {"input": payload},
        {
            "objective": payload.get("objective"),
            "departments": payload.get("departments", []),
            "context": payload,
        },
    ]


class OpenClawDispatcher:
    def __init__(self, settings: Settings, ws_client: OpenClawWsClient) -> None:
        self._settings = settings
        self._ws_client = ws_client

    async def dispatch(
        self,
        method: str,
        payload: dict[str, Any],
    ) -> DispatchResult:
        attempts: list[dict[str, Any]] = []

        mode = self._settings.openclaw_dispatch_mode
        if mode not in {"auto", "ws_only", "webhook_only"}:
            mode = "auto"

        try_ws = mode in {"auto", "ws_only"}
        try_webhook = mode in {"auto", "webhook_only"}

        if try_ws:
            ws_result = await self._try_ws(method=method, payload=payload, attempts=attempts)
            if ws_result is not None:
                return ws_result

        if try_webhook:
            webhook_result = await self._try_webhook(payload=payload, attempts=attempts)
            if webhook_result is not None:
                return webhook_result

        return DispatchResult(
            ok=False,
            channel=None,
            request_id=None,
            result=None,
            error="Aucun canal de dispatch n'a réussi",
            attempts=attempts,
        )

    async def _try_ws(
        self,
        method: str,
        payload: dict[str, Any],
        attempts: list[dict[str, Any]],
    ) -> DispatchResult | None:
        if self._settings.openclaw_allowlist_policy == "strict":
            if method not in self._settings.openclaw_allowed_methods:
                attempts.append(
                    {
                        "channel": "ws",
                        "method": method,
                        "status": "skipped",
                        "reason": "method_blocked_by_allowlist",
                    }
                )
                return None

        for index, variant in enumerate(_ws_payload_variants(method, payload), start=1):
            try:
                response = await self._ws_client.request(
                    method=method,
                    params=variant,
                    enforce_allowlist=self._settings.openclaw_allowlist_policy == "strict",
                )
            except OpenClawError as exc:
                attempts.append(
                    {
                        "channel": "ws",
                        "method": method,
                        "variant": index,
                        "status": "error",
                        "error": str(exc),
                    }
                )
                continue

            if response.error is None:
                attempts.append(
                    {
                        "channel": "ws",
                        "method": method,
                        "variant": index,
                        "status": "ok",
                        "request_id": response.request_id,
                    }
                )
                return DispatchResult(
                    ok=True,
                    channel="ws",
                    request_id=response.request_id,
                    result=response.result,
                    error=None,
                    attempts=attempts,
                )

            attempts.append(
                {
                    "channel": "ws",
                    "method": method,
                    "variant": index,
                    "status": "rejected",
                    "error": response.error,
                }
            )

        return None

    async def _try_webhook(
        self,
        payload: dict[str, Any],
        attempts: list[dict[str, Any]],
    ) -> DispatchResult | None:
        webhook_url = self._settings.openclaw_webhook_url or _derive_webhook_url_from_gateway(
            self._settings.openclaw_gateway_url
        )

        headers = {}
        if self._settings.openclaw_token:
            headers["Authorization"] = f"Bearer {self._settings.openclaw_token}"
            headers["x-openclaw-token"] = self._settings.openclaw_token

        timeout = self._settings.openclaw_timeout_seconds
        async with httpx.AsyncClient(timeout=timeout) as client:
            for index, body in enumerate(_webhook_payload_variants(payload), start=1):
                try:
                    response = await client.post(webhook_url, headers=headers, json=body)
                except Exception as exc:
                    attempts.append(
                        {
                            "channel": "webhook",
                            "url": webhook_url,
                            "variant": index,
                            "status": "error",
                            "error": str(exc),
                        }
                    )
                    continue

                response_data: dict[str, Any] | None
                try:
                    response_data = response.json()
                except Exception:
                    response_data = {"raw": response.text}

                if 200 <= response.status_code < 300:
                    request_id = None
                    if isinstance(response_data, dict):
                        request_id = str(response_data.get("id") or response_data.get("request_id") or "") or None
                    attempts.append(
                        {
                            "channel": "webhook",
                            "url": webhook_url,
                            "variant": index,
                            "status": "ok",
                            "http_status": response.status_code,
                        }
                    )
                    return DispatchResult(
                        ok=True,
                        channel="webhook",
                        request_id=request_id,
                        result=response_data if isinstance(response_data, dict) else {"data": response_data},
                        error=None,
                        attempts=attempts,
                    )

                attempts.append(
                    {
                        "channel": "webhook",
                        "url": webhook_url,
                        "variant": index,
                        "status": "rejected",
                        "http_status": response.status_code,
                        "error": response_data,
                    }
                )

        return None
