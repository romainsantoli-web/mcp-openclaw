from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from typing import Any

import websockets
from websockets.client import WebSocketClientProtocol

from .config import Settings


class OpenClawError(RuntimeError):
    pass


@dataclass
class OpenClawResponse:
    request_id: str
    result: dict[str, Any] | None
    error: dict[str, Any] | None


class OpenClawWsClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._ws: WebSocketClientProtocol | None = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        async with self._lock:
            if self._ws is not None:
                return

            last_error: Exception | None = None
            for _ in range(max(self._settings.openclaw_reconnect_max_attempts, 1)):
                try:
                    self._ws = await websockets.connect(
                        self._settings.openclaw_gateway_url,
                        open_timeout=self._settings.openclaw_timeout_seconds,
                        additional_headers=self._auth_headers(),
                    )
                    return
                except Exception as exc:
                    last_error = exc
                    await asyncio.sleep(0.5)

            raise OpenClawError(
                f"Impossible de se connecter à OpenClaw: {last_error}"
            )

    async def close(self) -> None:
        async with self._lock:
            if self._ws is not None:
                await self._ws.close()
                self._ws = None

    async def request(self, method: str, params: dict[str, Any] | None = None) -> OpenClawResponse:
        if method not in self._settings.openclaw_allowed_methods:
            raise OpenClawError(f"Méthode non autorisée: {method}")

        if self._settings.read_only_mode and method.endswith(".write"):
            raise OpenClawError("Mode lecture seule actif: écriture refusée")

        await self.connect()
        assert self._ws is not None

        request_id = str(uuid.uuid4())
        payload = {
            "id": request_id,
            "method": method,
            "params": params or {},
        }

        try:
            await asyncio.wait_for(
                self._ws.send(json.dumps(payload)),
                timeout=self._settings.openclaw_timeout_seconds,
            )
            raw = await asyncio.wait_for(
                self._ws.recv(),
                timeout=self._settings.openclaw_timeout_seconds,
            )
        except Exception as exc:
            await self.close()
            raise OpenClawError(f"Erreur réseau OpenClaw: {exc}") from exc

        try:
            message = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OpenClawError("Réponse OpenClaw non JSON") from exc

        return OpenClawResponse(
            request_id=str(message.get("id", request_id)),
            result=message.get("result"),
            error=message.get("error"),
        )

    def _auth_headers(self) -> dict[str, str]:
        if not self._settings.openclaw_token:
            return {}
        return {
            "Authorization": f"Bearer {self._settings.openclaw_token}",
            "x-openclaw-token": self._settings.openclaw_token,
        }
