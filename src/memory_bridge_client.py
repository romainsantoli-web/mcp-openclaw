from __future__ import annotations

import json
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


class MemoryBridgeClient:
    def __init__(self, base_url: str, query_path: str, timeout_seconds: int = 3) -> None:
        self._base_url = base_url.rstrip("/")
        self._query_path = query_path if query_path.startswith("/") else f"/{query_path}"
        self._timeout_seconds = max(1, timeout_seconds)

    def query(self, query: str, limit: int = 16) -> dict[str, Any]:
        payload = {
            "query": query,
            "limit": max(1, limit),
        }
        request = Request(
            url=f"{self._base_url}{self._query_path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except URLError as exc:
            return {
                "ok": False,
                "error": str(exc),
                "items": [],
            }

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {
                "ok": False,
                "error": "invalid_json_response",
                "items": [],
            }

        if not isinstance(parsed, dict):
            return {"ok": False, "error": "invalid_response_shape", "items": []}
        return parsed
