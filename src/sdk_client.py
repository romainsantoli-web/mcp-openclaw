from __future__ import annotations

from contextlib import AsyncExitStack
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


class McpOpenClawClient:
    def __init__(self, url: str = "http://127.0.0.1:8011/mcp") -> None:
        self._url = url
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "McpOpenClawClient":
        stack = AsyncExitStack()
        read_stream, write_stream, _ = await stack.enter_async_context(
            streamable_http_client(self._url)
        )
        session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
        await session.initialize()

        self._stack = stack
        self._session = session
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self._session = None

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("Client non initialisé. Utilise 'async with McpOpenClawClient(...)'.")
        return self._session

    async def list_tools(self) -> list[str]:
        response = await self.session.list_tools()
        return [tool.name for tool in response.tools]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        response = await self.session.call_tool(name, arguments or {})
        content = response.structuredContent
        if isinstance(content, dict):
            return content
        return {"ok": True, "content": content}

    async def run_delivery_workflow(
        self,
        objective: str,
        departments: list[str] | None = None,
        push_to_openclaw: bool = False,
        task_family: str | None = None,
        quality_tier: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "objective": objective,
            "push_to_openclaw": push_to_openclaw,
        }
        if departments is not None:
            payload["departments"] = departments
        if task_family is not None:
            payload["task_family"] = task_family
        if quality_tier is not None:
            payload["quality_tier"] = quality_tier
        return await self.call_tool("firm_run_delivery_workflow", payload)

    async def dashboard_snapshot(self, limit: int = 20) -> dict[str, Any]:
        return await self.call_tool("ops_dashboard_snapshot", {"limit": max(1, limit)})

    async def health(self) -> dict[str, Any]:
        return await self.call_tool("openclaw_health", {})
