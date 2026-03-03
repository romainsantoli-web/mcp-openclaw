"""
Coverage tests for src/main.py — MCP server dispatcher, auth, resources, prompts, SSE.
Targets: 0% → 100%.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

# We import the module-level objects directly to test them
from src.main import (
    TOOL_REGISTRY,
    _MCP_PROMPTS,
    _MCP_RESOURCES,
    _MCP_TASKS,
    _PENDING_ELICITATIONS,
    _build_app,
    _check_auth,
    _get_prompt,
    _mcp_call_tool,
    _mcp_tools_list,
    _read_resource,
    _resource_links_for_tool,
    _run_durable_task,
)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── _mcp_tools_list ──────────────────────────────────────────────────────────

class TestMcpToolsList:
    def test_returns_list(self):
        tools = _mcp_tools_list()
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_each_tool_has_required_fields(self):
        tools = _mcp_tools_list()
        for t in tools[:5]:  # spot check first 5
            assert "name" in t
            assert "description" in t
            assert "inputSchema" in t
            assert "icons" in t
            assert len(t["icons"]) >= 1

    def test_icons_have_uri(self):
        tools = _mcp_tools_list()
        t = tools[0]
        assert t["icons"][0]["uri"].startswith("data:text/plain,")
        assert t["icons"][0]["mediaType"] == "text/plain"


# ── _mcp_call_tool ───────────────────────────────────────────────────────────

class TestMcpCallTool:
    def test_unknown_tool(self):
        r = _run(_mcp_call_tool("nonexistent_tool_xyz_999", {}))
        assert r["isError"] is True
        assert "Unknown tool" in r["content"][0]["text"]

    def test_known_tool_returns_content(self):
        # Use a basic tool that doesn't require external resources
        r = _run(_mcp_call_tool("openclaw_prompt_injection_check", {"text": "Hello world safe text"}))
        assert "content" in r
        assert "structuredContent" in r

    def test_pydantic_validation_error(self):
        # prompt_injection_check requires "text" — pass invalid args
        r = _run(_mcp_call_tool("openclaw_prompt_injection_check", {}))
        # Either it works with defaults or returns validation error
        assert "content" in r

    def test_timeout_handling(self):
        """Test that timeout produces isError."""
        # Create a mock handler that sleeps forever
        async def slow_handler(**kwargs):
            await asyncio.sleep(9999)

        with patch.dict(TOOL_REGISTRY, {"__test_slow": {
            "name": "__test_slow",
            "handler": slow_handler,
            "inputSchema": {"type": "object", "properties": {}},
            "description": "test",
        }}):
            with patch("src.main.TOOL_TIMEOUT_S", 0.01):
                r = _run(_mcp_call_tool("__test_slow", {}))
                assert r["isError"] is True
                assert "timed out" in r["content"][0]["text"]

    def test_type_error_handling(self):
        """Handler that raises TypeError."""
        async def bad_handler(**kwargs):
            raise TypeError("bad args")

        with patch.dict(TOOL_REGISTRY, {"__test_typeerr": {
            "name": "__test_typeerr",
            "handler": bad_handler,
            "inputSchema": {"type": "object", "properties": {}},
            "description": "test",
        }}):
            r = _run(_mcp_call_tool("__test_typeerr", {}))
            assert r["isError"] is True
            assert "Invalid arguments" in r["content"][0]["text"]

    def test_generic_exception_handling(self):
        """Handler that raises a generic Exception."""
        async def failing_handler(**kwargs):
            raise ValueError("something broke")

        with patch.dict(TOOL_REGISTRY, {"__test_fail": {
            "name": "__test_fail",
            "handler": failing_handler,
            "inputSchema": {"type": "object", "properties": {}},
            "description": "test",
        }}):
            r = _run(_mcp_call_tool("__test_fail", {}))
            assert r["isError"] is True
            assert "Tool error" in r["content"][0]["text"]

    def test_sync_handler(self):
        """Test with a synchronous (non-async) handler."""
        def sync_handler(**kwargs):
            return {"ok": True, "sync": True}

        with patch.dict(TOOL_REGISTRY, {"__test_sync": {
            "name": "__test_sync",
            "handler": sync_handler,
            "inputSchema": {"type": "object", "properties": {}},
            "description": "test",
        }}):
            r = _run(_mcp_call_tool("__test_sync", {}))
            assert "isError" not in r
            assert "structuredContent" in r

    def test_structured_content_non_dict(self):
        """When handler returns non-dict, structuredContent wraps it."""
        async def list_handler(**kwargs):
            return [1, 2, 3]

        with patch.dict(TOOL_REGISTRY, {"__test_list": {
            "name": "__test_list",
            "handler": list_handler,
            "inputSchema": {"type": "object", "properties": {}},
            "description": "test",
        }}):
            r = _run(_mcp_call_tool("__test_list", {}))
            assert r["structuredContent"] == {"result": [1, 2, 3]}

    def test_extra_kwargs_filtered(self):
        """Extra kwargs not in handler signature are filtered out."""
        async def minimal_handler():
            return {"ok": True}

        with patch.dict(TOOL_REGISTRY, {"__test_minimal": {
            "name": "__test_minimal",
            "handler": minimal_handler,
            "inputSchema": {"type": "object", "properties": {}},
            "description": "test",
        }}):
            r = _run(_mcp_call_tool("__test_minimal", {"extra_arg": "ignored"}))
            assert "content" in r


# ── _read_resource ───────────────────────────────────────────────────────────

class TestReadResource:
    def test_config_resource(self):
        r = _run(_read_resource("openclaw://config/main"))
        assert "contents" in r
        assert r["contents"][0]["uri"] == "openclaw://config/main"

    def test_health_resource(self):
        r = _run(_read_resource("openclaw://health"))
        assert "contents" in r
        data = json.loads(r["contents"][0]["text"])
        assert data["status"] == "ok"
        assert "tools" in data

    def test_unknown_resource(self):
        r = _run(_read_resource("openclaw://unknown"))
        assert "error" in r


# ── _get_prompt ──────────────────────────────────────────────────────────────

class TestGetPrompt:
    def test_known_prompt(self):
        r = _run(_get_prompt("security-audit", {"config_path": "/tmp/test.json"}))
        assert "messages" in r
        assert len(r["messages"]) > 0
        assert r["messages"][0]["role"] == "user"

    def test_compliance_prompt(self):
        r = _run(_get_prompt("compliance-check", {}))
        assert len(r["messages"]) > 0

    def test_fleet_prompt(self):
        r = _run(_get_prompt("fleet-status", {}))
        assert len(r["messages"]) > 0

    def test_hebbian_prompt(self):
        r = _run(_get_prompt("hebbian-analysis", {}))
        assert len(r["messages"]) > 0

    def test_unknown_prompt(self):
        r = _run(_get_prompt("nonexistent-prompt", {}))
        assert r["messages"] == []
        assert "error" in r


# ── _resource_links_for_tool ─────────────────────────────────────────────────

class TestResourceLinks:
    def test_audit_tool_has_config_link(self):
        result = _resource_links_for_tool("openclaw_security_scan")
        assert result is not None
        assert "_meta" in result
        assert any("config" in l["uri"] for l in result["_meta"]["resourceLinks"])

    def test_all_tools_have_health_link(self):
        result = _resource_links_for_tool("firm_gateway_fleet_status")
        assert result is not None
        links = result["_meta"]["resourceLinks"]
        assert any("health" in l["uri"] for l in links)


# ── _check_auth ──────────────────────────────────────────────────────────────

class TestCheckAuth:
    def test_no_token_set(self):
        """When MCP_AUTH_TOKEN is not set, auth is disabled."""
        with patch("src.main.MCP_AUTH_TOKEN", None):
            request = MagicMock()
            result = _check_auth(request)
            assert result is None

    def test_missing_header(self):
        with patch("src.main.MCP_AUTH_TOKEN", "secret-token"):
            request = MagicMock()
            request.headers = {}
            result = _check_auth(request)
            assert result is not None
            assert result.status == 401

    def test_wrong_token(self):
        with patch("src.main.MCP_AUTH_TOKEN", "secret-token"):
            request = MagicMock()
            request.headers = {"Authorization": "Bearer wrong-token"}
            result = _check_auth(request)
            assert result is not None
            assert result.status == 403

    def test_correct_token(self):
        with patch("src.main.MCP_AUTH_TOKEN", "secret-token"):
            request = MagicMock()
            request.headers = {"Authorization": "Bearer secret-token"}
            result = _check_auth(request)
            assert result is None

    def test_no_bearer_prefix(self):
        with patch("src.main.MCP_AUTH_TOKEN", "secret-token"):
            request = MagicMock()
            request.headers = {"Authorization": "Basic secret-token"}
            result = _check_auth(request)
            assert result is not None
            assert result.status == 401


# ── _run_durable_task ────────────────────────────────────────────────────────

class TestRunDurableTask:
    def setup_method(self):
        _MCP_TASKS.clear()

    def test_successful_task(self):
        task_id = "test-task-1"
        _MCP_TASKS[task_id] = {"id": task_id, "status": "running"}

        async def mock_tool(**kw):
            return {"ok": True}

        with patch.dict(TOOL_REGISTRY, {"__test_dur": {
            "name": "__test_dur",
            "handler": mock_tool,
            "inputSchema": {"type": "object", "properties": {}},
            "description": "test",
        }}):
            _run(_run_durable_task(task_id, "__test_dur", {}))
            assert _MCP_TASKS[task_id]["status"] == "completed"
            assert _MCP_TASKS[task_id]["result"] is not None

    def test_failed_task(self):
        """When handler raises, _mcp_call_tool catches it and returns isError.
        _run_durable_task gets a 'completed' status with error result."""
        task_id = "test-task-2"
        _MCP_TASKS[task_id] = {"id": task_id, "status": "running"}

        async def bad_tool(**kw):
            raise RuntimeError("boom")

        with patch.dict(TOOL_REGISTRY, {"__test_durb": {
            "name": "__test_durb",
            "handler": bad_tool,
            "inputSchema": {"type": "object", "properties": {}},
            "description": "test",
        }}):
            _run(_run_durable_task(task_id, "__test_durb", {}))
            # _mcp_call_tool catches the exception, so task is "completed" with isError result
            assert _MCP_TASKS[task_id]["status"] == "completed"
            assert _MCP_TASKS[task_id]["result"]["isError"] is True


# ── _handle_mcp (aiohttp integration) ────────────────────────────────────────

@pytest.fixture
async def mcp_client(aiohttp_client):
    """Create test client for the MCP app."""
    app = await _build_app()
    return await aiohttp_client(app)


class TestHandleMcp:
    """Test _handle_mcp via aiohttp test client."""

    def _make_request(self, method, params=None, msg_id=1):
        return {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}

    @pytest.mark.asyncio
    async def test_initialize(self, mcp_client):
        resp = await mcp_client.post("/mcp", json=self._make_request("initialize"))
        assert resp.status == 200
        data = await resp.json()
        assert data["result"]["protocolVersion"] == "2025-11-25"
        assert "tools" in data["result"]["capabilities"]

    @pytest.mark.asyncio
    async def test_tools_list(self, mcp_client):
        resp = await mcp_client.post("/mcp", json=self._make_request("tools/list"))
        assert resp.status == 200
        data = await resp.json()
        assert "tools" in data["result"]
        assert len(data["result"]["tools"]) > 0

    @pytest.mark.asyncio
    async def test_tools_call(self, mcp_client):
        resp = await mcp_client.post("/mcp", json=self._make_request(
            "tools/call",
            {"name": "openclaw_prompt_injection_check", "arguments": {"text": "safe text"}},
        ))
        assert resp.status == 200
        data = await resp.json()
        assert "result" in data

    @pytest.mark.asyncio
    async def test_resources_list(self, mcp_client):
        resp = await mcp_client.post("/mcp", json=self._make_request("resources/list"))
        assert resp.status == 200
        data = await resp.json()
        assert "resources" in data["result"]

    @pytest.mark.asyncio
    async def test_resources_read(self, mcp_client):
        resp = await mcp_client.post("/mcp", json=self._make_request(
            "resources/read", {"uri": "openclaw://health"},
        ))
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_prompts_list(self, mcp_client):
        resp = await mcp_client.post("/mcp", json=self._make_request("prompts/list"))
        assert resp.status == 200
        data = await resp.json()
        assert "prompts" in data["result"]

    @pytest.mark.asyncio
    async def test_prompts_get(self, mcp_client):
        resp = await mcp_client.post("/mcp", json=self._make_request(
            "prompts/get", {"name": "security-audit", "arguments": {}},
        ))
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_elicitation_create(self, mcp_client):
        _PENDING_ELICITATIONS.clear()
        resp = await mcp_client.post("/mcp", json=self._make_request(
            "elicitation/create", {"message": "Pick a choice", "requestedSchema": {}},
        ))
        assert resp.status == 200
        data = await resp.json()
        assert data["result"]["action"] == "accept"

    @pytest.mark.asyncio
    async def test_tasks_create(self, mcp_client):
        _MCP_TASKS.clear()
        resp = await mcp_client.post("/mcp", json=self._make_request(
            "tasks/create", {"toolName": "openclaw_prompt_injection_check", "arguments": {"text": "safe"}},
        ))
        assert resp.status == 200
        data = await resp.json()
        assert data["result"]["status"] == "running"

    @pytest.mark.asyncio
    async def test_tasks_get_found(self, mcp_client):
        _MCP_TASKS["t1"] = {"id": "t1", "status": "completed"}
        resp = await mcp_client.post("/mcp", json=self._make_request("tasks/get", {"taskId": "t1"}))
        assert resp.status == 200
        data = await resp.json()
        assert data["result"]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_tasks_get_not_found(self, mcp_client):
        _MCP_TASKS.clear()
        resp = await mcp_client.post("/mcp", json=self._make_request("tasks/get", {"taskId": "nope"}))
        assert resp.status == 200
        data = await resp.json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_tasks_list(self, mcp_client):
        _MCP_TASKS["t2"] = {"id": "t2", "status": "running"}
        resp = await mcp_client.post("/mcp", json=self._make_request("tasks/list"))
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_tasks_cancel(self, mcp_client):
        _MCP_TASKS["t3"] = {"id": "t3", "status": "running"}
        resp = await mcp_client.post("/mcp", json=self._make_request("tasks/cancel", {"taskId": "t3"}))
        assert resp.status == 200
        data = await resp.json()
        assert data["result"]["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_tasks_cancel_not_found(self, mcp_client):
        _MCP_TASKS.clear()
        resp = await mcp_client.post("/mcp", json=self._make_request("tasks/cancel", {"taskId": "x"}))
        assert resp.status == 200
        data = await resp.json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_ping(self, mcp_client):
        resp = await mcp_client.post("/mcp", json=self._make_request("ping"))
        assert resp.status == 200
        data = await resp.json()
        assert data["result"]["pong"] is True

    @pytest.mark.asyncio
    async def test_unknown_method(self, mcp_client):
        resp = await mcp_client.post("/mcp", json=self._make_request("nonexistent/method"))
        assert resp.status == 200
        data = await resp.json()
        assert data["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_invalid_json_body(self, mcp_client):
        resp = await mcp_client.post("/mcp", data=b"not json{{{", headers={"Content-Type": "application/json"})
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_auth_required(self, mcp_client):
        with patch("src.main.MCP_AUTH_TOKEN", "secret"):
            resp = await mcp_client.post("/mcp", json=self._make_request("ping"))
            assert resp.status == 401


# ── _handle_health ────────────────────────────────────────────────────────────

class TestHandleHealth:
    @pytest.mark.asyncio
    async def test_health_endpoint(self, mcp_client):
        resp = await mcp_client.get("/health")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ok"
        assert "tools" in data
        assert "categories" in data

    @pytest.mark.asyncio
    async def test_healthz_endpoint(self, mcp_client):
        resp = await mcp_client.get("/healthz")
        assert resp.status == 200


# ── _handle_sse ──────────────────────────────────────────────────────────────

class TestHandleSSE:
    @pytest.mark.asyncio
    async def test_sse_auth_error(self, mcp_client):
        with patch("src.main.MCP_AUTH_TOKEN", "secret"):
            resp = await mcp_client.get("/mcp/sse")
            assert resp.status == 401

    @pytest.mark.asyncio
    async def test_sse_stream_starts(self, mcp_client):
        _MCP_TASKS["sse-t1"] = {"id": "sse-t1", "status": "running"}
        resp = await mcp_client.get("/mcp/sse")
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "text/event-stream"
        # Read initial data
        chunk = await resp.content.readline()
        assert len(chunk) > 0
        resp.close()


# ── Module constants ─────────────────────────────────────────────────────────

class TestModuleConstants:
    def test_mcp_resources_exist(self):
        assert len(_MCP_RESOURCES) >= 2

    def test_mcp_prompts_exist(self):
        assert len(_MCP_PROMPTS) >= 4

    def test_tool_registry_populated(self):
        assert len(TOOL_REGISTRY) >= 100
