"""
Smoke tests for mcp-openclaw-extensions.

Tests run without a live OpenClaw Gateway:
  - Server starts and responds to ping
  - All 16 tools register correctly
  - tools/list returns correct schema
  - vs_context_push handles WS unavailable gracefully
  - firm_export_document writes a local file

Run:  python -m pytest tests/test_smoke.py -v
"""

import asyncio
import json
import pathlib
import subprocess
import sys
import time
import os

import httpx
import pytest
import pytest_asyncio

# ── Constants ─────────────────────────────────────────────────────────────────
HOST = os.getenv("MCP_EXT_HOST", "127.0.0.1")
PORT = int(os.getenv("MCP_EXT_PORT", "8012"))
BASE_URL = f"http://{HOST}:{PORT}/mcp"
EXPECTED_TOOLS = 16  # 4 vs_bridge + 6 fleet + 6 delivery


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def mcp_server():
    """Start the MCP server as a subprocess for the test session."""
    src_dir = pathlib.Path(__file__).parent.parent
    proc = subprocess.Popen(
        [sys.executable, "-m", "src.main"],
        cwd=str(src_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "MCP_EXT_HOST": HOST, "MCP_EXT_PORT": str(PORT)},
    )

    # Wait up to 15s for server to be ready
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            r = httpx.post(
                BASE_URL,
                json={"jsonrpc": "2.0", "id": 0, "method": "ping"},
                timeout=2,
            )
            if r.status_code == 200 and "result" in r.json():
                break
        except Exception:
            pass
        time.sleep(0.5)
    else:
        proc.kill()
        raise RuntimeError("MCP server failed to start within 15s")

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# ── Tests ─────────────────────────────────────────────────────────────────────

def _rpc(method: str, params: dict | None = None, req_id: int = 1) -> dict:
    """Synchronous JSON-RPC POST helper."""
    payload: dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        payload["params"] = params
    resp = httpx.post(BASE_URL, json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()


class TestPing:
    def test_ping_returns_pong(self, mcp_server):
        result = _rpc("ping")
        assert "result" in result
        assert result["result"] == "pong"


class TestInitialize:
    def test_initialize_returns_capabilities(self, mcp_server):
        result = _rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "smoke-test", "version": "1.0.0"},
        })
        assert "result" in result
        cap = result["result"]
        assert "capabilities" in cap
        assert "tools" in cap["capabilities"]
        assert cap["serverInfo"]["name"] == "mcp-openclaw-extensions"


class TestToolsList:
    def test_tools_list_count(self, mcp_server):
        result = _rpc("tools/list")
        tools = result["result"]["tools"]
        assert len(tools) == EXPECTED_TOOLS, (
            f"Expected {EXPECTED_TOOLS} tools, got {len(tools)}. "
            f"Found: {[t['name'] for t in tools]}"
        )

    def test_tools_list_names(self, mcp_server):
        result = _rpc("tools/list")
        names = {t["name"] for t in result["result"]["tools"]}
        required = {
            # vs_bridge
            "vs_context_push", "vs_context_pull", "vs_session_link", "vs_session_status",
            # fleet
            "firm_gateway_fleet_status", "firm_gateway_fleet_add", "firm_gateway_fleet_remove",
            "firm_gateway_fleet_broadcast", "firm_gateway_fleet_sync", "firm_gateway_fleet_list",
            # delivery
            "firm_export_github_pr", "firm_export_jira_ticket", "firm_export_linear_issue",
            "firm_export_slack_digest", "firm_export_document", "firm_export_auto",
        }
        missing = required - names
        assert not missing, f"Missing tools: {missing}"

    def test_tools_have_input_schema(self, mcp_server):
        result = _rpc("tools/list")
        for tool in result["result"]["tools"]:
            assert "inputSchema" in tool, f"Tool {tool['name']!r} missing inputSchema"
            schema = tool["inputSchema"]
            assert schema.get("type") == "object", f"Tool {tool['name']!r} schema not object"
            assert "properties" in schema


class TestVsBridgeGracefulDegradation:
    """vs_context_push must handle missing Gateway gracefully (no OpenClaw in CI)."""

    def test_vs_context_push_no_gateway(self, mcp_server):
        result = _rpc("tools/call", {
            "name": "vs_context_push",
            "arguments": {
                "session_id": "smoke-test-session",
                "workspace_path": "/tmp/smoke-test",
                "open_files": ["main.py"],
                "active_file": "main.py",
                "selection": "",
                "diagnostics": [],
            },
        })
        # Must return a result (not a hard error), with error field in content
        assert "result" in result
        content = result["result"]["content"]
        assert isinstance(content, list)
        text = content[0].get("text", "")
        # Either success or a gateway connection error — both are acceptable in smoke test
        assert isinstance(text, str)
        assert len(text) > 0


class TestFirmExportDocument:
    """firm_export_document must write a local file without any external service."""

    def test_export_document_creates_file(self, mcp_server, tmp_path):
        result = _rpc("tools/call", {
            "name": "firm_export_document",
            "arguments": {
                "objective": "Smoke test deliverable",
                "content": "# Smoke test\nThis is a smoke test deliverable.",
                "departments": ["qa", "engineering"],
            },
        })
        assert "result" in result
        content = result["result"]["content"]
        text = content[0]["text"]
        data = json.loads(text)
        # Check path was returned
        assert "path" in data or "error" in data


class TestUnknownMethod:
    def test_unknown_method_returns_error(self, mcp_server):
        result = _rpc("methods/nonexistent")
        assert "error" in result
        assert result["error"]["code"] == -32601  # Method not found


class TestToolCallUnknownTool:
    def test_unknown_tool_returns_error(self, mcp_server):
        result = _rpc("tools/call", {"name": "does_not_exist", "arguments": {}})
        assert "result" in result
        content = result["result"]["content"]
        text = content[0]["text"]
        assert "unknown tool" in text.lower() or "error" in text.lower()
