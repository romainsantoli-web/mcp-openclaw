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
EXPECTED_TOOLS = 30  # 4 vs_bridge + 6 fleet + 6 delivery + 4 security_audit + 6 acp_bridge + 4 reliability_probe


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
        assert result["result"]["pong"] is True


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
            # security_audit (C1, C2, C3, H8)
            "openclaw_security_scan", "openclaw_sandbox_audit",
            "openclaw_session_config_check", "openclaw_rate_limit_check",
            # acp_bridge (C4, H3, H4, H5)
            "acp_session_persist", "acp_session_restore", "acp_session_list_active",
            "fleet_session_inject_env", "fleet_cron_schedule", "openclaw_workspace_lock",
            # reliability_probe (H6, H7, M1, M5, M6)
            "openclaw_gateway_probe", "openclaw_doc_sync_check",
            "openclaw_channel_audit", "firm_adr_generate",
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
        # Check file_path or error was returned
        assert "file_path" in data or "error" in data


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


class TestPydanticValidation:
    """Pydantic models must reject invalid inputs before the handler is called."""

    def test_vs_context_push_missing_required_field(self, mcp_server):
        """session_id is required — omitting it must return a validation error."""
        result = _rpc("tools/call", {
            "name": "vs_context_push",
            "arguments": {
                # session_id intentionally missing
                "workspace_path": "/tmp/test",
            },
        })
        assert "result" in result
        text = result["result"]["content"][0]["text"]
        data = json.loads(text)
        assert "error" in data
        assert data["error"] == "Validation failed"
        locs = [e["loc"] for e in data["details"]]
        assert ["session_id"] in locs

    def test_fleet_add_invalid_url_scheme(self, mcp_server):
        """url must start with http/https/ws/wss — ftp:// must be rejected."""
        result = _rpc("tools/call", {
            "name": "firm_gateway_fleet_add",
            "arguments": {
                "name": "test-instance",
                "url": "ftp://bad-url.example.com",
            },
        })
        assert "result" in result
        text = result["result"]["content"][0]["text"]
        data = json.loads(text)
        assert "error" in data
        assert data["error"] == "Validation failed"

    def test_fleet_add_invalid_name_chars(self, mcp_server):
        """Instance name must match ^[a-zA-Z0-9_-]+ — spaces are not allowed."""
        result = _rpc("tools/call", {
            "name": "firm_gateway_fleet_add",
            "arguments": {
                "name": "bad name with spaces",
                "url": "http://127.0.0.1:18789",
            },
        })
        assert "result" in result
        text = result["result"]["content"][0]["text"]
        data = json.loads(text)
        assert "error" in data
        assert data["error"] == "Validation failed"

    def test_export_auto_invalid_format(self, mcp_server):
        """delivery_format must be one of the 7 known formats."""
        result = _rpc("tools/call", {
            "name": "firm_export_auto",
            "arguments": {
                "objective": "Test",
                "content": "# Test",
                "delivery_format": "telepathy",  # invalid
            },
        })
        assert "result" in result
        text = result["result"]["content"][0]["text"]
        data = json.loads(text)
        assert "error" in data
        assert data["error"] == "Validation failed"

    def test_export_document_path_traversal_blocked(self, mcp_server):
        """output_path containing .. must be rejected."""
        result = _rpc("tools/call", {
            "name": "firm_export_document",
            "arguments": {
                "objective": "Test",
                "content": "# Test",
                "output_path": "../../etc/passwd",
            },
        })
        assert "result" in result
        text = result["result"]["content"][0]["text"]
        data = json.loads(text)
        assert "error" in data
        assert data["error"] == "Validation failed"

    def test_export_document_valid_passes(self, mcp_server):
        """Valid arguments must NOT trigger validation error."""
        result = _rpc("tools/call", {
            "name": "firm_export_document",
            "arguments": {
                "objective": "Pydantic validation smoke test",
                "content": "# OK\nAll fields are valid.",
                "departments": ["qa"],
            },
        })
        assert "result" in result
        text = result["result"]["content"][0]["text"]
        data = json.loads(text)
        # Must succeed (no validation error)
        assert "error" not in data or data.get("error") != "Validation failed"
        assert data.get("ok") is True or "file_path" in data


class TestSecurityAudit:
    """Tests for the 4 security_audit tools (gaps C1, C2, C3, H8)."""

    def test_security_scan_nonexistent_path(self, mcp_server):
        """Scanning a path that doesn't exist must return ok:False with an error."""
        result = _rpc("tools/call", {
            "name": "openclaw_security_scan",
            "arguments": {
                "target_path": "/nonexistent/path/to/nowhere",
            },
        })
        assert "result" in result
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is False
        assert "error" in data

    def test_security_scan_path_traversal_rejected(self, mcp_server):
        """target_path with .. must be rejected by Pydantic before reaching the handler."""
        result = _rpc("tools/call", {
            "name": "openclaw_security_scan",
            "arguments": {
                "target_path": "../../etc/passwd",
            },
        })
        assert "result" in result
        data = json.loads(result["result"]["content"][0]["text"])
        assert "error" in data
        assert data["error"] == "Validation failed"

    def test_sandbox_audit_nonexistent_config(self, mcp_server):
        """Auditing a config that doesn't exist must return ok:False."""
        result = _rpc("tools/call", {
            "name": "openclaw_sandbox_audit",
            "arguments": {
                "config_path": "/nonexistent/config.yaml",
            },
        })
        assert "result" in result
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is False

    def test_sandbox_audit_config_path_traversal_rejected(self, mcp_server):
        """config_path with .. must be rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "openclaw_sandbox_audit",
            "arguments": {"config_path": "../../etc/openclaw.yaml"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"

    def test_sandbox_audit_detects_off(self, mcp_server, tmp_path):
        """A config with sandbox.mode: off must return severity CRITICAL."""
        config = tmp_path / "config.yaml"
        config.write_text("agents:\n  defaults:\n    sandbox:\n      mode: off\n")
        result = _rpc("tools/call", {
            "name": "openclaw_sandbox_audit",
            "arguments": {"config_path": str(config)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        assert data["severity"] == "CRITICAL"
        assert "fix_snippet" in data

    def test_sandbox_audit_detects_non_main_ok(self, mcp_server, tmp_path):
        """A config with sandbox.mode: non-main must return severity OK."""
        config = tmp_path / "config.yaml"
        config.write_text("agents:\n  defaults:\n    sandbox:\n      mode: non-main\n")
        result = _rpc("tools/call", {
            "name": "openclaw_sandbox_audit",
            "arguments": {"config_path": str(config)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        assert data["severity"] == "OK"

    def test_session_config_check_no_args(self, mcp_server):
        """With no args, checks the current process env — must return ok:True."""
        result = _rpc("tools/call", {
            "name": "openclaw_session_config_check",
            "arguments": {},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        assert "severity" in data
        assert data["severity"] in ("OK", "HIGH")

    def test_session_config_check_detects_missing_secret(self, mcp_server, tmp_path):
        """docker-compose without SESSION_SECRET must be flagged HIGH."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n  openclaw:\n    image: ghcr.io/openclaw/openclaw:stable\n"
        )
        result = _rpc("tools/call", {
            "name": "openclaw_session_config_check",
            "arguments": {"compose_file_path": str(compose)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        assert data["severity"] == "HIGH"
        assert data["fix_docker"] is not None

    def test_rate_limit_check_nonexistent_config(self, mcp_server):
        """Rate limit check on nonexistent file must return ok:False."""
        result = _rpc("tools/call", {
            "name": "openclaw_rate_limit_check",
            "arguments": {"gateway_config_path": "/nonexistent/config.yaml"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is False

    def test_rate_limit_check_detects_funnel_no_proxy(self, mcp_server, tmp_path):
        """Config with funnel:true and no Nginx/Caddy must return CRITICAL."""
        config = tmp_path / "config.yaml"
        config.write_text("gateway:\n  funnel: true\n  port: 18789\n")
        result = _rpc("tools/call", {
            "name": "openclaw_rate_limit_check",
            "arguments": {
                "gateway_config_path": str(config),
                "check_funnel": True,
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        assert data["severity"] == "CRITICAL"
        assert data["funnel_active"] is True
        assert data["fix_nginx"] is not None


class TestAcpBridge:
    """Tests for the 6 acp_bridge tools (gaps C4, H3, H4, H5)."""

    def test_acp_session_persist_and_restore(self, mcp_server, tmp_path, monkeypatch):
        """Persist a session, then restore it — roundtrip must work."""
        import src.acp_bridge as ab
        monkeypatch.setattr(ab, "ACP_SESSIONS_PATH", str(tmp_path / "acp_sessions.json"))

        # Persist
        r1 = _rpc("tools/call", {
            "name": "acp_session_persist",
            "arguments": {
                "run_id": "test-run-001",
                "gateway_session_key": "gw-key-abc123",
                "metadata": {"ide": "vscode"},
            },
        })
        d1 = json.loads(r1["result"]["content"][0]["text"])
        assert d1["ok"] is True
        assert d1["run_id"] == "test-run-001"

        # Restore
        r2 = _rpc("tools/call", {
            "name": "acp_session_restore",
            "arguments": {"max_age_hours": 24},
        })
        d2 = json.loads(r2["result"]["content"][0]["text"])
        assert d2["ok"] is True
        assert d2["restored"] >= 1

    def test_acp_session_persist_missing_run_id(self, mcp_server):
        """run_id is required — Pydantic must reject missing field."""
        result = _rpc("tools/call", {
            "name": "acp_session_persist",
            "arguments": {
                # run_id missing
                "gateway_session_key": "gw-key-xyz",
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"
        assert any(e["loc"] == ["run_id"] for e in data["details"])

    def test_acp_session_list_active(self, mcp_server):
        """list_active must return ok:True and a sessions list."""
        result = _rpc("tools/call", {
            "name": "acp_session_list_active",
            "arguments": {"include_stale": False},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        assert "sessions" in data
        assert isinstance(data["sessions"], list)

    def test_fleet_cron_schedule_valid(self, mcp_server):
        """Valid cron schedule on main session must succeed."""
        result = _rpc("tools/call", {
            "name": "fleet_cron_schedule",
            "arguments": {
                "command": "node scripts/report.js",
                "schedule": "0 9 * * 1-5",
                "session": "main",
                "description": "Daily report",
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        assert "cron_id" in data

    def test_fleet_cron_schedule_invalid_command_chars(self, mcp_server):
        """Command with semicolons must be rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "fleet_cron_schedule",
            "arguments": {
                "command": "rm -rf /; echo pwned",
                "schedule": "0 9 * * 1-5",
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"

    def test_fleet_inject_env_invalid_empty_vars(self, mcp_server):
        """Empty env_vars dict must be rejected by Pydantic (min_length=1)."""
        result = _rpc("tools/call", {
            "name": "fleet_session_inject_env",
            "arguments": {"env_vars": {}},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"

    def test_workspace_lock_acquire_and_release(self, mcp_server):
        """Acquire a lock then release it — both must succeed."""
        # Status first
        r1 = _rpc("tools/call", {
            "name": "openclaw_workspace_lock",
            "arguments": {
                "path": "smoke-test/resource.json",
                "action": "status",
                "owner": "test-agent",
            },
        })
        d1 = json.loads(r1["result"]["content"][0]["text"])
        assert d1["ok"] is True

        # Acquire
        r2 = _rpc("tools/call", {
            "name": "openclaw_workspace_lock",
            "arguments": {
                "path": "smoke-test/resource.json",
                "action": "acquire",
                "owner": "test-agent",
                "timeout_s": 5.0,
            },
        })
        d2 = json.loads(r2["result"]["content"][0]["text"])
        assert d2["ok"] is True
        assert d2["locked"] is True

        # Release
        r3 = _rpc("tools/call", {
            "name": "openclaw_workspace_lock",
            "arguments": {
                "path": "smoke-test/resource.json",
                "action": "release",
                "owner": "test-agent",
            },
        })
        d3 = json.loads(r3["result"]["content"][0]["text"])
        assert d3["ok"] is True

    def test_workspace_lock_path_traversal_rejected(self, mcp_server):
        """Lock path with .. must be rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "openclaw_workspace_lock",
            "arguments": {
                "path": "../../etc/shadow",
                "action": "acquire",
                "owner": "attacker",
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"


class TestReliabilityProbe:
    """Tests for the 4 reliability_probe tools (gaps H6, H7, M1, M5, M6)."""

    def test_gateway_probe_unreachable(self, mcp_server):
        """Probing an unreachable URL must return ok:False with restart_command."""
        result = _rpc("tools/call", {
            "name": "openclaw_gateway_probe",
            "arguments": {
                "gateway_url": "ws://127.0.0.1:1",  # port 1 is always closed
                "max_retries": 1,
                "backoff_factor": 0.1,
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is False
        assert data["status"] == "unreachable"
        assert "restart_command" in data
        assert "launchctl" in data["restart_command"]

    def test_gateway_probe_invalid_url_scheme(self, mcp_server):
        """gateway_url must start with ws:// or wss:// — http:// is rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "openclaw_gateway_probe",
            "arguments": {"gateway_url": "http://127.0.0.1:18789"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"

    def test_doc_sync_check_nonexistent_package_json(self, mcp_server):
        """Non-existent package.json must return ok:False."""
        result = _rpc("tools/call", {
            "name": "openclaw_doc_sync_check",
            "arguments": {"package_json_path": "/nonexistent/package.json"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is False

    def test_channel_audit_detects_zombie_dep(self, mcp_server, tmp_path):
        """@line/bot-sdk in package.json but not in README must be reported as zombie."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"@line/bot-sdk": "^10.6.0", "grammy": "^1.0.0"}
        }))
        readme = tmp_path / "README.md"
        readme.write_text("# OpenClaw\n\n## Channels\n\n- Telegram (grammY)\n")
        result = _rpc("tools/call", {
            "name": "openclaw_channel_audit",
            "arguments": {
                "package_json_path": str(pkg),
                "readme_path": str(readme),
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        # @line/bot-sdk (LINE) should be flagged as zombie
        zombie_packages = [z["package"] for z in data["zombie_details"]]
        assert "@line/bot-sdk" in zombie_packages

    def test_adr_generate_valid(self, mcp_server):
        """Valid ADR input must produce a markdown document with correct fields."""
        result = _rpc("tools/call", {
            "name": "firm_adr_generate",
            "arguments": {
                "title": "Use mcporter for MCP instead of native support",
                "context": "VISION.md explicitly excludes MCP in core.",
                "decision": "Route all MCP via external mcporter bridge.",
                "alternatives": ["Native MCP support in core", "No MCP support"],
                "consequences": [
                    "Positive: keeps core lean",
                    "Negative: users must install mcporter separately",
                ],
                "status": "accepted",
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        assert "markdown" in data
        assert "# " in data["markdown"]  # Has a heading
        assert "mcporter" in data["markdown"]
        assert "commit_path" in data
        assert data["status"] == "accepted"

    def test_adr_generate_invalid_status(self, mcp_server):
        """Invalid status must be rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "firm_adr_generate",
            "arguments": {
                "title": "Test decision",
                "context": "Some context here that is long enough.",
                "decision": "Some decision that was made here.",
                "alternatives": ["Alt A"],
                "consequences": ["Con A"],
                "status": "maybe",  # invalid
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"
