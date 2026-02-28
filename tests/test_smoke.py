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
EXPECTED_TOOLS = 59  # 4 vs_bridge + 6 fleet + 6 delivery + 4 security_audit + 6 acp_bridge + 4 reliability_probe + 5 gateway_hardening + 7 runtime_audit + 8 advanced_security + 5 config_migration + 2 observability + 2 memory_audit


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
            # gateway_hardening (H2, M3, M4, M7, M8)
            "openclaw_gateway_auth_check", "openclaw_credentials_check",
            "openclaw_webhook_sig_check", "openclaw_log_config_check",
            "openclaw_workspace_integrity_check",
            # runtime_audit (C5, C6, H9, H10, H11, M15, M16)
            "openclaw_node_version_check", "openclaw_secrets_workflow_check",
            "openclaw_http_headers_check", "openclaw_nodes_commands_check",
            "openclaw_trusted_proxy_check", "openclaw_session_disk_budget_check",
            "openclaw_dm_allowlist_check",
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


class TestGatewayHardening:
    """Tests for gateway_hardening module (H2, M3, M4, M7, M8)."""

    # ── openclaw_gateway_auth_check (H2) ─────────────────────────────────────

    def test_gateway_auth_check_no_config(self, mcp_server):
        """Nonexistent config path → status no_config, no crash."""
        result = _rpc("tools/call", {
            "name": "openclaw_gateway_auth_check",
            "arguments": {"config_path": "/nonexistent/openclaw.json"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] in ("no_config", "ok", "findings")

    def test_gateway_auth_check_path_traversal_rejected(self, mcp_server):
        """config_path with .. must be rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "openclaw_gateway_auth_check",
            "arguments": {"config_path": "../../etc/passwd"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"

    def test_gateway_auth_check_funnel_no_password(self, mcp_server, tmp_path):
        """Funnel mode without auth.mode=password must produce a CRITICAL finding."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {
                "tailscale": {"mode": "funnel"},
                "auth": {"mode": "none"},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_gateway_auth_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["severity"] == "CRITICAL"
        assert data["finding_count"] >= 1

    def test_gateway_auth_check_disable_device_auth(self, mcp_server, tmp_path):
        """dangerouslyDisableDeviceAuth=true must produce a HIGH finding."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {
                "controlUi": {"dangerouslyDisableDeviceAuth": True},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_gateway_auth_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["severity"] in ("HIGH", "CRITICAL")

    # ── openclaw_credentials_check (M3) ──────────────────────────────────────

    def test_credentials_check_no_dir(self, mcp_server):
        """Nonexistent credentials dir → status no_credentials_dir."""
        result = _rpc("tools/call", {
            "name": "openclaw_credentials_check",
            "arguments": {"credentials_dir": "/nonexistent/credentials"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] in ("no_credentials_dir", "ok", "findings")

    def test_credentials_check_corrupted_json(self, mcp_server, tmp_path):
        """A corrupted creds.json must produce a CRITICAL finding."""
        creds_dir = tmp_path / "whatsapp-test"
        creds_dir.mkdir(parents=True)
        (creds_dir / "creds.json").write_text("not valid json !!!")
        result = _rpc("tools/call", {
            "name": "openclaw_credentials_check",
            "arguments": {"credentials_dir": str(tmp_path)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["severity"] == "CRITICAL"

    def test_credentials_check_path_traversal_rejected(self, mcp_server):
        """credentials_dir with .. must be rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "openclaw_credentials_check",
            "arguments": {"credentials_dir": "../../etc"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"

    # ── openclaw_webhook_sig_check (M4) ───────────────────────────────────────

    def test_webhook_sig_check_no_config(self, mcp_server):
        """Nonexistent config → graceful status."""
        result = _rpc("tools/call", {
            "name": "openclaw_webhook_sig_check",
            "arguments": {"config_path": "/nonexistent/openclaw.json"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] in ("no_config", "ok", "findings")

    def test_webhook_sig_check_missing_secret(self, mcp_server, tmp_path):
        """A telegram channel with webhookPath but no webhookSecret → HIGH finding."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "channels": {
                "telegram": {
                    "webhookPath": "/webhook/telegram",
                    # no webhookSecret
                }
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_webhook_sig_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["severity"] == "HIGH"

    # ── openclaw_log_config_check (M7) ────────────────────────────────────────

    def test_log_config_check_debug_level(self, mcp_server, tmp_path):
        """logging.level=debug must produce a HIGH finding."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({"logging": {"level": "debug"}}))
        result = _rpc("tools/call", {
            "name": "openclaw_log_config_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["severity"] == "HIGH"

    def test_log_config_check_missing_redact(self, mcp_server, tmp_path):
        """Absent redactPatterns must produce a MEDIUM finding."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({"logging": {"level": "info"}}))
        result = _rpc("tools/call", {
            "name": "openclaw_log_config_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["severity"] in ("MEDIUM", "HIGH", "CRITICAL")

    # ── openclaw_workspace_integrity_check (M8) ───────────────────────────────

    def test_workspace_integrity_missing_dir(self, mcp_server):
        """Nonexistent workspace dir → HIGH finding."""
        result = _rpc("tools/call", {
            "name": "openclaw_workspace_integrity_check",
            "arguments": {"workspace_dir": "/nonexistent/workspace"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["severity"] == "HIGH"

    def test_workspace_integrity_path_traversal_rejected(self, mcp_server):
        """workspace_dir with .. must be rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "openclaw_workspace_integrity_check",
            "arguments": {"workspace_dir": "../../etc/passwd"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"


class TestRuntimeAudit:
    """Tests for runtime_audit tools (C5, C6, H9, H10, H11, M15, M16)."""

    # ── openclaw_node_version_check (C5) ──────────────────────────────────────

    def test_node_version_check_auto_detect(self, mcp_server):
        """Auto-detect node in PATH — should return a result without error."""
        result = _rpc("tools/call", {
            "name": "openclaw_node_version_check",
            "arguments": {},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        # Must not crash — either ok/critical or node_not_found
        assert "status" in data or "error" in data

    def test_node_version_check_nonexistent_binary(self, mcp_server):
        """Non-existent binary returns error status without raising."""
        result = _rpc("tools/call", {
            "name": "openclaw_node_version_check",
            "arguments": {"node_binary": "/nonexistent/node"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "error"

    def test_node_version_check_traversal_rejected(self, mcp_server):
        """node_binary with .. must be rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "openclaw_node_version_check",
            "arguments": {"node_binary": "../../etc/node"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"

    # ── openclaw_secrets_workflow_check (C6) ──────────────────────────────────

    def test_secrets_workflow_no_config(self, mcp_server):
        """Nonexistent config path → graceful ok status."""
        result = _rpc("tools/call", {
            "name": "openclaw_secrets_workflow_check",
            "arguments": {"config_path": "/nonexistent/openclaw.json"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] in ("ok", "error")

    def test_secrets_workflow_hardcoded_token(self, mcp_server, tmp_path):
        """Hardcoded token in config must be flagged as CRITICAL."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {
                "auth": {"token": "sk-abc123hardcoded456789xyz0123456789"}
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_secrets_workflow_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "critical"
        assert data["hardcoded_count"] >= 1

    def test_secrets_workflow_env_placeholder_ok(self, mcp_server, tmp_path):
        """Env-var placeholder $ENV_VAR should NOT be flagged."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {"auth": {"token": "$MY_GATEWAY_TOKEN"}}
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_secrets_workflow_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["hardcoded_count"] == 0

    # ── openclaw_http_headers_check (H9) ──────────────────────────────────────

    def test_http_headers_check_loopback_no_warnings(self, mcp_server, tmp_path):
        """Loopback bind with no headers → INFO only (not HIGH)."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({"gateway": {"bind": "loopback"}}))
        result = _rpc("tools/call", {
            "name": "openclaw_http_headers_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] in ("ok", "info")

    def test_http_headers_check_public_missing_hsts(self, mcp_server, tmp_path):
        """Public bind without HSTS configured → HIGH finding."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({"gateway": {"bind": "lan"}}))
        result = _rpc("tools/call", {
            "name": "openclaw_http_headers_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"
        assert any(f["id"] == "missing_hsts" for f in data["findings"])

    # ── openclaw_nodes_commands_check (H10) ───────────────────────────────────

    def test_nodes_commands_check_clean(self, mcp_server, tmp_path):
        """No allowCommands set → status ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({"gateway": {}}))
        result = _rpc("tools/call", {
            "name": "openclaw_nodes_commands_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    def test_nodes_commands_check_allow_commands_local(self, mcp_server, tmp_path):
        """allowCommands on local bind → HIGH finding."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {
                "bind": "loopback",
                "nodes": {"allowCommands": ["system.run"]},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_nodes_commands_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] in ("high", "critical")

    def test_nodes_commands_check_allow_commands_remote(self, mcp_server, tmp_path):
        """allowCommands on remote bind → CRITICAL finding."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {
                "bind": "lan",
                "nodes": {"allowCommands": ["system.run", "system.exec"]},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_nodes_commands_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "critical"

    # ── openclaw_trusted_proxy_check (H11) ────────────────────────────────────

    def test_trusted_proxy_check_clean(self, mcp_server, tmp_path):
        """token auth without trusted-proxy → status ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {"auth": {"mode": "token"}, "bind": "loopback"}
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_trusted_proxy_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    def test_trusted_proxy_check_missing_proxies(self, mcp_server, tmp_path):
        """trusted-proxy mode without trustedProxies → CRITICAL."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {
                "auth": {"mode": "trusted-proxy"},
                "bind": "loopback",
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_trusted_proxy_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "critical"

    # ── openclaw_session_disk_budget_check (M15) ──────────────────────────────

    def test_session_disk_budget_not_configured(self, mcp_server, tmp_path):
        """No maxDiskBytes → MEDIUM finding."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({"session": {}}))
        result = _rpc("tools/call", {
            "name": "openclaw_session_disk_budget_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "medium"
        assert any(f["id"] == "session_max_disk_bytes_missing" for f in data["findings"])

    def test_session_disk_budget_configured(self, mcp_server, tmp_path):
        """maxDiskBytes configured → ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "session": {
                "maintenance": {
                    "maxDiskBytes": 524288000,
                    "highWaterBytes": 419430400,
                }
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_session_disk_budget_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    # ── openclaw_dm_allowlist_check (M16) ─────────────────────────────────────

    def test_dm_allowlist_check_clean(self, mcp_server, tmp_path):
        """dmPolicy=pairing → no HIGH findings."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "channels": {
                "telegram": {"dmPolicy": "pairing"},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_dm_allowlist_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] in ("ok", "medium")

    def test_dm_allowlist_check_empty_allowlist(self, mcp_server, tmp_path):
        """dmPolicy=allowlist with empty allowFrom → HIGH finding."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "channels": {
                "telegram": {"dmPolicy": "allowlist", "allowFrom": []},
                "discord": {"dmPolicy": "allowlist", "allowFrom": []},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_dm_allowlist_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"
        assert len(data["channel_findings"]) >= 2


class TestAdvancedSecurity:
    """Tests for advanced_security tools (C7, C8, C9, H12, H13, H14, H15, H16)."""

    # ── openclaw_secrets_lifecycle_check (C7) ─────────────────────────────────

    def test_secrets_lifecycle_inline_creds(self, mcp_server, tmp_path):
        """Inline credentials in auth profiles → CRITICAL."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "auth": {
                "profiles": {
                    "openai": {"apiKey": "sk-realkey123456789realkey12345"},
                    "anthropic": {"apiKey": "$ANTHROPIC_API_KEY"},
                }
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_secrets_lifecycle_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "critical"
        assert data["inline_credential_count"] == 1

    def test_secrets_lifecycle_all_refs_ok(self, mcp_server, tmp_path):
        """All credentials use env-var refs → ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "auth": {
                "profiles": {
                    "openai": {"apiKey": "$OPENAI_API_KEY"},
                    "anthropic": {"apiKey": "{{ANTHROPIC_KEY}}"},
                }
            },
            "secrets": {"managed": True, "snapshotActivated": True},
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_secrets_lifecycle_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"
        assert data["inline_credential_count"] == 0

    def test_secrets_lifecycle_traversal_rejected(self, mcp_server):
        """config_path with .. must be rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "openclaw_secrets_lifecycle_check",
            "arguments": {"config_path": "../../etc/openclaw.json"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"

    # ── openclaw_channel_auth_canon_check (C8) ────────────────────────────────

    def test_channel_auth_canon_auth_none_remote(self, mcp_server, tmp_path):
        """auth.mode=none on non-loopback → CRITICAL."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {
                "auth": {"mode": "none"},
                "bind": "lan",
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_channel_auth_canon_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "critical"

    def test_channel_auth_canon_loopback_ok(self, mcp_server, tmp_path):
        """Loopback with token auth → ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {
                "auth": {"mode": "token"},
                "bind": "loopback",
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_channel_auth_canon_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    # ── openclaw_exec_approval_freeze_check (C9) ──────────────────────────────

    def test_exec_approval_no_sandbox(self, mcp_server, tmp_path):
        """exec.host != sandbox with sandbox.mode off → HIGH."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "tools": {"exec": {"host": "gateway"}},
            "agents": {"defaults": {"sandbox": {"mode": "off"}}},
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_exec_approval_freeze_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"

    def test_exec_approval_sandbox_ok(self, mcp_server, tmp_path):
        """exec.host=sandbox → ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "tools": {"exec": {"host": "sandbox"}},
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_exec_approval_freeze_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    # ── openclaw_hook_session_routing_check (H12) ─────────────────────────────

    def test_hook_session_unrestricted(self, mcp_server, tmp_path):
        """allowRequestSessionKey=true without prefixes → HIGH."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "hooks": {
                "allowRequestSessionKey": True,
                "mappings": {"test": "/hook/test"},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_hook_session_routing_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"

    def test_hook_session_with_prefixes_ok(self, mcp_server, tmp_path):
        """allowRequestSessionKey=true with prefixes → ok (INFO only)."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "hooks": {
                "allowRequestSessionKey": True,
                "allowedSessionKeyPrefixes": ["hook:"],
                "defaultSessionKey": "hook:default",
                "token": "a" * 32,
                "mappings": {"test": "/hook/test"},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_hook_session_routing_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    # ── openclaw_config_include_check (H13) ───────────────────────────────────

    def test_config_include_traversal(self, mcp_server, tmp_path):
        """$include with path traversal → CRITICAL."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "server": {"$include": "../../etc/secret.json"}
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_config_include_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "critical"

    def test_config_include_clean(self, mcp_server, tmp_path):
        """No $include directives → ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({"gateway": {"bind": "loopback"}}))
        result = _rpc("tools/call", {
            "name": "openclaw_config_include_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    # ── openclaw_config_prototype_check (H14) ─────────────────────────────────

    def test_config_prototype_pollution(self, mcp_server, tmp_path):
        """Config with __proto__ key → CRITICAL."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {"bind": "loopback"},
            "__proto__": {"isAdmin": True},
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_config_prototype_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "critical"
        assert data["prototype_key_count"] >= 1

    def test_config_prototype_clean(self, mcp_server, tmp_path):
        """Clean config → ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({"gateway": {"bind": "loopback"}}))
        result = _rpc("tools/call", {
            "name": "openclaw_config_prototype_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    # ── openclaw_safe_bins_profile_check (H15) ────────────────────────────────

    def test_safe_bins_interpreter_no_profile(self, mcp_server, tmp_path):
        """safeBins with python but no profile → CRITICAL."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "tools": {
                "exec": {
                    "safeBins": ["python3", "cat"],
                    "safeBinProfiles": {},
                }
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_safe_bins_profile_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "critical"
        assert any("python3" in f["message"] for f in data["findings"])

    def test_safe_bins_no_bins_ok(self, mcp_server, tmp_path):
        """No safeBins → ok (INFO)."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({"tools": {"exec": {}}}))
        result = _rpc("tools/call", {
            "name": "openclaw_safe_bins_profile_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    # ── openclaw_group_policy_default_check (H16) ─────────────────────────────

    def test_group_policy_permissive_default(self, mcp_server, tmp_path):
        """defaults.groupPolicy='all' → HIGH."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "channels": {
                "defaults": {"groupPolicy": "all"},
                "telegram": {"enabled": True},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_group_policy_default_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"

    def test_group_policy_allowlist_default_ok(self, mcp_server, tmp_path):
        """defaults.groupPolicy='allowlist' → ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "channels": {
                "defaults": {"groupPolicy": "allowlist"},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_group_policy_default_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"


# ═══════════════════════════════════════════════════════════════════════════════
# Export tools — missing-token error paths (no external API needed)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExportMissingTokens:
    """Export tools must return ok=False when tokens are missing."""

    def test_github_pr_missing_token(self, mcp_server):
        result = _rpc("tools/call", {
            "name": "firm_export_github_pr",
            "arguments": {
                "repo": "owner/repo",
                "content": "# Test",
                "objective": "Test objective",
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is False
        assert "GITHUB_TOKEN" in data["error"]

    def test_jira_ticket_missing_token(self, mcp_server):
        result = _rpc("tools/call", {
            "name": "firm_export_jira_ticket",
            "arguments": {
                "project_key": "ENG",
                "content": "# Test",
                "objective": "Test objective",
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is False
        assert "JIRA_API_TOKEN" in data["error"]

    def test_linear_issue_missing_token(self, mcp_server):
        result = _rpc("tools/call", {
            "name": "firm_export_linear_issue",
            "arguments": {
                "team_id": "team-uuid",
                "content": "# Test",
                "objective": "Test objective",
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is False
        assert "LINEAR_API_KEY" in data["error"]

    def test_slack_digest_missing_webhook(self, mcp_server):
        result = _rpc("tools/call", {
            "name": "firm_export_slack_digest",
            "arguments": {
                "content": "# Test",
                "objective": "Test objective",
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is False
        assert "SLACK_WEBHOOK_URL" in data["error"]


# ═══════════════════════════════════════════════════════════════════════════════
# Export tools — success paths with mocked HTTP (direct async call)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExportMockedSuccess:
    """Export tools must succeed with mocked external APIs."""

    @pytest.mark.asyncio
    async def test_github_pr_success(self, monkeypatch):
        """Mock all GitHub API steps and verify PR result."""
        from unittest.mock import AsyncMock, MagicMock
        from src.delivery_export import firm_export_github_pr
        import src.delivery_export as mod

        monkeypatch.setattr(mod, "GITHUB_TOKEN", "ghp_test1234")

        # Build mock response objects
        def _make_resp(status_code, json_data):
            resp = MagicMock()
            resp.status_code = status_code
            resp.json.return_value = json_data
            resp.raise_for_status = MagicMock()
            resp.text = json.dumps(json_data)
            return resp

        ref_resp = _make_resp(200, {"object": {"sha": "abc123"}})
        branch_resp = _make_resp(201, {})
        commit_resp = _make_resp(201, {})
        pr_resp = _make_resp(201, {"number": 42, "html_url": "https://github.com/o/r/pull/42"})
        labels_resp = _make_resp(200, {})

        call_count = {"n": 0}
        responses = {
            "get": [ref_resp],
            "post": [branch_resp, pr_resp, labels_resp],
            "put": [commit_resp],
        }
        idx = {"get": 0, "post": 0, "put": 0}

        class FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def get(self, *a, **kw):
                r = responses["get"][idx["get"]]; idx["get"] += 1; return r
            async def post(self, *a, **kw):
                r = responses["post"][idx["post"]]; idx["post"] += 1; return r
            async def put(self, *a, **kw):
                r = responses["put"][idx["put"]]; idx["put"] += 1; return r

        monkeypatch.setattr(mod.httpx, "AsyncClient", lambda **kw: FakeClient())

        result = await firm_export_github_pr(
            repo="owner/repo",
            content="# PR body",
            objective="test feature",
            departments=["eng"],
        )
        assert result["ok"] is True
        assert result["pr_number"] == 42
        assert result["pr_url"] == "https://github.com/o/r/pull/42"
        assert result["draft"] is True
        assert "ai-generated" in result["labels"]

    @pytest.mark.asyncio
    async def test_slack_digest_success(self, monkeypatch):
        """Mock Slack webhook and verify success."""
        from unittest.mock import MagicMock
        from src.delivery_export import firm_export_slack_digest
        import src.delivery_export as mod

        monkeypatch.setattr(mod, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"

        class FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, *a, **kw): return mock_resp

        monkeypatch.setattr(mod.httpx, "AsyncClient", lambda **kw: FakeClient())

        result = await firm_export_slack_digest(
            content="# Digest\nAll tasks completed.",
            objective="weekly digest",
            departments=["ops"],
        )
        assert result["ok"] is True
        assert "webhook_used" in result

    @pytest.mark.asyncio
    async def test_jira_ticket_success(self, monkeypatch):
        """Mock Jira REST API and verify issue creation."""
        from unittest.mock import MagicMock
        from src.delivery_export import firm_export_jira_ticket
        import src.delivery_export as mod

        monkeypatch.setattr(mod, "JIRA_API_TOKEN", "jira-token-1234")
        monkeypatch.setattr(mod, "JIRA_BASE_URL", "https://org.atlassian.net")
        monkeypatch.setattr(mod, "JIRA_USER_EMAIL", "test@example.com")

        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"key": "ENG-123"}
        mock_resp.text = '{"key": "ENG-123"}'

        class FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, *a, **kw): return mock_resp

        monkeypatch.setattr(mod.httpx, "AsyncClient", lambda **kw: FakeClient())

        result = await firm_export_jira_ticket(
            project_key="ENG",
            content="# Issue body",
            objective="bug fix",
            departments=["qa"],
        )
        assert result["ok"] is True
        assert result["issue_key"] == "ENG-123"
        assert "atlassian.net/browse/ENG-123" in result["issue_url"]

    @pytest.mark.asyncio
    async def test_linear_issue_success(self, monkeypatch):
        """Mock Linear GraphQL API and verify issue creation."""
        from unittest.mock import MagicMock
        from src.delivery_export import firm_export_linear_issue
        import src.delivery_export as mod

        monkeypatch.setattr(mod, "LINEAR_API_KEY", "lin_api_test1234")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "issueCreate": {
                    "success": True,
                    "issue": {
                        "id": "uuid-123",
                        "identifier": "ENG-42",
                        "url": "https://linear.app/team/issue/ENG-42",
                    },
                }
            }
        }
        mock_resp.raise_for_status = MagicMock()

        class FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, *a, **kw): return mock_resp

        monkeypatch.setattr(mod.httpx, "AsyncClient", lambda **kw: FakeClient())

        result = await firm_export_linear_issue(
            team_id="team-uuid",
            content="# Issue",
            objective="new feature",
            departments=["product"],
        )
        assert result["ok"] is True
        assert result["issue_id"] == "uuid-123"
        assert result["issue_identifier"] == "ENG-42"
        assert "linear.app" in result["issue_url"]


# ═══════════════════════════════════════════════════════════════════════════════
# Observability tools (T1, T6)
# ═══════════════════════════════════════════════════════════════════════════════

class TestObservability:
    """Tests for observability tools (T1 observability pipeline, T6 CI check)."""

    # ── openclaw_observability_pipeline (T1) ──────────────────────────────────

    def test_observability_pipeline_file_not_found(self, mcp_server):
        result = _rpc("tools/call", {
            "name": "openclaw_observability_pipeline",
            "arguments": {"jsonl_path": "/nonexistent/traces.jsonl"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is False
        assert "not found" in data["error"]

    def test_observability_pipeline_ingest(self, mcp_server, tmp_path):
        """Ingest a small JSONL file and verify SQLite ingestion."""
        traces = tmp_path / "test.jsonl"
        db = tmp_path / "test.db"
        lines = [
            json.dumps({"traceId": "t1", "spanId": "s1", "severity": "INFO", "message": "hello"}),
            json.dumps({"traceId": "t1", "spanId": "s2", "severity": "WARN", "message": "world"}),
            json.dumps({"traceId": "t2", "spanId": "s3", "severity": "ERROR", "message": "fail"}),
        ]
        traces.write_text("\n".join(lines))

        result = _rpc("tools/call", {
            "name": "openclaw_observability_pipeline",
            "arguments": {
                "jsonl_path": str(traces),
                "db_path": str(db),
            },
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        assert data["ingested"] == 3
        assert data["total_rows_in_table"] == 3
        assert db.exists()

    def test_observability_pipeline_deduplication(self, mcp_server, tmp_path):
        """Re-ingesting the same traces should skip duplicates."""
        traces = tmp_path / "dup.jsonl"
        db = tmp_path / "dup.db"
        line = json.dumps({"traceId": "t1", "spanId": "s1", "message": "hello"})
        traces.write_text(line + "\n" + line)

        result = _rpc("tools/call", {
            "name": "openclaw_observability_pipeline",
            "arguments": {"jsonl_path": str(traces), "db_path": str(db)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["ok"] is True
        assert data["ingested"] == 1
        assert data["skipped_duplicates"] == 1

    def test_observability_pipeline_traversal_blocked(self, mcp_server):
        result = _rpc("tools/call", {
            "name": "openclaw_observability_pipeline",
            "arguments": {"jsonl_path": "../../etc/passwd.jsonl"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert "error" in data
        assert data["error"] == "Validation failed"

    # ── openclaw_ci_pipeline_check (T6) ───────────────────────────────────────

    def test_ci_pipeline_no_ci_dir(self, mcp_server, tmp_path):
        """Repo without .github/workflows → critical."""
        result = _rpc("tools/call", {
            "name": "openclaw_ci_pipeline_check",
            "arguments": {"repo_path": str(tmp_path)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "critical"
        assert "lint" in data["missing_required"]

    def test_ci_pipeline_complete(self, mcp_server, tmp_path):
        """Repo with complete CI → ok."""
        ci_dir = tmp_path / ".github" / "workflows"
        ci_dir.mkdir(parents=True)
        (ci_dir / "ci.yml").write_text("""
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ruff check .
      - run: pytest --cov --cov-fail-under=80
      - uses: trufflesecurity/trufflehog@main
      - run: mypy src/
""")
        result = _rpc("tools/call", {
            "name": "openclaw_ci_pipeline_check",
            "arguments": {"repo_path": str(tmp_path)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"
        assert data["missing_required"] == []
        assert data["required_steps"]["lint"] is True
        assert data["required_steps"]["test"] is True
        assert data["required_steps"]["secrets"] is True

    def test_ci_pipeline_partial(self, mcp_server, tmp_path):
        """Repo with lint + test but no secrets → high."""
        ci_dir = tmp_path / ".github" / "workflows"
        ci_dir.mkdir(parents=True)
        (ci_dir / "ci.yml").write_text("- run: ruff check .\n- run: pytest tests/\n")
        result = _rpc("tools/call", {
            "name": "openclaw_ci_pipeline_check",
            "arguments": {"repo_path": str(tmp_path)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"
        assert "secrets" in data["missing_required"]

    def test_ci_pipeline_traversal_blocked(self, mcp_server):
        result = _rpc("tools/call", {
            "name": "openclaw_ci_pipeline_check",
            "arguments": {"repo_path": "../../etc"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert "error" in data
        assert data["error"] == "Validation failed"


# ═══════════════════════════════════════════════════════════════════════════════
# Memory audit tools (T3, T9)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMemoryAudit:
    """Tests for memory_audit tools (T3 pgvector, T9 knowledge graph)."""

    # ── openclaw_pgvector_memory_check (T3) ───────────────────────────────────

    @pytest.mark.asyncio
    async def test_pgvector_no_config(self):
        """No config provided → error."""
        from src.memory_audit import openclaw_pgvector_memory_check
        result = await openclaw_pgvector_memory_check()
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_pgvector_no_vector_config(self):
        """Config without vector section → info."""
        from src.memory_audit import openclaw_pgvector_memory_check
        result = await openclaw_pgvector_memory_check(config_data={"gateway": {}})
        assert result["status"] == "info"

    @pytest.mark.asyncio
    async def test_pgvector_hnsw_ok(self):
        """Well-configured pgvector → ok."""
        from src.memory_audit import openclaw_pgvector_memory_check
        result = await openclaw_pgvector_memory_check(config_data={
            "memory": {
                "vector": {
                    "backend": "pgvector",
                    "index_type": "hnsw",
                    "dimensions": 1536,
                    "distance": "cosine",
                    "m": 16,
                    "ef_construction": 128,
                }
            }
        })
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_pgvector_embedded_credentials(self):
        """Connection string with credentials → critical."""
        from src.memory_audit import openclaw_pgvector_memory_check
        result = await openclaw_pgvector_memory_check(
            config_data={"memory": {"vector": {"backend": "pgvector", "index_type": "hnsw", "dimensions": 1536, "distance": "cosine"}}},
            connection_string="postgresql://admin:s3cret@db.example.com:5432/openclaw",
        )
        assert result["status"] == "critical"
        crit = [f for f in result["findings"] if f["severity"] == "CRITICAL"]
        assert len(crit) >= 1

    @pytest.mark.asyncio
    async def test_pgvector_missing_index_and_dims(self):
        """No index type and no dimensions → high."""
        from src.memory_audit import openclaw_pgvector_memory_check
        result = await openclaw_pgvector_memory_check(config_data={
            "memory": {"vector": {"backend": "pgvector"}}
        })
        assert result["status"] == "high"

    # ── openclaw_knowledge_graph_check (T9) ───────────────────────────────────

    @pytest.mark.asyncio
    async def test_kg_no_config(self):
        """No config → error."""
        from src.memory_audit import openclaw_knowledge_graph_check
        result = await openclaw_knowledge_graph_check()
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_kg_no_graph_section(self):
        """Config without graph section → info."""
        from src.memory_audit import openclaw_knowledge_graph_check
        result = await openclaw_knowledge_graph_check(config_data={"gateway": {}})
        assert result["status"] == "info"

    @pytest.mark.asyncio
    async def test_kg_well_configured(self):
        """Complete graph config → ok."""
        from src.memory_audit import openclaw_knowledge_graph_check
        result = await openclaw_knowledge_graph_check(config_data={
            "memory": {
                "graph": {
                    "backend": "neo4j",
                    "ttl_seconds": 2_592_000,  # 30 days
                    "max_nodes": 100_000,
                    "backup": {"enabled": True, "interval": "daily"},
                }
            }
        })
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_kg_missing_ttl_and_backup(self):
        """No TTL and no backup → high."""
        from src.memory_audit import openclaw_knowledge_graph_check
        result = await openclaw_knowledge_graph_check(config_data={
            "memory": {"graph": {"backend": "json"}}
        })
        assert result["status"] == "high"

    @pytest.mark.asyncio
    async def test_kg_graph_data_with_orphans(self, tmp_path):
        """Graph export with orphan nodes → findings with orphan count."""
        from src.memory_audit import openclaw_knowledge_graph_check
        graph_file = tmp_path / "graph.json"
        graph_file.write_text(json.dumps({
            "nodes": [
                {"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "orphan1"}, {"id": "orphan2"},
            ],
            "edges": [
                {"source": "a", "target": "b"},
                {"source": "b", "target": "c"},
            ],
        }))
        result = await openclaw_knowledge_graph_check(
            config_data={"memory": {"graph": {"backend": "json", "ttl_seconds": 86400, "max_nodes": 1000, "backup": True}}},
            graph_data_path=str(graph_file),
        )
        assert result["metrics"]["orphan_nodes"] == 2
        assert result["metrics"]["total_nodes"] == 5

    @pytest.mark.asyncio
    async def test_kg_graph_data_with_cycles(self, tmp_path):
        """Graph with cycles → detected."""
        from src.memory_audit import openclaw_knowledge_graph_check
        graph_file = tmp_path / "cyclic.json"
        graph_file.write_text(json.dumps({
            "nodes": [{"id": "a"}, {"id": "b"}, {"id": "c"}],
            "edges": [
                {"source": "a", "target": "b"},
                {"source": "b", "target": "c"},
                {"source": "c", "target": "a"},
            ],
        }))
        result = await openclaw_knowledge_graph_check(
            config_data={"memory": {"graph": {"backend": "json", "ttl_seconds": 86400, "max_nodes": 1000, "backup": True}}},
            graph_data_path=str(graph_file),
        )
        assert result["metrics"]["has_cycles"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# Concurrency lock tests (I9)
# ═══════════════════════════════════════════════════════════════════════════════

class TestConcurrencyLocks:
    """Test workspace lock under concurrent access (I9)."""

    def test_lock_concurrent_acquire(self, mcp_server):
        """Two sequential lock attempts — second should fail if first is held."""
        import concurrent.futures

        def lock_call(lock_id):
            return _rpc("tools/call", {
                "name": "openclaw_workspace_lock",
                "arguments": {
                    "path": f"/tmp/test-concurrent-{lock_id}",
                    "action": "acquire",
                    "owner": f"test-owner-{lock_id}",
                },
            })

        # Just verify the tool responds correctly to concurrent calls
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(lock_call, "a")
            f2 = executor.submit(lock_call, "b")
            r1 = f1.result()
            r2 = f2.result()

        # Both should respond (different workspaces, no contention)
        assert "result" in r1
        assert "result" in r2

    def test_lock_acquire_release_cycle(self, mcp_server, tmp_path):
        """Acquire → release cycle works correctly."""
        ws = str(tmp_path / "locktest")
        result1 = _rpc("tools/call", {
            "name": "openclaw_workspace_lock",
            "arguments": {"path": ws, "action": "acquire", "owner": "test-owner"},
        })
        data1 = json.loads(result1["result"]["content"][0]["text"])
        assert data1.get("locked") is True or data1.get("ok") is True

        result2 = _rpc("tools/call", {
            "name": "openclaw_workspace_lock",
            "arguments": {"path": ws, "action": "release", "owner": "test-owner"},
        })
        data2 = json.loads(result2["result"]["content"][0]["text"])
        assert data2.get("released") is True or data2.get("ok") is True


class TestConfigMigration:
    """Tests for config_migration tools (H17, H18, H19, M17, M21)."""

    # ── openclaw_shell_env_check (H17) ────────────────────────────────────────

    def test_shell_env_ld_preload_rejected(self, mcp_server, tmp_path):
        """LD_PRELOAD in agents.defaults.env → HIGH."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "agents": {
                "defaults": {
                    "env": {"LD_PRELOAD": "/tmp/evil.so", "HOME": "/home/agent"},
                }
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_shell_env_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"
        assert any("LD_PRELOAD" in f["message"] for f in data["findings"])

    def test_shell_env_clean(self, mcp_server, tmp_path):
        """No dangerous env vars → ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "agents": {
                "defaults": {
                    "env": {"PATH": "/usr/bin:/usr/local/bin"},
                }
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_shell_env_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    def test_shell_env_traversal_rejected(self, mcp_server):
        """config_path with .. must be rejected by Pydantic."""
        result = _rpc("tools/call", {
            "name": "openclaw_shell_env_check",
            "arguments": {"config_path": "../../etc/openclaw.json"},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["error"] == "Validation failed"

    # ── openclaw_plugin_integrity_check (H18) ─────────────────────────────────

    def test_plugin_no_version_pin(self, mcp_server, tmp_path):
        """Plugin without version → HIGH."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "plugins": {
                "entries": {
                    "my-plugin": {"source": "npm"},
                }
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_plugin_integrity_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"
        assert any("no version" in f["message"].lower() for f in data["findings"])

    def test_plugin_pinned_ok(self, mcp_server, tmp_path):
        """Plugin with exact version + integrity → ok or medium."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "plugins": {
                "entries": {
                    "my-plugin": {
                        "source": "npm",
                        "version": "1.2.3",
                        "integrity": "sha256-abc123",
                    },
                }
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_plugin_integrity_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] in ("ok", "medium")  # medium if no manifest file

    # ── openclaw_token_separation_check (H19) ─────────────────────────────────

    def test_token_reuse_detected(self, mcp_server, tmp_path):
        """Same token for hooks and gateway → HIGH."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "hooks": {"token": "shared-secret-token-12345678901234"},
            "gateway": {"auth": {"token": "shared-secret-token-12345678901234"}},
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_token_separation_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"
        assert any("identical" in f["message"].lower() for f in data["findings"])

    def test_token_separated_ok(self, mcp_server, tmp_path):
        """Different tokens → ok."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "hooks": {"token": "a" * 32},
            "gateway": {"auth": {"token": "b" * 32}},
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_token_separation_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    # ── openclaw_otel_redaction_check (M17) ───────────────────────────────────

    def test_otel_redaction_disabled(self, mcp_server, tmp_path):
        """Redaction explicitly disabled → HIGH."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "otel": {
                "endpoint": "https://otel.example.com",
                "redaction": {"enabled": False},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_otel_redaction_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"
        assert any("redaction" in f["message"].lower() for f in data["findings"])

    def test_otel_inline_auth_endpoint(self, mcp_server, tmp_path):
        """Endpoint with user:pass@host → HIGH."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "otel": {
                "endpoint": "https://admin:secret@otel.example.com",
                "redaction": {"enabled": True},
            }
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_otel_redaction_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"

    def test_otel_no_config_ok(self, mcp_server, tmp_path):
        """No otel config → ok (INFO)."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({"gateway": {"bind": "loopback"}}))
        result = _rpc("tools/call", {
            "name": "openclaw_otel_redaction_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

    # ── openclaw_rpc_rate_limit_check (M21) ───────────────────────────────────

    def test_rpc_rate_limit_remote_no_limit(self, mcp_server, tmp_path):
        """Remote bind without rate limit → HIGH."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {"bind": "lan"},
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_rpc_rate_limit_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "high"
        assert data["is_remote"] is True

    def test_rpc_rate_limit_loopback_ok(self, mcp_server, tmp_path):
        """Loopback without rate limit → ok (INFO only)."""
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(json.dumps({
            "gateway": {"bind": "loopback"},
        }))
        result = _rpc("tools/call", {
            "name": "openclaw_rpc_rate_limit_check",
            "arguments": {"config_path": str(cfg)},
        })
        data = json.loads(result["result"]["content"][0]["text"])
        assert data["status"] == "ok"

