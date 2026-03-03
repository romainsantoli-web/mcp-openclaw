"""
Coverage tests for src/acp_bridge.py, src/gateway_fleet.py, src/vs_bridge.py.
Targets: acp 13%→100%, fleet 17%→100%, vs_bridge 33%→100%.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ═══════════════════════════════════════════════════════════════════════════════
# ACP BRIDGE
# ═══════════════════════════════════════════════════════════════════════════════

class TestAcpSessionPersist:
    def test_persist_new_session(self, tmp_path):
        sessions_path = str(tmp_path / "sessions.json")
        with patch("src.acp_bridge.ACP_SESSIONS_PATH", sessions_path):
            from src.acp_bridge import acp_session_persist
            r = _run(acp_session_persist("run-1", "gw-key-1", metadata={"test": True}))
            assert r["ok"] is True
            assert r["run_id"] == "run-1"
            assert r["total_sessions"] == 1

    def test_persist_updates_existing(self, tmp_path):
        sessions_path = str(tmp_path / "sessions.json")
        with patch("src.acp_bridge.ACP_SESSIONS_PATH", sessions_path):
            from src.acp_bridge import acp_session_persist
            _run(acp_session_persist("run-1", "gw-key-1"))
            r = _run(acp_session_persist("run-2", "gw-key-2"))
            assert r["total_sessions"] == 2

    def test_persist_no_metadata(self, tmp_path):
        sessions_path = str(tmp_path / "sessions.json")
        with patch("src.acp_bridge.ACP_SESSIONS_PATH", sessions_path):
            from src.acp_bridge import acp_session_persist
            r = _run(acp_session_persist("run-1", "gw-key-1"))
            assert r["ok"] is True


class TestAcpSessionRestore:
    def test_restore_empty(self, tmp_path):
        sessions_path = str(tmp_path / "sessions.json")
        with patch("src.acp_bridge.ACP_SESSIONS_PATH", sessions_path):
            from src.acp_bridge import acp_session_restore
            r = _run(acp_session_restore())
            assert r["ok"] is True
            assert r["restored"] == 0

    def test_restore_with_active_sessions(self, tmp_path):
        sessions_path = str(tmp_path / "sessions.json")
        sessions = {
            "run-1": {"gateway_session_key": "gw-1", "persisted_at": time.time(), "metadata": {}},
        }
        Path(sessions_path).write_text(json.dumps(sessions))
        with patch("src.acp_bridge.ACP_SESSIONS_PATH", sessions_path):
            from src.acp_bridge import acp_session_restore
            r = _run(acp_session_restore(max_age_hours=24))
            assert r["ok"] is True
            assert r["restored"] == 1

    def test_restore_purges_stale(self, tmp_path):
        sessions_path = str(tmp_path / "sessions.json")
        sessions = {
            "old-run": {"gateway_session_key": "gw-old", "persisted_at": time.time() - 200000, "metadata": {}},
        }
        Path(sessions_path).write_text(json.dumps(sessions))
        with patch("src.acp_bridge.ACP_SESSIONS_PATH", sessions_path):
            from src.acp_bridge import acp_session_restore
            r = _run(acp_session_restore(max_age_hours=1))
            assert r["purged"] == 1
            assert r["restored"] == 0

    def test_restore_corrupted_json(self, tmp_path):
        sessions_path = str(tmp_path / "sessions.json")
        Path(sessions_path).write_text("not valid json{{{")
        with patch("src.acp_bridge.ACP_SESSIONS_PATH", sessions_path):
            from src.acp_bridge import acp_session_restore
            r = _run(acp_session_restore())
            assert r["ok"] is True
            assert r["restored"] == 0


class TestAcpSessionListActive:
    def test_list_empty(self, tmp_path):
        sessions_path = str(tmp_path / "sessions.json")
        with patch("src.acp_bridge.ACP_SESSIONS_PATH", sessions_path):
            from src.acp_bridge import acp_session_list_active
            r = _run(acp_session_list_active())
            assert r["ok"] is True
            assert r["total"] == 0

    def test_list_includes_active_excludes_stale(self, tmp_path):
        sessions_path = str(tmp_path / "sessions.json")
        sessions = {
            "active": {"gateway_session_key": "gw-1", "persisted_at": time.time(), "metadata": {}},
            "stale": {"gateway_session_key": "gw-2", "persisted_at": time.time() - 200000, "metadata": {}},
        }
        Path(sessions_path).write_text(json.dumps(sessions))
        with patch("src.acp_bridge.ACP_SESSIONS_PATH", sessions_path):
            from src.acp_bridge import acp_session_list_active
            r = _run(acp_session_list_active(include_stale=False))
            assert r["total"] == 1

    def test_list_include_stale(self, tmp_path):
        sessions_path = str(tmp_path / "sessions.json")
        sessions = {
            "active": {"gateway_session_key": "gw-1", "persisted_at": time.time(), "metadata": {}},
            "stale": {"gateway_session_key": "gw-2", "persisted_at": time.time() - 200000, "metadata": {}},
        }
        Path(sessions_path).write_text(json.dumps(sessions))
        with patch("src.acp_bridge.ACP_SESSIONS_PATH", sessions_path):
            from src.acp_bridge import acp_session_list_active
            r = _run(acp_session_list_active(include_stale=True))
            assert r["total"] == 2


class TestFleetSessionInjectEnv:
    def test_all_rejected(self):
        from src.acp_bridge import fleet_session_inject_env
        r = _run(fleet_session_inject_env(env_vars={"DISALLOWED_KEY": "value"}))
        assert r["ok"] is False
        assert "No env vars passed" in r["error"]

    def test_allowed_keys_pass(self):
        from src.acp_bridge import fleet_session_inject_env
        r = _run(fleet_session_inject_env(
            env_vars={"ANTHROPIC_API_KEY": "sk-test-key-123456"},
            dry_run=True,
        ))
        assert r["ok"] is True
        assert r["dry_run"] is True
        assert "ANTHROPIC_API_KEY" in r["validated_keys"]

    def test_mixed_keys(self):
        from src.acp_bridge import fleet_session_inject_env
        r = _run(fleet_session_inject_env(
            env_vars={"OPENAI_API_KEY": "sk-test", "BAD_KEY": "val"},
            dry_run=True,
        ))
        assert r["ok"] is True
        assert len(r["rejected"]) == 1

    def test_extra_allowlist(self):
        from src.acp_bridge import fleet_session_inject_env
        r = _run(fleet_session_inject_env(
            env_vars={"MY_CUSTOM_VAR": "val"},
            allowlist_keys=["MY_CUSTOM_VAR"],
            dry_run=True,
        ))
        assert r["ok"] is True
        assert "MY_CUSTOM_VAR" in r["validated_keys"]

    def test_actual_broadcast(self):
        from src.acp_bridge import fleet_session_inject_env
        with patch("src.gateway_fleet.firm_gateway_fleet_broadcast", new_callable=AsyncMock) as mock_bc:
            mock_bc.return_value = {"ok": True, "sent": 0}
            r = _run(fleet_session_inject_env(
                env_vars={"ANTHROPIC_API_KEY": "sk-test"},
                dry_run=False,
            ))
            assert r["ok"] is True
            assert r["dry_run"] is False
            mock_bc.assert_called_once()


class TestFleetCronSchedule:
    def test_invalid_command_chars(self):
        from src.acp_bridge import fleet_cron_schedule
        r = _run(fleet_cron_schedule(command="rm -rf /; echo pwned", schedule="0 9 * * *"))
        assert r["ok"] is False
        assert "disallowed characters" in r["error"]

    def test_blocklisted_command(self):
        from src.acp_bridge import fleet_cron_schedule
        r = _run(fleet_cron_schedule(command="rm /tmp/data", schedule="0 9 * * *"))
        assert r["ok"] is False
        assert "blocklist" in r["error"]

    def test_invalid_cron(self):
        from src.acp_bridge import fleet_cron_schedule
        r = _run(fleet_cron_schedule(command="echo hello", schedule="invalid"))
        assert r["ok"] is False
        assert "Invalid cron" in r["error"]

    def test_non_main_session(self):
        from src.acp_bridge import fleet_cron_schedule
        r = _run(fleet_cron_schedule(command="echo hello", schedule="0 9 * * 1", session="sandbox"))
        assert r["ok"] is False
        assert "main" in r["error"]

    def test_happy_path(self, tmp_path):
        cron_path = str(tmp_path / "cron.json")
        with patch("src.acp_bridge._CRON_SCHEDULE_PATH", cron_path):
            from src.acp_bridge import fleet_cron_schedule
            r = _run(fleet_cron_schedule(
                command="echo hello",
                schedule="0 9 * * 1-5",
                description="Morning greeting",
            ))
            assert r["ok"] is True
            assert "cron_id" in r
            # Verify persisted
            data = json.loads(Path(cron_path).read_text())
            assert len(data) == 1

    def test_dd_blocked(self):
        from src.acp_bridge import fleet_cron_schedule
        r = _run(fleet_cron_schedule(command="dd if=/dev/zero", schedule="0 0 * * *"))
        assert r["ok"] is False


class TestWorkspaceLock:
    def test_path_traversal(self):
        from src.acp_bridge import openclaw_workspace_lock
        r = _run(openclaw_workspace_lock(path="../etc/passwd", action="acquire", owner="test"))
        assert r["ok"] is False
        assert ".." in r["error"]

    def test_invalid_action(self):
        from src.acp_bridge import openclaw_workspace_lock
        r = _run(openclaw_workspace_lock(path="test.json", action="delete", owner="test"))
        assert r["ok"] is False

    def test_status_no_lock(self, tmp_path):
        with patch("src.acp_bridge.WORKSPACE_LOCKS_DIR", str(tmp_path)):
            from src.acp_bridge import openclaw_workspace_lock
            r = _run(openclaw_workspace_lock(path="myfile.json", action="status", owner="test"))
            assert r["ok"] is True
            assert r["locked"] is False

    def test_acquire_and_status(self, tmp_path):
        with patch("src.acp_bridge.WORKSPACE_LOCKS_DIR", str(tmp_path)):
            from src.acp_bridge import openclaw_workspace_lock
            r = _run(openclaw_workspace_lock(path="myfile.json", action="acquire", owner="agent-1"))
            assert r["ok"] is True
            assert r["locked"] is True

            r2 = _run(openclaw_workspace_lock(path="myfile.json", action="status", owner="anyone"))
            assert r2["locked"] is True
            assert r2["lock_owner"] == "agent-1"

    def test_release_no_lock(self, tmp_path):
        with patch("src.acp_bridge.WORKSPACE_LOCKS_DIR", str(tmp_path)):
            from src.acp_bridge import openclaw_workspace_lock
            r = _run(openclaw_workspace_lock(path="myfile.json", action="release", owner="test"))
            assert r["ok"] is True
            assert "nothing to release" in r["note"].lower()

    def test_release_wrong_owner(self, tmp_path):
        with patch("src.acp_bridge.WORKSPACE_LOCKS_DIR", str(tmp_path)):
            from src.acp_bridge import openclaw_workspace_lock
            _run(openclaw_workspace_lock(path="file.json", action="acquire", owner="agent-1"))
            r = _run(openclaw_workspace_lock(path="file.json", action="release", owner="agent-2"))
            assert r["ok"] is False
            assert "owned by" in r["error"]

    def test_release_correct_owner(self, tmp_path):
        with patch("src.acp_bridge.WORKSPACE_LOCKS_DIR", str(tmp_path)):
            from src.acp_bridge import openclaw_workspace_lock
            _run(openclaw_workspace_lock(path="file.json", action="acquire", owner="agent-1"))
            r = _run(openclaw_workspace_lock(path="file.json", action="release", owner="agent-1"))
            assert r["ok"] is True

    def test_acquire_timeout(self, tmp_path):
        with patch("src.acp_bridge.WORKSPACE_LOCKS_DIR", str(tmp_path)):
            from src.acp_bridge import openclaw_workspace_lock
            # Acquire first lock
            _run(openclaw_workspace_lock(path="busy.json", action="acquire", owner="holder"))
            # Try to acquire same lock with short timeout
            r = _run(openclaw_workspace_lock(path="busy.json", action="acquire", owner="waiter", timeout_s=0.2))
            assert r["ok"] is False
            assert "Timed out" in r["error"]


# ═══════════════════════════════════════════════════════════════════════════════
# GATEWAY FLEET
# ═══════════════════════════════════════════════════════════════════════════════

class TestGatewayFleetStatus:
    def test_empty_fleet(self, tmp_path):
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", str(tmp_path / "fleet.json")):
            from src.gateway_fleet import firm_gateway_fleet_status
            r = _run(firm_gateway_fleet_status())
            assert r["ok"] is True
            assert r["total"] == 0

    def test_with_instances(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        fleet_data = {
            "inst1": {
                "name": "inst1", "ws_url": "ws://localhost:1234",
                "http_url": "http://localhost:1234", "tags": [], "department": "eng",
            },
        }
        Path(fleet_path).write_text(json.dumps(fleet_data))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            with patch("src.gateway_fleet._check_instance", new_callable=AsyncMock) as mock_check:
                mock_check.return_value = {"name": "inst1", "status": "ok"}
                from src.gateway_fleet import firm_gateway_fleet_status
                r = _run(firm_gateway_fleet_status())
                assert r["total"] == 1
                assert r["healthy"] == 1

    def test_filter_by_department(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        fleet_data = {
            "eng1": {"name": "eng1", "ws_url": "ws://a:1", "http_url": "http://a:1", "department": "eng", "tags": []},
            "hr1": {"name": "hr1", "ws_url": "ws://b:1", "http_url": "http://b:1", "department": "hr", "tags": []},
        }
        Path(fleet_path).write_text(json.dumps(fleet_data))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            with patch("src.gateway_fleet._check_instance", new_callable=AsyncMock) as mock_check:
                mock_check.return_value = {"name": "eng1", "status": "ok"}
                from src.gateway_fleet import firm_gateway_fleet_status
                r = _run(firm_gateway_fleet_status(filter_department="eng"))
                assert r["total"] == 1


class TestGatewayFleetAdd:
    def test_fleet_limit(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        Path(fleet_path).write_text(json.dumps({f"inst{i}": {
            "name": f"inst{i}", "ws_url": f"ws://a:{i}", "http_url": f"http://a:{i}", "tags": [],
        } for i in range(50)}))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            from src.gateway_fleet import firm_gateway_fleet_add
            r = _run(firm_gateway_fleet_add("new", "ws://x:1", "http://x:1"))
            assert r["ok"] is False
            assert "limit" in r["error"]

    def test_duplicate_name(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        Path(fleet_path).write_text(json.dumps({"existing": {
            "name": "existing", "ws_url": "ws://a:1", "http_url": "http://a:1", "tags": [],
        }}))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            from src.gateway_fleet import firm_gateway_fleet_add
            r = _run(firm_gateway_fleet_add("existing", "ws://b:1", "http://b:1"))
            assert r["ok"] is False
            assert "already exists" in r["error"]

    def test_invalid_ws_url(self, tmp_path):
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", str(tmp_path / "fleet.json")):
            from src.gateway_fleet import firm_gateway_fleet_add
            r = _run(firm_gateway_fleet_add("test", "http://bad:1", "http://ok:1"))
            assert r["ok"] is False
            assert "ws://" in r["error"]

    def test_invalid_http_url(self, tmp_path):
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", str(tmp_path / "fleet.json")):
            from src.gateway_fleet import firm_gateway_fleet_add
            r = _run(firm_gateway_fleet_add("test", "ws://ok:1", "ftp://bad:1"))
            assert r["ok"] is False
            assert "http://" in r["error"]

    def test_unreachable_instance(self, tmp_path):
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", str(tmp_path / "fleet.json")):
            with patch("src.gateway_fleet._check_instance", new_callable=AsyncMock) as mock_check:
                mock_check.return_value = {"name": "test", "status": "unreachable", "error": "timeout"}
                from src.gateway_fleet import firm_gateway_fleet_add
                r = _run(firm_gateway_fleet_add("test", "ws://ok:1", "http://ok:1"))
                assert r["ok"] is False
                assert "not reachable" in r["error"]

    def test_happy_path(self, tmp_path):
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", str(tmp_path / "fleet.json")):
            with patch("src.gateway_fleet._check_instance", new_callable=AsyncMock) as mock_check:
                mock_check.return_value = {"name": "prod", "status": "ok"}
                from src.gateway_fleet import firm_gateway_fleet_add
                r = _run(firm_gateway_fleet_add("prod", "ws://p:1", "http://p:1", token="t", department="eng", tags=["prod"]))
                assert r["ok"] is True
                assert r["name"] == "prod"


class TestGatewayFleetRemove:
    def test_not_found(self, tmp_path):
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", str(tmp_path / "fleet.json")):
            from src.gateway_fleet import firm_gateway_fleet_remove
            r = _run(firm_gateway_fleet_remove("nonexistent"))
            assert r["ok"] is False

    def test_happy_path(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        Path(fleet_path).write_text(json.dumps({"inst1": {
            "name": "inst1", "ws_url": "ws://a:1", "http_url": "http://a:1", "tags": [],
        }}))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            from src.gateway_fleet import firm_gateway_fleet_remove
            r = _run(firm_gateway_fleet_remove("inst1"))
            assert r["ok"] is True
            assert r["removed"] is True


class TestGatewayFleetBroadcast:
    def test_empty_fleet(self, tmp_path):
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", str(tmp_path / "fleet.json")):
            from src.gateway_fleet import firm_gateway_fleet_broadcast
            r = _run(firm_gateway_fleet_broadcast(message="hello"))
            assert r["ok"] is True
            assert r["sent"] == 0

    def test_broadcast_with_filter(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        fleet_data = {
            "eng1": {"name": "eng1", "ws_url": "ws://a:1", "http_url": "http://a:1", "department": "eng", "tags": ["prod"]},
            "hr1": {"name": "hr1", "ws_url": "ws://b:1", "http_url": "http://b:1", "department": "hr", "tags": []},
        }
        Path(fleet_path).write_text(json.dumps(fleet_data))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            with patch("src.gateway_fleet._ws_rpc_instance", new_callable=AsyncMock) as mock_rpc:
                mock_rpc.return_value = {"ok": True}
                from src.gateway_fleet import firm_gateway_fleet_broadcast
                r = _run(firm_gateway_fleet_broadcast(message="hello eng", filter_department="eng"))
                assert r["sent"] == 1

    def test_broadcast_failure(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        fleet_data = {
            "inst1": {"name": "inst1", "ws_url": "ws://a:1", "http_url": "http://a:1", "tags": []},
        }
        Path(fleet_path).write_text(json.dumps(fleet_data))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            with patch("src.gateway_fleet._ws_rpc_instance", new_callable=AsyncMock) as mock_rpc:
                mock_rpc.side_effect = RuntimeError("connection refused")
                from src.gateway_fleet import firm_gateway_fleet_broadcast
                r = _run(firm_gateway_fleet_broadcast(message="hel", require_all_success=True))
                assert r["ok"] is False
                assert r["failed"] == 1

    def test_broadcast_tag_filter(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        fleet_data = {
            "p1": {"name": "p1", "ws_url": "ws://a:1", "http_url": "http://a:1", "tags": ["prod"]},
        }
        Path(fleet_path).write_text(json.dumps(fleet_data))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            with patch("src.gateway_fleet._ws_rpc_instance", new_callable=AsyncMock) as mock_rpc:
                mock_rpc.return_value = {}
                from src.gateway_fleet import firm_gateway_fleet_broadcast
                r = _run(firm_gateway_fleet_broadcast(message="hi", filter_tag="prod"))
                assert r["sent"] == 1


class TestGatewayFleetSync:
    def test_no_params(self, tmp_path):
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", str(tmp_path / "fleet.json")):
            from src.gateway_fleet import firm_gateway_fleet_sync
            r = _run(firm_gateway_fleet_sync())
            assert r["ok"] is False
            assert "Provide" in r["error"]

    def test_dry_run(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        fleet_data = {"i1": {"name": "i1", "ws_url": "ws://a:1", "http_url": "http://a:1", "tags": []}}
        Path(fleet_path).write_text(json.dumps(fleet_data))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            from src.gateway_fleet import firm_gateway_fleet_sync
            r = _run(firm_gateway_fleet_sync(config_patch={"model": "new"}, dry_run=True))
            assert r["ok"] is True
            assert r["dry_run"] is True

    def test_sync_config_and_skills(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        fleet_data = {"i1": {"name": "i1", "ws_url": "ws://a:1", "http_url": "http://a:1", "tags": []}}
        Path(fleet_path).write_text(json.dumps(fleet_data))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            with patch("src.gateway_fleet._ws_rpc_instance", new_callable=AsyncMock) as mock_rpc:
                mock_rpc.return_value = {}
                from src.gateway_fleet import firm_gateway_fleet_sync
                r = _run(firm_gateway_fleet_sync(config_patch={"a": 1}, skill_slugs=["sk1"]))
                assert r["ok"] is True
                assert r["synced"] == 1

    def test_sync_failure(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        fleet_data = {"i1": {"name": "i1", "ws_url": "ws://a:1", "http_url": "http://a:1", "tags": []}}
        Path(fleet_path).write_text(json.dumps(fleet_data))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            with patch("src.gateway_fleet._ws_rpc_instance", new_callable=AsyncMock) as mock_rpc:
                mock_rpc.side_effect = RuntimeError("fail")
                from src.gateway_fleet import firm_gateway_fleet_sync
                r = _run(firm_gateway_fleet_sync(config_patch={"a": 1}))
                assert r["ok"] is False
                assert r["failed"] == 1


class TestGatewayFleetList:
    def test_empty(self, tmp_path):
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", str(tmp_path / "fleet.json")):
            from src.gateway_fleet import firm_gateway_fleet_list
            r = _run(firm_gateway_fleet_list())
            assert r["ok"] is True
            assert r["count"] == 0

    def test_with_instances(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        fleet_data = {
            "i1": {"name": "i1", "ws_url": "ws://a:1", "http_url": "http://a:1", "tags": ["prod"], "department": "eng", "token": "secret"},
        }
        Path(fleet_path).write_text(json.dumps(fleet_data))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            from src.gateway_fleet import firm_gateway_fleet_list
            r = _run(firm_gateway_fleet_list())
            assert r["count"] == 1
            inst = r["instances"][0]
            assert inst["has_token"] is True
            assert inst["department"] == "eng"

    def test_filter_tag(self, tmp_path):
        fleet_path = str(tmp_path / "fleet.json")
        fleet_data = {
            "i1": {"name": "i1", "ws_url": "ws://a:1", "http_url": "http://a:1", "tags": ["prod"]},
            "i2": {"name": "i2", "ws_url": "ws://b:1", "http_url": "http://b:1", "tags": ["dev"]},
        }
        Path(fleet_path).write_text(json.dumps(fleet_data))
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", fleet_path):
            from src.gateway_fleet import firm_gateway_fleet_list
            r = _run(firm_gateway_fleet_list(filter_tag="prod"))
            assert r["count"] == 1


class TestGatewayInstanceDataclass:
    def test_to_dict_from_dict(self):
        from src.gateway_fleet import GatewayInstance
        inst = GatewayInstance(name="test", ws_url="ws://a:1", http_url="http://a:1", token="t", department="eng", tags=["prod"])
        d = inst.to_dict()
        inst2 = GatewayInstance.from_dict(d)
        assert inst2.name == "test"
        assert inst2.token == "t"

    def test_from_dict_defaults(self):
        from src.gateway_fleet import GatewayInstance
        inst = GatewayInstance.from_dict({"name": "x", "ws_url": "ws://a:1", "http_url": "http://a:1"})
        assert inst.token is None
        assert inst.tags == []


class TestCheckInstance:
    def test_timeout(self):
        import httpx
        from src.gateway_fleet import GatewayInstance, _check_instance
        inst = GatewayInstance(name="t", ws_url="ws://a:1", http_url="http://a:1")
        with patch("src.gateway_fleet.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            r = _run(_check_instance(inst))
            assert r["status"] == "timeout"

    def test_http_error(self):
        import httpx
        from src.gateway_fleet import GatewayInstance, _check_instance
        inst = GatewayInstance(name="t", ws_url="ws://a:1", http_url="http://a:1")
        with patch("src.gateway_fleet.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            resp = MagicMock()
            resp.raise_for_status.side_effect = httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock())
            mock_client.get.return_value = resp
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            r = _run(_check_instance(inst))
            assert r["status"] == "error"

    def test_generic_exception(self):
        from src.gateway_fleet import GatewayInstance, _check_instance
        inst = GatewayInstance(name="t", ws_url="ws://a:1", http_url="http://a:1")
        with patch("src.gateway_fleet.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.side_effect = ConnectionError("refused")
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            r = _run(_check_instance(inst))
            assert r["status"] == "unreachable"

    def test_success(self):
        from src.gateway_fleet import GatewayInstance, _check_instance
        inst = GatewayInstance(name="t", ws_url="ws://a:1", http_url="http://a:1", token="tok")
        with patch("src.gateway_fleet.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.headers = {"content-type": "application/json"}
            resp.json.return_value = {"version": "2.0.0", "sessions": 3, "uptime": 1234}
            mock_client.get.return_value = resp
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            r = _run(_check_instance(inst))
            assert r["status"] == "ok"
            assert r["gateway_version"] == "2.0.0"


# ═══════════════════════════════════════════════════════════════════════════════
# VS BRIDGE
# ═══════════════════════════════════════════════════════════════════════════════

class TestVSContext:
    def test_to_payload(self):
        from src.vs_bridge import VSContext
        ctx = VSContext(
            workspace_path="/test",
            open_files=[f"file{i}.py" for i in range(30)],
            recent_changes=[{"file": f"f{i}"} for i in range(15)],
        )
        payload = ctx.to_payload()
        assert len(payload["open_files"]) == 20
        assert len(payload["recent_changes"]) == 10

    def test_fingerprint(self):
        from src.vs_bridge import VSContext
        ctx = VSContext(workspace_path="/test")
        fp = ctx.fingerprint()
        assert len(fp) == 16


class TestVsContextPush:
    def test_push_ws_failure(self):
        from src.vs_bridge import vs_context_push
        with patch("src.vs_bridge._ws_rpc", new_callable=AsyncMock) as mock_rpc:
            mock_rpc.side_effect = RuntimeError("ws error")
            r = _run(vs_context_push(workspace_path="/test"))
            assert r["ok"] is False
            assert "ws error" in r["error"]

    def test_push_success(self):
        from src.vs_bridge import vs_context_push
        with patch("src.vs_bridge._ws_rpc", new_callable=AsyncMock) as mock_rpc:
            mock_rpc.return_value = {}
            r = _run(vs_context_push(
                workspace_path="/test",
                open_files=["a.py"],
                active_file="a.py",
                recent_changes=[{"file": "a.py"}],
                agent_last_action="edit",
                agent_last_result="ok",
                session_id="custom-session",
            ))
            assert r["ok"] is True
            assert r["session_id"] == "custom-session"

    def test_push_large_context_trimmed(self):
        from src.vs_bridge import vs_context_push
        with patch("src.vs_bridge._ws_rpc", new_callable=AsyncMock) as mock_rpc:
            mock_rpc.return_value = {}
            with patch("src.vs_bridge.MAX_CONTEXT_BYTES", 10):
                r = _run(vs_context_push(
                    workspace_path="/test",
                    open_files=[f"long_file_{i}.py" for i in range(100)],
                    recent_changes=[{"file": f"c{i}"} for i in range(50)],
                ))
                assert r["ok"] is True

    def test_push_uses_registry(self):
        from src.vs_bridge import vs_context_push, _session_registry
        _session_registry["/my/workspace"] = "session-42"
        with patch("src.vs_bridge._ws_rpc", new_callable=AsyncMock) as mock_rpc:
            mock_rpc.return_value = {}
            r = _run(vs_context_push(workspace_path="/my/workspace"))
            assert r["session_id"] == "session-42"
        _session_registry.pop("/my/workspace", None)


class TestVsContextPull:
    def test_pull_success(self):
        from src.vs_bridge import vs_context_pull
        with patch("src.vs_bridge._ws_rpc", new_callable=AsyncMock) as mock_rpc:
            mock_rpc.return_value = {"model": "claude-3", "tokens": 1000, "lastMessage": "hi"}
            r = _run(vs_context_pull(session_id="main"))
            assert r["ok"] is True
            assert r["context"]["model"] == "claude-3"

    def test_pull_failure(self):
        from src.vs_bridge import vs_context_pull
        with patch("src.vs_bridge._ws_rpc", new_callable=AsyncMock) as mock_rpc:
            mock_rpc.side_effect = RuntimeError("fail")
            r = _run(vs_context_pull())
            assert r["ok"] is False
            assert r["context"] == {}


class TestVsSessionLink:
    def test_link_success(self):
        from src.vs_bridge import vs_session_link, _session_registry
        with patch("src.vs_bridge._ws_rpc", new_callable=AsyncMock) as mock_rpc:
            mock_rpc.return_value = {}
            r = _run(vs_session_link(workspace_path="/test", session_id="s1"))
            assert r["ok"] is True
            assert _session_registry["/test"] == "s1"
        _session_registry.pop("/test", None)

    def test_link_failure(self):
        from src.vs_bridge import vs_session_link
        with patch("src.vs_bridge._ws_rpc", new_callable=AsyncMock) as mock_rpc:
            mock_rpc.side_effect = RuntimeError("session not found")
            r = _run(vs_session_link(workspace_path="/test", session_id="bad"))
            assert r["ok"] is False


class TestVsSessionStatus:
    def test_status_reachable(self):
        from src.vs_bridge import vs_session_status
        with patch("src.vs_bridge._http_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"status": "ok"}
            r = _run(vs_session_status())
            assert r["ok"] is True
            assert r["gateway_reachable"] is True

    def test_status_unreachable(self):
        from src.vs_bridge import vs_session_status
        with patch("src.vs_bridge._http_get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = RuntimeError("fail")
            r = _run(vs_session_status())
            assert r["ok"] is True
            assert r["gateway_reachable"] is False

    def test_status_specific_workspace(self):
        from src.vs_bridge import vs_session_status, _session_registry
        _session_registry["/my/ws"] = "s1"
        with patch("src.vs_bridge._http_get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = RuntimeError("fail")
            r = _run(vs_session_status(workspace_path="/my/ws"))
            assert "/my/ws" in r["linked_sessions"]
        _session_registry.pop("/my/ws", None)


class TestVsBuildHeaders:
    def test_no_token(self):
        with patch("src.vs_bridge.GATEWAY_TOKEN", None):
            from src.vs_bridge import _build_ws_headers
            h = _build_ws_headers()
            assert "Authorization" not in h

    def test_with_token(self):
        with patch("src.vs_bridge.GATEWAY_TOKEN", "my-token"):
            from src.vs_bridge import _build_ws_headers
            h = _build_ws_headers()
            assert h["Authorization"] == "Bearer my-token"
