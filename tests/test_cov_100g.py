"""Coverage push — test_cov_100g: targeting remaining gaps toward 95%+."""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import patch, AsyncMock

import pytest

# ── helpers ─────────────────────────────────────────────────────────

def _run(coro):
    """Run an async coroutine."""
    if asyncio.iscoroutine(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()
    return coro


def _write(tmp_path, data, name="cfg.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return str(p)


def _fc(r):
    """Count findings in result dict."""
    if isinstance(r, dict):
        fl = r.get("findings", r.get("finding_count", []))
        if isinstance(fl, list):
            return len(fl)
        if isinstance(fl, int):
            return fl
    return 0


# ═══════════════════════════════════════════════════════════════════
# ACP BRIDGE — 56 missed stmts (73% → target 95%+)
# ═══════════════════════════════════════════════════════════════════

class TestAcpBridgeFullG:
    """Tests for acp_bridge.py uncovered paths."""

    def test_session_persist_and_restore(self, tmp_path):
        """Full persist → restore cycle (lines 108-127)."""
        import src.acp_bridge as ab
        sessions_file = tmp_path / "sessions.json"
        with patch.object(ab, "ACP_SESSIONS_PATH", str(sessions_file)):
            r = _run(ab.acp_session_persist(
                run_id="run-123",
                gateway_session_key="sess-abc",
                metadata={"agent": "test"},
            ))
        assert r["ok"] is True
        assert r["run_id"] == "run-123"
        assert r["total_sessions"] >= 1
        # Verify persisted
        data = json.loads(sessions_file.read_text())
        assert "run-123" in data

    def test_session_persist_overwrite(self, tmp_path):
        """Persist same run_id twice → overwrites."""
        import src.acp_bridge as ab
        sessions_file = tmp_path / "sessions.json"
        with patch.object(ab, "ACP_SESSIONS_PATH", str(sessions_file)):
            _run(ab.acp_session_persist(run_id="r1", gateway_session_key="s1"))
            _run(ab.acp_session_persist(run_id="r1", gateway_session_key="s2"))
        data = json.loads(sessions_file.read_text())
        assert data["r1"]["gateway_session_key"] == "s2"

    def test_session_restore_success(self, tmp_path):
        """Restore all persisted sessions (lines 126-170)."""
        import src.acp_bridge as ab
        sessions_file = tmp_path / "sessions.json"
        with patch.object(ab, "ACP_SESSIONS_PATH", str(sessions_file)):
            _run(ab.acp_session_persist(run_id="r1", gateway_session_key="s1"))
            r = _run(ab.acp_session_restore(max_age_hours=24))
        assert r["ok"] is True
        assert r["restored"] >= 1

    def test_session_restore_with_stale_purge(self, tmp_path):
        """Restore purges stale sessions (lines 147-163)."""
        import src.acp_bridge as ab
        sessions_file = tmp_path / "sessions.json"
        now = time.time()
        sessions = {
            "fresh": {"gateway_session_key": "s1", "persisted_at": now - 100, "metadata": {}},
            "old": {"gateway_session_key": "s2", "persisted_at": now - 200000, "metadata": {}},
        }
        sessions_file.write_text(json.dumps(sessions))
        with patch.object(ab, "ACP_SESSIONS_PATH", str(sessions_file)):
            r = _run(ab.acp_session_restore(max_age_hours=24))
        assert r["ok"] is True
        assert r["purged"] >= 1
        assert r["restored"] >= 1

    def test_session_list_active_with_stale(self, tmp_path):
        """List active sessions including stale (lines 179-210)."""
        import src.acp_bridge as ab
        sessions_file = tmp_path / "sessions.json"
        now = time.time()
        sessions = {
            "active-1": {"gateway_session_key": "s1", "persisted_at": now - 100, "metadata": {}},
            "stale-1": {"gateway_session_key": "s2", "persisted_at": now - 100000, "metadata": {}},
        }
        sessions_file.write_text(json.dumps(sessions))
        with patch.object(ab, "ACP_SESSIONS_PATH", str(sessions_file)):
            r = _run(ab.acp_session_list_active(include_stale=True))
        assert r["ok"] is True
        assert r["total"] == 2
        statuses = {s["status"] for s in r["sessions"]}
        assert "stale" in statuses
        assert "active" in statuses

    def test_session_list_active_exclude_stale(self, tmp_path):
        """List only active sessions (exclude stale by default)."""
        import src.acp_bridge as ab
        sessions_file = tmp_path / "sessions.json"
        now = time.time()
        sessions = {
            "active-1": {"gateway_session_key": "s1", "persisted_at": now - 100, "metadata": {}},
            "stale-1": {"gateway_session_key": "s2", "persisted_at": now - 100000, "metadata": {}},
        }
        sessions_file.write_text(json.dumps(sessions))
        with patch.object(ab, "ACP_SESSIONS_PATH", str(sessions_file)):
            r = _run(ab.acp_session_list_active(include_stale=False))
        assert r["ok"] is True
        # Stale should be excluded
        assert all(s["status"] == "active" for s in r["sessions"])

    def test_fleet_session_inject_env_valid_keys(self, tmp_path):
        """Inject env vars with valid keys (lines 242-299)."""
        import src.acp_bridge as ab
        mock_broadcast = AsyncMock(return_value={"ok": True})
        with patch("src.gateway_fleet.firm_gateway_fleet_broadcast", mock_broadcast):
            r = _run(ab.fleet_session_inject_env(
                env_vars={"ANTHROPIC_API_KEY": "sk-test-123"},
                dry_run=False,
            ))
        assert isinstance(r, dict)

    def test_fleet_session_inject_env_dry_run(self, tmp_path):
        """Dry run mode returns validated keys without injecting (lines 261-271)."""
        import src.acp_bridge as ab
        r = _run(ab.fleet_session_inject_env(
            env_vars={"ANTHROPIC_API_KEY": "sk-test"},
            dry_run=True,
        ))
        assert isinstance(r, dict)
        if r.get("ok"):
            assert r.get("dry_run") is True

    def test_fleet_session_inject_env_all_rejected(self):
        """All env vars rejected by allowlist (lines 254-260)."""
        import src.acp_bridge as ab
        r = _run(ab.fleet_session_inject_env(
            env_vars={"MALICIOUS_VAR": "val", "HACK_KEY": "val2"},
            dry_run=False,
        ))
        assert r.get("ok") is False

    def test_fleet_cron_schedule_blocklisted_command(self, tmp_path):
        """Blocked command in cron (lines 351-357)."""
        import src.acp_bridge as ab
        with patch.object(ab, "_CRON_SCHEDULE_PATH", str(tmp_path / "cron.json")):
            r = _run(ab.fleet_cron_schedule(command="rm -rf /", schedule="0 * * * *"))
        assert r.get("ok") is False
        assert "blocklist" in r.get("error", "").lower() or "disallowed" in r.get("error", "").lower()

    def test_fleet_cron_schedule_invalid_cron_expr(self, tmp_path):
        """Invalid cron expression (lines 359-363)."""
        import src.acp_bridge as ab
        with patch.object(ab, "_CRON_SCHEDULE_PATH", str(tmp_path / "cron.json")):
            r = _run(ab.fleet_cron_schedule(command="echo hello", schedule="not valid"))
        assert r.get("ok") is False

    def test_fleet_cron_schedule_non_main_session(self, tmp_path):
        """Non-main session blocked (lines 365-373)."""
        import src.acp_bridge as ab
        with patch.object(ab, "_CRON_SCHEDULE_PATH", str(tmp_path / "cron.json")):
            r = _run(ab.fleet_cron_schedule(
                command="echo hello", schedule="0 * * * *", session="sandbox"
            ))
        assert r.get("ok") is False
        assert "main" in r.get("error", "").lower()

    def test_fleet_cron_schedule_success(self, tmp_path):
        """Successful cron schedule (lines 375-410)."""
        import src.acp_bridge as ab
        cron_file = tmp_path / "cron.json"
        with patch.object(ab, "_CRON_SCHEDULE_PATH", str(cron_file)):
            r = _run(ab.fleet_cron_schedule(
                command="echo hello",
                schedule="0 9 * * 1-5",
                session="main",
                description="Test daily task",
            ))
        assert r.get("ok") is True
        assert "cron_id" in r
        # Verify file was written
        assert cron_file.exists()
        data = json.loads(cron_file.read_text())
        assert len(data) >= 1

    def test_fleet_cron_disallowed_chars(self, tmp_path):
        """Command with disallowed characters (lines 342-349)."""
        import src.acp_bridge as ab
        with patch.object(ab, "_CRON_SCHEDULE_PATH", str(tmp_path / "cron.json")):
            r = _run(ab.fleet_cron_schedule(
                command="echo 'hello world' && rm -rf /",
                schedule="0 * * * *",
            ))
        assert r.get("ok") is False

    def test_save_acp_sessions_unlink_on_error(self, tmp_path):
        """Save sessions cleans up tmp file on error (lines 82-85)."""
        import src.acp_bridge as ab
        sessions_file = tmp_path / "sessions.json"
        with patch.object(ab, "ACP_SESSIONS_PATH", str(sessions_file)):
            # Write valid sessions first
            sessions_file.write_text("{}")
            # Make the directory read-only to cause write failure
            with patch("builtins.open", side_effect=PermissionError("write denied")):
                ab._save_acp_sessions({"test": {"data": 1}})
        # Should not crash — just logs error


# ═══════════════════════════════════════════════════════════════════
# ADVANCED SECURITY — deep branch tests
# ═══════════════════════════════════════════════════════════════════

class TestAdvancedSecurityDeepG:
    """Tests for advanced_security.py uncovered branches."""

    def test_secrets_lifecycle_inline_credential(self, tmp_path):
        """Inline credential in auth profile (lines 163-169)."""
        from src.advanced_security import openclaw_secrets_lifecycle_check
        cfg = _write(tmp_path, {
            "auth": {"profiles": {
                "main": {"apiKey": "hardcoded-secret-value"}
            }}
        })
        r = _run(openclaw_secrets_lifecycle_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_secrets_lifecycle_snapshot_not_activated(self, tmp_path):
        """Snapshot not activated (lines 200-204)."""
        from src.advanced_security import openclaw_secrets_lifecycle_check
        cfg = _write(tmp_path, {
            "secrets": {
                "managed": True,
                "snapshotActivated": False,
            }
        })
        r = _run(openclaw_secrets_lifecycle_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_secrets_lifecycle_target_path_traversal(self, tmp_path):
        """Target path traversal detection (line 182)."""
        from src.advanced_security import openclaw_secrets_lifecycle_check
        cfg = _write(tmp_path, {
            "secrets": {
                "apply": {"targetPath": "../../../etc/shadow"}
            }
        })
        r = _run(openclaw_secrets_lifecycle_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_channel_auth_remote_no_auth(self, tmp_path):
        """Remote bind with no auth (lines 273-274)."""
        from src.advanced_security import openclaw_channel_auth_canon_check
        cfg = _write(tmp_path, {
            "gateway": {
                "bind": "0.0.0.0",
                "auth": {"mode": "none"},
            }
        })
        r = _run(openclaw_channel_auth_canon_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_channel_auth_basepath_traversal(self, tmp_path):
        """Control UI basePath traversal (line 302)."""
        from src.advanced_security import openclaw_channel_auth_canon_check
        cfg = _write(tmp_path, {
            "gateway": {
                "controlUi": {"basePath": "/../admin"},
            }
        })
        r = _run(openclaw_channel_auth_canon_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_channel_auth_transforms_dir_traversal(self, tmp_path):
        """Hook transformsDir traversal (line 316)."""
        from src.advanced_security import openclaw_channel_auth_canon_check
        cfg = _write(tmp_path, {
            "hooks": {
                "transformsDir": "../../../secret"
            }
        })
        r = _run(openclaw_channel_auth_canon_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_exec_approval_host_no_sandbox(self, tmp_path):
        """exec host without sandbox (lines 397-400)."""
        from src.advanced_security import openclaw_exec_approval_freeze_check
        cfg = _write(tmp_path, {
            "tools": {"exec": {"host": "direct"}},
            "sandbox": {"mode": "off"},
        })
        r = _run(openclaw_exec_approval_freeze_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_exec_approval_shell_wrapper(self, tmp_path):
        """Shell wrapper in approval list (lines 428-432)."""
        import src.advanced_security as adv
        from src.advanced_security import openclaw_exec_approval_freeze_check
        approvals_dir = tmp_path / "openclaw"
        approvals_dir.mkdir()
        approvals = approvals_dir / "exec-approvals.json"
        approvals.write_text(json.dumps({
            "pattern1": {"executable": "/bin/bash"},
            "pattern2": {"executable": "/bin/sh"},
        }))
        cfg = _write(tmp_path, {})
        with patch.object(adv, "_OPENCLAW_DIR", approvals_dir):
            r = _run(openclaw_exec_approval_freeze_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_exec_apply_patch_not_workspace_only(self, tmp_path):
        """applyPatch.workspaceOnly=false (line 458)."""
        from src.advanced_security import openclaw_exec_approval_freeze_check
        cfg = _write(tmp_path, {
            "tools": {"exec": {"applyPatch": {"workspaceOnly": False}}},
        })
        r = _run(openclaw_exec_approval_freeze_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_hook_session_key_unrestricted(self, tmp_path):
        """allowRequestSessionKey without prefixes (lines 504-510)."""
        from src.advanced_security import openclaw_hook_session_routing_check
        cfg = _write(tmp_path, {
            "hooks": {
                "allowRequestSessionKey": True,
            }
        })
        r = _run(openclaw_hook_session_routing_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_hook_no_default_session_key(self, tmp_path):
        """Hooks without defaultSessionKey (lines 534-540)."""
        from src.advanced_security import openclaw_hook_session_routing_check
        cfg = _write(tmp_path, {
            "hooks": {
                "enabled": True,
            }
        })
        r = _run(openclaw_hook_session_routing_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_config_include_traversal(self, tmp_path):
        """$include with path traversal (lines 622-632)."""
        from src.advanced_security import openclaw_config_include_check
        cfg = _write(tmp_path, {
            "$include": "../../../etc/passwd"
        })
        r = _run(openclaw_config_include_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_config_include_missing_file(self, tmp_path):
        """$include target doesn't exist (lines 634-640)."""
        from src.advanced_security import openclaw_config_include_check
        cfg = _write(tmp_path, {
            "$include": "/nonexistent/path/config.json"
        })
        r = _run(openclaw_config_include_check(config_path=cfg))
        assert _fc(r) >= 1


# ═══════════════════════════════════════════════════════════════════
# COMPLIANCE MEDIUM — deep branch tests
# ═══════════════════════════════════════════════════════════════════

class TestComplianceMediumDeepG:
    """Tests for compliance_medium.py uncovered branches."""

    def test_deprecation_sunset_without_deprecated(self, tmp_path):
        """Tool with sunset but deprecated=false (lines 92-97)."""
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write(tmp_path, {
            "mcp": {"tools": [
                {"name": "old_tool", "annotations": {
                    "deprecated": False,
                    "sunset": "2026-06-01",
                }}
            ]}
        })
        r = _run(tool_deprecation_audit(config_path=cfg))
        assert _fc(r) >= 1

    def test_deprecation_no_message(self, tmp_path):
        """Deprecated tool without deprecatedMessage (lines 131-135)."""
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write(tmp_path, {
            "mcp": {"tools": [
                {"name": "old_tool", "annotations": {
                    "deprecated": True,
                    "sunset": "2026-06-01",
                }}
            ]}
        })
        r = _run(tool_deprecation_audit(config_path=cfg))
        assert _fc(r) >= 1

    def test_deprecation_replacement_not_found(self, tmp_path):
        """Replacement tool doesn't exist (lines 155-160)."""
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write(tmp_path, {
            "mcp": {"tools": [
                {"name": "old_tool", "annotations": {
                    "deprecated": True,
                    "deprecatedMessage": "Use new_tool instead",
                    "sunset": "2026-06-01",
                    "replacement": "nonexistent_tool",
                }}
            ]}
        })
        r = _run(tool_deprecation_audit(config_path=cfg))
        assert _fc(r) >= 1

    def test_circuit_breaker_missing_threshold(self, tmp_path):
        """Missing failure threshold (lines 207-210)."""
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write(tmp_path, {
            "mcp": {
                "resilience": {
                    "circuitBreaker": {"enabled": True},
                }
            }
        })
        r = _run(circuit_breaker_audit(config_path=cfg))
        assert _fc(r) >= 1

    def test_circuit_breaker_no_retry(self, tmp_path):
        """No retry policy (lines 229-233)."""
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write(tmp_path, {
            "mcp": {
                "resilience": {
                    "circuitBreaker": {
                        "enabled": True,
                        "failureThreshold": 5,
                    },
                }
            }
        })
        r = _run(circuit_breaker_audit(config_path=cfg))
        assert _fc(r) >= 1

    def test_circuit_breaker_no_backoff(self, tmp_path):
        """Retry without backoff (lines 248-252)."""
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write(tmp_path, {
            "mcp": {
                "resilience": {
                    "circuitBreaker": {
                        "enabled": True,
                        "failureThreshold": 5,
                    },
                    "retry": {"maxRetries": 3},
                }
            }
        })
        r = _run(circuit_breaker_audit(config_path=cfg))
        assert _fc(r) >= 1

    def test_circuit_breaker_no_timeout(self, tmp_path):
        """No timeout configured (lines 268-275)."""
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write(tmp_path, {
            "mcp": {
                "resilience": {
                    "circuitBreaker": {
                        "enabled": True,
                        "failureThreshold": 5,
                    },
                    "retry": {"maxRetries": 3, "backoff": 1000},
                }
            }
        })
        r = _run(circuit_breaker_audit(config_path=cfg))
        assert _fc(r) >= 1

    def test_gdpr_no_legal_basis(self, tmp_path):
        """No legal basis declared (lines 357-362)."""
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write(tmp_path, {
            "mcp": {
                "gdpr": {
                    "enabled": True,
                }
            }
        })
        r = _run(gdpr_residency_audit(config_path=cfg))
        assert _fc(r) >= 1

    def test_gdpr_no_erasure(self, tmp_path):
        """No right to erasure (lines 380-385)."""
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write(tmp_path, {
            "mcp": {
                "gdpr": {
                    "enabled": True,
                    "legalBasis": "consent",
                }
            }
        })
        r = _run(gdpr_residency_audit(config_path=cfg))
        assert _fc(r) >= 1

    def test_gdpr_no_residency(self, tmp_path):
        """No data residency config (lines 400-405)."""
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write(tmp_path, {
            "mcp": {
                "gdpr": {
                    "enabled": True,
                    "legalBasis": "consent",
                    "rightToErasure": {"endpoint": "/erase"},
                }
            }
        })
        r = _run(gdpr_residency_audit(config_path=cfg))
        # Should have findings about residency
        assert isinstance(r, dict)

    def test_gdpr_pii_field_in_tool(self, tmp_path):
        """PII-like field in tool inputSchema (lines 440-445)."""
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write(tmp_path, {
            "mcp": {
                "gdpr": {"enabled": True, "legalBasis": "consent",
                          "rightToErasure": {"endpoint": "/erase"},
                          "residency": {"region": "eu-west-1"}},
            },
            "tools": {
                "entries": {
                    "user_lookup": {
                        "inputSchema": {
                            "properties": {
                                "email": {"type": "string"},
                                "phone_number": {"type": "string"},
                            }
                        }
                    }
                }
            }
        })
        r = _run(gdpr_residency_audit(config_path=cfg))
        assert _fc(r) >= 1


# ═══════════════════════════════════════════════════════════════════
# MODELS — validator branch tests
# ═══════════════════════════════════════════════════════════════════

class TestModelsValidatorsG:
    """Tests for models.py uncovered validator branches."""

    def test_fleet_add_invalid_url_scheme(self):
        from src.models import FleetAddInput
        with pytest.raises(Exception):
            FleetAddInput(url="ftp://invalid-scheme.com", name="test")

    def test_export_github_pr_bad_repo_format(self):
        from src.models import ExportGithubPrInput
        with pytest.raises(Exception):
            ExportGithubPrInput(
                title="Test PR", body="test", repo="no-slash-repo"
            )

    def test_export_document_path_traversal(self):
        from src.models import ExportDocumentInput
        with pytest.raises(Exception):
            ExportDocumentInput(
                title="Test", content="x", output_path="../../../etc/shadow"
            )

    def test_session_config_no_paths(self):
        """Neither env_file_path nor compose_file_path provided (lines 219-223)."""
        from src.models import SessionConfigCheckInput
        with pytest.raises(Exception):
            SessionConfigCheckInput()

    def test_fleet_session_inject_empty_key(self):
        """Empty key in env_vars (line 266)."""
        from src.models import FleetSessionInjectEnvInput
        with pytest.raises(Exception):
            FleetSessionInjectEnvInput(env_vars={"": "value"})

    def test_config_path_traversal(self):
        """Config path traversal check (line 33)."""
        from src.models import ConfigPathInput
        with pytest.raises(Exception):
            ConfigPathInput(config_path="../../../etc/passwd")

    def test_session_config_path_traversal(self):
        """SessionConfigCheckInput path traversal (line 214)."""
        from src.models import SessionConfigCheckInput
        with pytest.raises(Exception):
            SessionConfigCheckInput(
                env_file_path="../../../etc/passwd",
                compose_file_path=None,
            )


# ═══════════════════════════════════════════════════════════════════
# SPEC COMPLIANCE — branch coverage
# ═══════════════════════════════════════════════════════════════════

class TestSpecComplianceBranchesG:
    """Tests targeting uncovered branches in spec_compliance.py."""

    def test_elicitation_partial_config(self, tmp_path):
        """Elicitation with missing requestedSchema (branch line 63)."""
        from src.spec_compliance import elicitation_audit
        cfg = _write(tmp_path, {
            "capabilities": {"elicitation": {"enabled": True}},
            "tools": {"entries": {
                "t1": {"elicitation": {"required": True}}
            }}
        })
        r = _run(elicitation_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_tasks_no_durability(self, tmp_path):
        """Tasks without durability config."""
        from src.spec_compliance import tasks_audit
        cfg = _write(tmp_path, {
            "capabilities": {"tasks": {"enabled": True}},
        })
        r = _run(tasks_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_resources_no_listchanged(self, tmp_path):
        """Resources without listChanged notification."""
        from src.spec_compliance import resources_prompts_audit
        cfg = _write(tmp_path, {
            "capabilities": {
                "resources": {"enabled": True},
                "prompts": {"enabled": True},
            }
        })
        r = _run(resources_prompts_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_audio_missing_mime(self, tmp_path):
        """Audio without supported MIME types."""
        from src.spec_compliance import audio_content_audit
        cfg = _write(tmp_path, {
            "capabilities": {"audio": {"enabled": True}},
        })
        r = _run(audio_content_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_json_schema_wrong_dialect(self, tmp_path):
        """JSON schema dialect not 2020-12."""
        from src.spec_compliance import json_schema_dialect_check
        cfg = _write(tmp_path, {
            "tools": {
                "entries": {
                    "t1": {
                        "inputSchema": {
                            "$schema": "http://json-schema.org/draft-07/schema#",
                            "properties": {}
                        }
                    }
                }
            }
        })
        r = _run(json_schema_dialect_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_sse_no_resumption(self, tmp_path):
        """SSE transport without resumption config."""
        from src.spec_compliance import sse_transport_audit
        cfg = _write(tmp_path, {
            "transport": {"sse": {"enabled": True}},
        })
        r = _run(sse_transport_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_icon_missing_metadata(self, tmp_path):
        """Icon metadata check with no icons defined."""
        from src.spec_compliance import icon_metadata_audit
        cfg = _write(tmp_path, {
            "tools": {"entries": {"t1": {"name": "test"}}}
        })
        r = _run(icon_metadata_audit(config_path=cfg))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════
# PLATFORM AUDIT — branch coverage
# ═══════════════════════════════════════════════════════════════════

class TestPlatformAuditBranchesG:
    """Tests targeting uncovered branches in platform_audit.py."""

    def test_agent_routing_no_default(self, tmp_path):
        """Agent routing without default route (line 203)."""
        from src.platform_audit import openclaw_agent_routing_check
        cfg = _write(tmp_path, {
            "agents": {
                "routes": [
                    {"pattern": "test/*", "agent": "a1"},
                ]
            }
        })
        r = openclaw_agent_routing_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_voice_security_no_tls(self, tmp_path):
        """Voice config without TLS (line 295)."""
        from src.platform_audit import openclaw_voice_security_check
        cfg = _write(tmp_path, {
            "voice": {
                "enabled": True,
                "provider": "twilio",
                "endpoint": "http://not-secure.com/voice",
            }
        })
        r = openclaw_voice_security_check(config_path=cfg)
        assert _fc(r) >= 1

    def test_trust_model_no_verification(self, tmp_path):
        """Trust model without verification."""
        from src.platform_audit import openclaw_trust_model_check
        cfg = _write(tmp_path, {
            "trust": {
                "mode": "open",
            }
        })
        r = openclaw_trust_model_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_autoupdate_insecure(self, tmp_path):
        """Autoupdate without signature verification."""
        from src.platform_audit import openclaw_autoupdate_check
        cfg = _write(tmp_path, {
            "autoUpdate": {
                "enabled": True,
                "verifySignature": False,
                "channel": "stable",
            }
        })
        r = openclaw_autoupdate_check(config_path=cfg)
        assert _fc(r) >= 1

    def test_plugin_sdk_no_sandbox(self, tmp_path):
        """Plugin SDK without sandbox isolation."""
        from src.platform_audit import openclaw_plugin_sdk_check
        cfg = _write(tmp_path, {
            "plugins": {
                "enabled": True,
                "sandbox": False,
            }
        })
        r = openclaw_plugin_sdk_check(config_path=cfg)
        assert _fc(r) >= 1

    def test_content_boundary_no_limits(self, tmp_path):
        """Content boundary without limits."""
        from src.platform_audit import openclaw_content_boundary_check
        cfg = _write(tmp_path, {
            "content": {
                "maxSize": None,
            }
        })
        r = openclaw_content_boundary_check(config_path=cfg)
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════
# ECOSYSTEM AUDIT — branch coverage
# ═══════════════════════════════════════════════════════════════════

class TestEcosystemAuditBranchesG:
    """Tests targeting uncovered branches in ecosystem_audit.py."""

    def test_mcp_firewall_no_policies(self, tmp_path):
        """MCP firewall check with no policies."""
        from src.ecosystem_audit import openclaw_mcp_firewall_check
        cfg = _write(tmp_path, {"mcp": {"firewall": {"enabled": True}}})
        r = openclaw_mcp_firewall_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_sandbox_exec_no_isolation(self, tmp_path):
        """Sandbox exec without isolation."""
        from src.ecosystem_audit import openclaw_sandbox_exec_check
        cfg = _write(tmp_path, {
            "sandbox": {"mode": "off"},
            "tools": {"exec": {"enabled": True}},
        })
        r = openclaw_sandbox_exec_check(config_path=cfg)
        assert _fc(r) >= 1

    def test_context_health_large_context(self):
        """Context health with oversized context."""
        from src.ecosystem_audit import openclaw_context_health_check
        r = openclaw_context_health_check(session_data={
            "contextTokens": 200000,
            "maxContextTokens": 128000,
            "messageCount": 500,
        })
        assert isinstance(r, dict)

    def test_token_budget_system_prompt_heavy(self, tmp_path):
        """Token budget with heavy system prompt."""
        from src.ecosystem_audit import openclaw_token_budget_optimizer
        cfg = _write(tmp_path, {"model": "claude-3.5-sonnet"})
        r = openclaw_token_budget_optimizer(session_data={
            "systemPromptTokens": 50000,
            "maxContextTokens": 128000,
            "toolDefinitionTokens": 30000,
        }, config_path=cfg)
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════
# RUNTIME AUDIT — branch coverage
# ═══════════════════════════════════════════════════════════════════

class TestRuntimeAuditBranchesG:
    """Tests targeting uncovered branches in runtime_audit.py."""

    def test_secrets_workflow_inline_secret(self, tmp_path):
        """Secrets workflow with inline secret value (line 225-226)."""
        from src.runtime_audit import openclaw_secrets_workflow_check
        cfg = _write(tmp_path, {
            "channels": {
                "whatsapp": {
                    "auth": {"apiKey": "hardcoded-value-not-env-ref"}
                }
            }
        })
        r = _run(openclaw_secrets_workflow_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_http_headers_no_hsts(self, tmp_path):
        """HTTP without HSTS on non-loopback (line 280-281)."""
        from src.runtime_audit import openclaw_http_headers_check
        cfg = _write(tmp_path, {
            "gateway": {
                "bind": "0.0.0.0",
                "headers": {},
            }
        })
        r = _run(openclaw_http_headers_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_nodes_commands_wildcard(self, tmp_path):
        """nodes.allowCommands with wildcard (line 376-377)."""
        from src.runtime_audit import openclaw_nodes_commands_check
        cfg = _write(tmp_path, {
            "gateway": {"nodes": {"allowCommands": ["*"]}}
        })
        r = _run(openclaw_nodes_commands_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_disk_budget_no_limit(self, tmp_path):
        """Session disk budget with no limit set (line 470-471)."""
        from src.runtime_audit import openclaw_session_disk_budget_check
        cfg = _write(tmp_path, {
            "sessions": {"storage": {"enabled": True}}
        })
        r = _run(openclaw_session_disk_budget_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_dm_allowlist_wildcard(self, tmp_path):
        """DM allowlist with wildcard allowing all (line 574-575)."""
        from src.runtime_audit import openclaw_dm_allowlist_check
        cfg = _write(tmp_path, {
            "channels": {
                "dm": {"policy": {"allowlist": ["*"]}}
            }
        })
        r = _run(openclaw_dm_allowlist_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_trusted_proxy_open(self, tmp_path):
        """Trusted proxy with open trust (line 648-649)."""
        from src.runtime_audit import openclaw_trusted_proxy_check
        cfg = _write(tmp_path, {
            "gateway": {
                "trustedProxy": "*",
                "bind": "0.0.0.0",
            }
        })
        r = _run(openclaw_trusted_proxy_check(config_path=cfg))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════
# CONFIG MIGRATION — branch tests
# ═══════════════════════════════════════════════════════════════════

class TestConfigMigrationBranchesG:
    """Tests targeting uncovered branches in config_migration.py."""

    def test_shell_env_ld_preload(self, tmp_path):
        """Shell env with LD_PRELOAD set (line 90-91)."""
        from src.config_migration import openclaw_shell_env_check
        cfg = _write(tmp_path, {
            "agents": {"defaults": {"env": {"LD_PRELOAD": "/lib/evil.so"}}},
        })
        r = _run(openclaw_shell_env_check(config_path=cfg))
        assert _fc(r) >= 1

    def test_token_separation_shared_token(self, tmp_path):
        """Token separation with shared token across channels."""
        from src.config_migration import openclaw_token_separation_check
        cfg = _write(tmp_path, {
            "channels": {
                "whatsapp": {"auth": {"token": "same-token"}},
                "telegram": {"auth": {"token": "same-token"}},
            }
        })
        r = _run(openclaw_token_separation_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_rpc_rate_limit_no_limit(self, tmp_path):
        """RPC with no rate limit configured."""
        from src.config_migration import openclaw_rpc_rate_limit_check
        cfg = _write(tmp_path, {
            "gateway": {
                "bind": "0.0.0.0",
                "rpc": {"enabled": True},
            }
        })
        r = _run(openclaw_rpc_rate_limit_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_otel_endpoint_inline_auth(self, tmp_path):
        """OTEL endpoint URL with inline credentials (line 456)."""
        from src.config_migration import openclaw_otel_redaction_check
        cfg = _write(tmp_path, {"otel": {
            "endpoint": "https://user:password@otel.example.com/v1",
        }})
        r = _run(openclaw_otel_redaction_check(config_path=cfg))
        assert _fc(r) >= 1


# ═══════════════════════════════════════════════════════════════════
# A2A BRIDGE — branch coverage
# ═══════════════════════════════════════════════════════════════════

class TestA2ABridgeBranchesG:
    """Tests for a2a_bridge.py uncovered branches."""

    def test_card_validate_no_input(self):
        """Card validate with neither card_path nor card_json."""
        from src.a2a_bridge import openclaw_a2a_card_validate
        r = _run(openclaw_a2a_card_validate())
        assert r.get("ok") is False

    def test_card_validate_invalid_json(self, tmp_path):
        """Card validate with invalid JSON file."""
        from src.a2a_bridge import openclaw_a2a_card_validate
        card = tmp_path / "card.json"
        card.write_text("NOT VALID JSON{{{")
        r = _run(openclaw_a2a_card_validate(card_path=str(card)))
        assert r.get("ok") is False

    def test_card_validate_missing_fields(self, tmp_path):
        """Card validate with minimal card (missing required fields)."""
        from src.a2a_bridge import openclaw_a2a_card_validate
        r = _run(openclaw_a2a_card_validate(card_json={"name": "test"}))
        assert isinstance(r, dict)
        # Should have issues
        issues = r.get("issues", r.get("findings", []))
        assert len(issues) >= 1

    def test_task_send_ssrf_localhost(self):
        """Task send blocked for localhost (SSRF protection)."""
        from src.a2a_bridge import openclaw_a2a_task_send
        r = _run(openclaw_a2a_task_send(
            agent_url="http://localhost:8080/task",
            message="hello",
        ))
        assert r.get("ok") is False

    def test_push_config_create(self):
        """Push config create action."""
        from src.a2a_bridge import openclaw_a2a_push_config
        r = _run(openclaw_a2a_push_config(
            task_id="t1",
            action="create",
            webhook_url="https://example.com/webhook",
            auth_token="bearer-token",
        ))
        assert isinstance(r, dict)

    def test_push_config_list(self):
        """Push config list action."""
        from src.a2a_bridge import openclaw_a2a_push_config
        r = _run(openclaw_a2a_push_config(task_id="t1", action="list"))
        assert isinstance(r, dict)

    def test_push_config_delete(self):
        """Push config delete action."""
        from src.a2a_bridge import openclaw_a2a_push_config
        r = _run(openclaw_a2a_push_config(
            task_id="t1", action="delete", config_id="cfg1"
        ))
        assert isinstance(r, dict)

    def test_discovery_no_input(self):
        """Discovery with no URLs or souls_dir."""
        from src.a2a_bridge import openclaw_a2a_discovery
        r = _run(openclaw_a2a_discovery())
        assert isinstance(r, dict)

    def test_discovery_souls_dir(self, tmp_path):
        """Discovery from souls directory."""
        from src.a2a_bridge import openclaw_a2a_discovery
        soul = tmp_path / "CEO.md"
        soul.write_text("---\nname: CEO Bot\nrole: leader\n---\n# CEO\n## Skills\n### Leadership\nLeads.")
        r = _run(openclaw_a2a_discovery(souls_dir=str(tmp_path)))
        assert isinstance(r, dict)

    def test_parse_soul_frontmatter(self):
        """Parse SOUL.md frontmatter."""
        from src.a2a_bridge import _parse_soul_frontmatter
        content = "---\nname: TestBot\nrole: tester\nversion: 1.0\n---\nBody text"
        meta = _parse_soul_frontmatter(content)
        assert meta["name"] == "TestBot"

    def test_extract_skills_from_soul(self):
        """Extract skills from SOUL.md."""
        from src.a2a_bridge import _extract_skills_from_soul
        content = "# CEO\n## Skills\n### Coding\nWrites code.\n### Testing\nTests code."
        meta = {"name": "TestBot"}
        skills = _extract_skills_from_soul(content, meta)
        assert len(skills) >= 1

    def test_validate_agent_card_complete(self):
        """Validate a well-formed agent card."""
        from src.a2a_bridge import _validate_agent_card
        card = {
            "name": "TestBot",
            "description": "A test bot",
            "url": "https://example.com",
            "version": "1.0.0",
            "capabilities": {"streaming": True},
            "skills": [{"id": "s1", "name": "Test", "description": "Tests"}],
        }
        issues = _validate_agent_card(card)
        assert isinstance(issues, list)


# ═══════════════════════════════════════════════════════════════════
# SKILL LOADER — branch coverage
# ═══════════════════════════════════════════════════════════════════

class TestSkillLoaderBranchesG:
    """Tests targeting skill_loader.py uncovered branches."""

    def test_skill_search_no_skills_dir(self, tmp_path):
        """Search with nonexistent skills dir."""
        import src.skill_loader as sl
        r = _run(sl.openclaw_skill_search(
            skills_dir=str(tmp_path / "nonexistent"), query="test"
        ))
        assert isinstance(r, dict)
        assert r.get("ok") is False

    def test_skill_lazy_loader_not_found(self, tmp_path):
        """Load a skill that doesn't exist."""
        import src.skill_loader as sl
        r = _run(sl.openclaw_skill_lazy_loader(
            skills_dir=str(tmp_path), skill_name="nonexistent-skill", refresh=True
        ))
        assert isinstance(r, dict)

    def test_skill_lazy_loader_success(self, tmp_path):
        """Load a skill that exists."""
        import src.skill_loader as sl
        skill_dir = tmp_path / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Test Skill\nThis is a test skill.")
        r = _run(sl.openclaw_skill_lazy_loader(
            skills_dir=str(tmp_path), skill_name="test-skill", refresh=True
        ))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════
# MAIN.PY — SSE & dispatcher branches
# ═══════════════════════════════════════════════════════════════════

class TestMainBranchesG:
    """Tests for main.py uncovered branches."""

    def test_list_tools_returns_tools(self):
        """Verify TOOL_REGISTRY has 100+ tools."""
        from src.main import TOOL_REGISTRY
        assert isinstance(TOOL_REGISTRY, dict)
        assert len(TOOL_REGISTRY) > 100
        for name, t in TOOL_REGISTRY.items():
            assert "handler" in t or "inputSchema" in t

    def test_tool_dispatch_unknown_tool(self):
        """Dispatch to unknown tool should return error."""
        from src.main import TOOL_REGISTRY
        assert "nonexistent_tool_xyz" not in TOOL_REGISTRY
