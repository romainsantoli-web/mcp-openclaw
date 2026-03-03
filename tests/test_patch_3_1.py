"""
Tests for the server 2026.3.1 patches — covers all new/modified tools.

Tests cover:
  - P0: systemRunPlan (advanced_security)
  - P0: realpath canonical (runtime_audit)
  - P1: health endpoints (reliability_probe)
  - P2: requireTopic Telegram DM (runtime_audit)
  - P2: ACPX version pin (acp_bridge)
  - P2: Claude 4.6 adaptive thinking (platform_audit)
  - P3: Discord thread lifecycle (reliability_probe)
  - P3: FIRM_SHELL env marker (config_migration)
"""

import asyncio
import json

import pytest

_run = asyncio.get_event_loop().run_until_complete


# ── P0: systemRunPlan in exec_approval_freeze_check ──────────────────────────

class TestSystemRunPlan:
    """P0: tools.exec with host=node must have systemRunPlan when approval active."""

    def test_system_run_plan_required(self, tmp_path):
        from src.advanced_security import firm_exec_approval_freeze_check

        cfg = {
            "tools": {
                "exec": {
                    "host": "node",
                    "approvalsMode": "always",
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_exec_approval_freeze_check(config_path=str(p)))
        findings_ids = [f["id"] for f in r.get("findings", [])]
        assert "system_run_plan_required" in findings_ids

    def test_system_run_plan_not_triggered_when_never(self, tmp_path):
        from src.advanced_security import firm_exec_approval_freeze_check

        cfg = {
            "tools": {
                "exec": {
                    "host": "node",
                    "approvalsMode": "never",
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_exec_approval_freeze_check(config_path=str(p)))
        findings_ids = [f["id"] for f in r.get("findings", [])]
        assert "system_run_plan_required" not in findings_ids

    def test_system_run_plan_docker_host_skip(self, tmp_path):
        from src.advanced_security import firm_exec_approval_freeze_check

        cfg = {
            "tools": {
                "exec": {
                    "host": "docker",
                    "approvalsMode": "always",
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_exec_approval_freeze_check(config_path=str(p)))
        findings_ids = [f["id"] for f in r.get("findings", [])]
        assert "system_run_plan_required" not in findings_ids


# ── P0: realpath canonical in nodes_commands_check ───────────────────────────

class TestRealpathCanonical:
    """P0: allowCommands entries must be canonical (realpath) paths."""

    def test_non_canonical_path_detected(self, tmp_path):
        from src.runtime_audit import firm_nodes_commands_check

        cfg = {
            "gateway": {
                "nodes": {
                    "allowCommands": ["tr", "node"]
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_nodes_commands_check(config_path=str(p)))
        findings_ids = [f["id"] for f in r.get("findings", [])]
        assert "allow_commands_non_canonical_path" in findings_ids

    def test_canonical_path_ok(self, tmp_path):
        from src.runtime_audit import firm_nodes_commands_check

        cfg = {
            "gateway": {
                "nodes": {
                    "allowCommands": ["/usr/bin/node", "/usr/local/bin/python3"]
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_nodes_commands_check(config_path=str(p)))
        findings_ids = [f["id"] for f in r.get("findings", [])]
        assert "allow_commands_non_canonical_path" not in findings_ids


# ── P1: health endpoints in gateway_probe ────────────────────────────────────

class TestHealthEndpoints:
    """P1: _check_health_endpoints helper produces correct structure."""

    def test_check_health_endpoints_unreachable(self):
        from src.reliability_probe import _check_health_endpoints

        r = _run(_check_health_endpoints("ws://127.0.0.1:19999"))
        assert isinstance(r, dict)
        assert r.get("all_ok") is False or r.get("all_ok") is True  # structure present
        assert "/health" in r or "all_ok" in r


# ── P2: requireTopic Telegram DM ─────────────────────────────────────────────

class TestRequireTopicTelegram:
    """P2: requireTopic check for Telegram DM channels (2026.3.1)."""

    def test_require_topic_missing(self, tmp_path):
        from src.runtime_audit import firm_dm_allowlist_check

        cfg = {
            "channels": {
                "telegram": {
                    "dmPolicy": "allowlist",
                    "allowFrom": ["user1"],
                    "direct": {}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_dm_allowlist_check(config_path=str(p)))
        findings_ids = [f["id"] for f in r.get("findings", [])]
        assert "telegram_require_topic_missing" in findings_ids

    def test_require_topic_true_empty_allowlist(self, tmp_path):
        from src.runtime_audit import firm_dm_allowlist_check

        cfg = {
            "channels": {
                "telegram": {
                    "dmPolicy": "allowlist",
                    "allowFrom": ["user1"],
                    "direct": {"requireTopic": True, "topicAllowlist": []}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_dm_allowlist_check(config_path=str(p)))
        findings_ids = [f["id"] for f in r.get("findings", [])]
        assert "telegram_topic_allowlist_empty" in findings_ids

    def test_require_topic_set_with_allowlist(self, tmp_path):
        from src.runtime_audit import firm_dm_allowlist_check

        cfg = {
            "channels": {
                "telegram": {
                    "dmPolicy": "pairing",
                    "direct": {"requireTopic": True, "topicAllowlist": [123, 456]}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_dm_allowlist_check(config_path=str(p)))
        findings_ids = [f["id"] for f in r.get("findings", [])]
        assert "telegram_require_topic_missing" not in findings_ids
        assert "telegram_topic_allowlist_empty" not in findings_ids


# ── P2: ACPX version pin check ──────────────────────────────────────────────

class TestAcpxVersionCheck:
    """P2: ACPX plugin version pin and streaming mode check."""

    def test_acpx_old_version_critical(self, tmp_path):
        from src.acp_bridge import firm_acpx_version_check

        cfg = {
            "plugins": {
                "acpx": {
                    "version": "0.1.12",
                    "streaming": {"mode": "full"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_acpx_version_check(config_path=str(p)))
        assert r["severity"] == "CRITICAL"
        assert any("acpx_version_too_old" == f["id"] for f in r["findings"])

    def test_acpx_correct_version(self, tmp_path):
        from src.acp_bridge import firm_acpx_version_check

        cfg = {
            "plugins": {
                "acpx": {
                    "version": "0.1.15",
                    "streaming": {"mode": "final_only"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_acpx_version_check(config_path=str(p)))
        assert r["ok"] is True
        assert r["severity"] == "OK"

    def test_acpx_unpinned_version(self, tmp_path):
        from src.acp_bridge import firm_acpx_version_check

        cfg = {
            "plugins": {
                "acpx": {
                    "streaming": {"mode": "final_only"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_acpx_version_check(config_path=str(p)))
        assert any("acpx_version_unpinned" == f["id"] for f in r["findings"])

    def test_acpx_wrong_streaming(self, tmp_path):
        from src.acp_bridge import firm_acpx_version_check

        cfg = {
            "plugins": {
                "acpx": {
                    "version": "0.1.15",
                    "streaming": {"mode": "incremental"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_acpx_version_check(config_path=str(p)))
        assert any("acpx_streaming_not_final_only" == f["id"] for f in r["findings"])

    def test_acpx_not_configured(self, tmp_path):
        from src.acp_bridge import firm_acpx_version_check

        cfg = {"plugins": {}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_acpx_version_check(config_path=str(p)))
        assert r["ok"] is True
        assert any("acpx_not_configured" == f["id"] for f in r["findings"])

    def test_acpx_config_not_found(self):
        from src.acp_bridge import firm_acpx_version_check

        r = _run(firm_acpx_version_check(config_path="/nonexistent/path/config.json"))
        assert r["ok"] is True  # INFO severity only


# ── P2: Claude 4.6 adaptive thinking ────────────────────────────────────────

class TestAdaptiveThinking:
    """P2: Claude 4.6 adaptive thinking configuration check."""

    def test_thinking_disabled_is_critical(self, tmp_path):
        from src.platform_audit import firm_adaptive_thinking_check

        cfg = {
            "agents": {
                "defaults": {
                    "model": "claude-4.6-sonnet",
                    "thinking": {"mode": "disabled"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = firm_adaptive_thinking_check(config_path=str(p))
        assert r["severity"] == "CRITICAL"
        assert any("claude46_thinking_disabled" == f["id"] for f in r["findings"])

    def test_thinking_low_is_high(self, tmp_path):
        from src.platform_audit import firm_adaptive_thinking_check

        cfg = {
            "agents": {
                "defaults": {
                    "model": "claude-opus-4.6",
                    "thinking": {"mode": "low"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = firm_adaptive_thinking_check(config_path=str(p))
        assert r["severity"] == "HIGH"

    def test_thinking_adaptive_ok(self, tmp_path):
        from src.platform_audit import firm_adaptive_thinking_check

        cfg = {
            "agents": {
                "defaults": {
                    "model": "claude-4.6-sonnet",
                    "thinking": {"mode": "adaptive"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = firm_adaptive_thinking_check(config_path=str(p))
        assert r["ok"] is True

    def test_thinking_no_mode_default_ok(self, tmp_path):
        from src.platform_audit import firm_adaptive_thinking_check

        cfg = {
            "agents": {
                "defaults": {
                    "model": "claude-4.6-haiku",
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = firm_adaptive_thinking_check(config_path=str(p))
        # INFO severity only — default adaptive applies
        assert r["ok"] is True

    def test_per_agent_override_detected(self, tmp_path):
        from src.platform_audit import firm_adaptive_thinking_check

        cfg = {
            "agents": {
                "defaults": {"model": "gpt-4o"},
                "researcher": {
                    "model": "claude-4.6-sonnet",
                    "thinking": {"mode": "disabled"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = firm_adaptive_thinking_check(config_path=str(p))
        assert r["severity"] == "CRITICAL"
        assert any("claude46_agent_researcher_thinking_disabled" == f["id"] for f in r["findings"])

    def test_non_claude46_ignored(self, tmp_path):
        from src.platform_audit import firm_adaptive_thinking_check

        cfg = {
            "agents": {
                "defaults": {
                    "model": "gpt-4o",
                    "thinking": {"mode": "disabled"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = firm_adaptive_thinking_check(config_path=str(p))
        assert r["ok"] is True
        assert r["severity"] == "OK"


# ── P3: Discord thread lifecycle ─────────────────────────────────────────────

class TestDiscordThreadLifecycle:
    """P3: Discord idle/maxAge hours check in channel_audit."""

    def test_discord_idle_hours_missing(self, tmp_path):
        from src.reliability_probe import firm_channel_audit

        pkg = {
            "dependencies": {"discord.js": "14.0.0"},
            "firm": {
                "channels": {
                    "discord": {"threads": {}}
                }
            }
        }
        readme = "# Bot\nDiscord integration."
        p = tmp_path / "package.json"
        p.write_text(json.dumps(pkg))
        r = tmp_path / "README.md"
        r.write_text(readme)
        result = _run(firm_channel_audit(str(p), str(r)))
        assert isinstance(result.get("discord_thread_lifecycle"), list)
        lifecycle = result["discord_thread_lifecycle"]
        findings_text = [f["finding"] for f in lifecycle]
        assert any("idleHours" in t for t in findings_text)

    def test_discord_max_age_missing(self, tmp_path):
        from src.reliability_probe import firm_channel_audit

        pkg = {
            "dependencies": {"discord.js": "14.0.0"},
            "firm": {
                "channels": {
                    "discord": {"threads": {"idleHours": 24}}
                }
            }
        }
        readme = "# Bot\nDiscord support."
        p = tmp_path / "package.json"
        p.write_text(json.dumps(pkg))
        r = tmp_path / "README.md"
        r.write_text(readme)
        result = _run(firm_channel_audit(str(p), str(r)))
        lifecycle = result.get("discord_thread_lifecycle", [])
        findings_text = [f["finding"] for f in lifecycle]
        assert any("maxAgeHours" in t for t in findings_text)


# ── P3: FIRM_SHELL env marker ───────────────────────────────────────────

class TestOpenclawShellMarker:
    """P3: FIRM_SHELL env marker check in shell_env_check."""

    def test_marker_missing(self, tmp_path):
        from src.config_migration import firm_shell_env_check

        cfg = {
            "agents": {
                "defaults": {
                    "env": {"PATH": "/usr/bin"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_shell_env_check(config_path=str(p)))
        findings_ids = [f["id"] for f in r.get("findings", [])]
        assert "firm_shell_marker_missing" in findings_ids

    def test_marker_present(self, tmp_path):
        from src.config_migration import firm_shell_env_check

        cfg = {
            "agents": {
                "defaults": {
                    "env": {"PATH": "/usr/bin", "FIRM_SHELL": "1"}
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        r = _run(firm_shell_env_check(config_path=str(p)))
        findings_ids = [f["id"] for f in r.get("findings", [])]
        assert "firm_shell_marker_missing" not in findings_ids


# ── Pydantic model tests ────────────────────────────────────────────────────

class TestPydanticModels:
    """Verify new Pydantic models are registered and validate inputs."""

    def test_acpx_model_registered(self):
        from src.models import TOOL_MODELS
        assert "firm_acpx_version_check" in TOOL_MODELS

    def test_adaptive_thinking_model_registered(self):
        from src.models import TOOL_MODELS
        assert "firm_adaptive_thinking_check" in TOOL_MODELS

    def test_gateway_probe_has_health_field(self):
        from src.models import GatewayProbeInput
        m = GatewayProbeInput(check_health_endpoints=False)
        assert m.check_health_endpoints is False

    def test_acpx_model_path_traversal_blocked(self):
        from src.models import AcpxVersionCheckInput
        with pytest.raises(Exception):
            AcpxVersionCheckInput(config_path="../../etc/passwd")

    def test_adaptive_model_valid(self):
        from src.models import AdaptiveThinkingCheckInput
        m = AdaptiveThinkingCheckInput(config_path="/tmp/test.json")
        assert m.config_path == "/tmp/test.json"
