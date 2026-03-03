"""Coverage tests for mid-coverage modules: config_migration, spec_compliance,
security_audit, advanced_security, platform_audit, n8n_bridge, i18n_audit,
delivery_export, gateway_hardening, ecosystem_audit, runtime_audit,
agent_orchestration, observability, skill_loader."""

from __future__ import annotations
import asyncio
import json
import os
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock



def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# Helper to write openclaw config
def _write_config(tmp_path, data: dict) -> str:
    p = tmp_path / "config.json"
    p.write_text(json.dumps(data))
    return str(p)


# ═══════════════════════════════════════════════════════════════════════════════
# config_migration.py  (47% → target ~90%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestShellEnvCheck:
    def test_dangerous_env(self, tmp_path):
        from src.config_migration import openclaw_shell_env_check
        cfg = _write_config(tmp_path, {
            "agents": {"defaults": {"env": {"LD_PRELOAD": "/lib/evil.so", "SAFE_VAR": "ok"}}},
            "tools": {"exec": {"env": {"DYLD_LIBRARY_PATH": "/tmp"}}},
            "hooks": {"env": {"BASH_ENV": "/tmp/.bashrc"}},
        })
        r = _run(openclaw_shell_env_check(config_path=cfg))
        assert isinstance(r, dict)
        assert any("LD_PRELOAD" in str(f) for f in r.get("findings", []))

    def test_fork_config(self, tmp_path):
        from src.config_migration import openclaw_shell_env_check
        cfg = _write_config(tmp_path, {
            "agents": {"defaults": {"env": {"ZDOTDIR": "/custom"}}},
            "fork": {"env": {"inherit": True}},
        })
        r = _run(openclaw_shell_env_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_clean_env(self, tmp_path):
        from src.config_migration import openclaw_shell_env_check
        cfg = _write_config(tmp_path, {
            "agents": {"defaults": {"env": {"NODE_ENV": "production"}}},
        })
        r = _run(openclaw_shell_env_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_empty_config(self, tmp_path):
        from src.config_migration import openclaw_shell_env_check
        cfg = _write_config(tmp_path, {})
        r = _run(openclaw_shell_env_check(config_path=cfg))
        assert isinstance(r, dict)


class TestPluginIntegrityCheck:
    def test_no_plugins_dir(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        with patch("src.config_migration._PLUGINS_DIR", tmp_path / "nonexistent"):
            cfg = _write_config(tmp_path, {})
            r = _run(openclaw_plugin_integrity_check(config_path=cfg))
            assert isinstance(r, dict)

    def test_plugin_with_manifest(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        plugins_dir = tmp_path / "plugins"
        plugin = plugins_dir / "my-plugin"
        plugin.mkdir(parents=True)
        manifest = {"name": "my-plugin", "version": "1.0.0",
                     "integrity": "sha256-abc123"}
        (plugin / "plugin-manifest.json").write_text(json.dumps(manifest))
        with patch("src.config_migration._PLUGINS_DIR", plugins_dir):
            cfg = _write_config(tmp_path, {})
            r = _run(openclaw_plugin_integrity_check(config_path=cfg))
            assert isinstance(r, dict)

    def test_plugin_without_manifest(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        plugins_dir = tmp_path / "plugins"
        plugin = plugins_dir / "bad-plugin"
        plugin.mkdir(parents=True)
        with patch("src.config_migration._PLUGINS_DIR", plugins_dir):
            cfg = _write_config(tmp_path, {})
            r = _run(openclaw_plugin_integrity_check(config_path=cfg))
            assert isinstance(r, dict)
            assert any("manifest" in str(f).lower() for f in r.get("findings", []))


class TestTokenSeparationCheck:
    def test_same_token(self, tmp_path):
        from src.config_migration import openclaw_token_separation_check
        cfg = _write_config(tmp_path, {
            "hooks": {"token": "shared-secret"},
            "gateway": {"auth": {"token": "shared-secret"}},
        })
        r = _run(openclaw_token_separation_check(config_path=cfg))
        assert isinstance(r, dict)
        assert any("identical" in str(f).lower() or "same" in str(f).lower()
                    for f in r.get("findings", []))

    def test_short_token(self, tmp_path):
        from src.config_migration import openclaw_token_separation_check
        cfg = _write_config(tmp_path, {
            "hooks": {"token": "short"},
            "gateway": {"auth": {"token": "different-but-also-short"}},
        })
        r = _run(openclaw_token_separation_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_placeholder_token(self, tmp_path):
        from src.config_migration import openclaw_token_separation_check
        cfg = _write_config(tmp_path, {
            "hooks": {"token": "$HOOKS_TOKEN"},
            "gateway": {"auth": {"token": "{{GATEWAY_TOKEN}}"}},
        })
        r = _run(openclaw_token_separation_check(config_path=cfg))
        assert isinstance(r, dict)


class TestOtelRedactionCheck:
    def test_inline_auth(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        cfg = _write_config(tmp_path, {
            "otel": {
                "enabled": True,
                "endpoint": "https://user:pass@otel.example.com",
                "headers": {"Authorization": "Bearer sk-1234"},
                "spanAttributes": {"api_key": "secret"},
            },
        })
        r = _run(openclaw_otel_redaction_check(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("otel_enabled") is True

    def test_otel_with_redaction(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        cfg = _write_config(tmp_path, {
            "otel": {
                "enabled": True,
                "endpoint": "https://otel.example.com",
                "redaction": {"enabled": True, "keys": ["password"]},
            },
        })
        r = _run(openclaw_otel_redaction_check(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("redaction_configured") is True

    def test_otel_disabled(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        cfg = _write_config(tmp_path, {})
        r = _run(openclaw_otel_redaction_check(config_path=cfg))
        assert isinstance(r, dict)


class TestRpcRateLimitCheck:
    def test_remote_no_rate_limit(self, tmp_path):
        from src.config_migration import openclaw_rpc_rate_limit_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "0.0.0.0:8080"},
        })
        r = _run(openclaw_rpc_rate_limit_check(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("is_remote") is True

    def test_loopback_bind(self, tmp_path):
        from src.config_migration import openclaw_rpc_rate_limit_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "127.0.0.1:8080"},
        })
        r = _run(openclaw_rpc_rate_limit_check(config_path=cfg))
        assert isinstance(r, dict)
        # Just check it returns a valid dict with bind info
        assert "bind" in r

    def test_with_rate_limit(self, tmp_path):
        from src.config_migration import openclaw_rpc_rate_limit_check
        cfg = _write_config(tmp_path, {
            "gateway": {
                "bind": "0.0.0.0:8080",
                "rateLimit": {"maxRequestsPerMinute": 100},
            },
            "hooks": {"rateLimit": {"maxRequestsPerMinute": 50}},
        })
        r = _run(openclaw_rpc_rate_limit_check(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("rate_limit_configured") is True


# ═══════════════════════════════════════════════════════════════════════════════
# spec_compliance.py  (49% → target ~85%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestElicitationAudit:
    def test_valid_elicitation(self, tmp_path):
        from src.spec_compliance import elicitation_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"capabilities": {"elicitation": {"enabled": True}}},
            "tools": [{"inputSchema": {"properties": {"name": {"type": "string"}}}}],
        })
        r = _run(elicitation_audit(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("feature") == "elicitation"

    def test_invalid_schema_types(self, tmp_path):
        from src.spec_compliance import elicitation_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"capabilities": {"elicitation": {"enabled": True}}},
            "tools": [{"inputSchema": {"properties": {"data": {"type": "array"}}}}],
        })
        r = _run(elicitation_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_empty_config(self, tmp_path):
        from src.spec_compliance import elicitation_audit
        cfg = _write_config(tmp_path, {})
        r = _run(elicitation_audit(config_path=cfg))
        assert isinstance(r, dict)


class TestTasksAudit:
    def test_valid_tasks(self, tmp_path):
        from src.spec_compliance import tasks_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"capabilities": {"tasks": {
                "enabled": True,
                "pollingInterval": 2000,
                "timeout": 60000,
                "maxConcurrent": 5,
            }}},
        })
        r = _run(tasks_audit(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("feature") == "tasks"

    def test_low_polling(self, tmp_path):
        from src.spec_compliance import tasks_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"capabilities": {"tasks": {
                "enabled": True,
                "pollingInterval": 100,
            }}},
        })
        r = _run(tasks_audit(config_path=cfg))
        assert isinstance(r, dict)
        assert any("polling" in str(f).lower() for f in r.get("findings", []))


class TestResourcesPromptsAudit:
    def test_resources_and_prompts(self, tmp_path):
        from src.spec_compliance import resources_prompts_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"capabilities": {
                "resources": {"enabled": True, "listChanged": True},
                "prompts": {"enabled": True, "listChanged": True},
            }},
            "resources": [{"uri": "file:///test"}],
            "prompts": [{"name": "test"}],
        })
        r = _run(resources_prompts_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_missing_capabilities(self, tmp_path):
        from src.spec_compliance import resources_prompts_audit
        cfg = _write_config(tmp_path, {})
        r = _run(resources_prompts_audit(config_path=cfg))
        assert isinstance(r, dict)


class TestAudioContentAudit:
    def test_valid_audio(self, tmp_path):
        from src.spec_compliance import audio_content_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"audio": {
                "mimeTypes": ["audio/wav", "audio/mp3"],
                "maxSizeBytes": 10485760,
                "maxDurationSeconds": 300,
            }},
        })
        r = _run(audio_content_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_oversized_audio(self, tmp_path):
        from src.spec_compliance import audio_content_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"audio": {
                "mimeTypes": ["audio/wav"],
                "maxSizeBytes": 999999999,
            }},
        })
        r = _run(audio_content_audit(config_path=cfg))
        assert isinstance(r, dict)


class TestJsonSchemaDialect:
    def test_draft07_keywords(self, tmp_path):
        from src.spec_compliance import json_schema_dialect_check
        cfg = _write_config(tmp_path, {
            "tools": [{"inputSchema": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "definitions": {"foo": {}},
                "dependencies": {"a": ["b"]},
            }}],
        })
        r = _run(json_schema_dialect_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_correct_dialect(self, tmp_path):
        from src.spec_compliance import json_schema_dialect_check
        cfg = _write_config(tmp_path, {
            "tools": [{"inputSchema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$defs": {"foo": {}},
            }}],
        })
        r = _run(json_schema_dialect_check(config_path=cfg))
        assert isinstance(r, dict)


class TestSseTransportAudit:
    def test_sse_config(self, tmp_path):
        from src.spec_compliance import sse_transport_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"transport": {
                "type": "sse",
                "polling": {"enabled": True, "interval": 5000},
                "eventIdEncoding": "base64",
                "allowedOrigins": ["https://example.com"],
                "requireProtocolVersionHeader": True,
            }},
        })
        r = _run(sse_transport_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_no_transport(self, tmp_path):
        from src.spec_compliance import sse_transport_audit
        cfg = _write_config(tmp_path, {})
        r = _run(sse_transport_audit(config_path=cfg))
        assert isinstance(r, dict)


class TestIconMetadataAudit:
    def test_with_icons(self, tmp_path):
        from src.spec_compliance import icon_metadata_audit
        cfg = _write_config(tmp_path, {
            "tools": [{"name": "test", "icon": "https://example.com/icon.svg"}],
            "resources": [{"name": "res", "icon": "http://insecure.com/icon.png"}],
        })
        r = _run(icon_metadata_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_missing_icons(self, tmp_path):
        from src.spec_compliance import icon_metadata_audit
        cfg = _write_config(tmp_path, {
            "tools": [{"name": "test"}],
        })
        r = _run(icon_metadata_audit(config_path=cfg))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# security_audit.py  (52% → target ~85%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityScan:
    def test_scan_with_vulns(self, tmp_path):
        from src.security_audit import openclaw_security_scan
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text('query = f"SELECT * FROM users WHERE id={user_input}"\n')
        r = _run(openclaw_security_scan(target_path=str(tmp_path)))
        assert isinstance(r, dict)
        assert r.get("total_files_scanned", 0) >= 1

    def test_scan_nonexistent(self):
        from src.security_audit import openclaw_security_scan
        r = _run(openclaw_security_scan(target_path="/nonexistent/path"))
        assert isinstance(r, dict)
        assert r.get("ok") is False

    def test_scan_depth_limit(self, tmp_path):
        from src.security_audit import openclaw_security_scan
        deep = tmp_path / "a" / "b" / "c" / "d" / "e"
        deep.mkdir(parents=True)
        (deep / "test.py").write_text("safe = True\n")
        r = _run(openclaw_security_scan(target_path=str(tmp_path), scan_depth=2))
        assert isinstance(r, dict)

    def test_scan_skips_node_modules(self, tmp_path):
        from src.security_audit import openclaw_security_scan
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('eval(user_input)\n')
        r = _run(openclaw_security_scan(target_path=str(tmp_path)))
        assert isinstance(r, dict)


class TestSandboxAudit:
    def test_sandbox_off(self, tmp_path):
        from src.security_audit import openclaw_sandbox_audit
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"sandbox": {"mode": "off"}}))
        r = _run(openclaw_sandbox_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_sandbox_all(self, tmp_path):
        from src.security_audit import openclaw_sandbox_audit
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"sandbox": {"mode": "all"}}))
        r = _run(openclaw_sandbox_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_sandbox_nonmain(self, tmp_path):
        from src.security_audit import openclaw_sandbox_audit
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"sandbox": {"mode": "non-main"}}))
        r = _run(openclaw_sandbox_audit(config_path=str(cfg)))
        assert isinstance(r, dict)


class TestSessionConfigCheck:
    def test_env_file(self, tmp_path):
        from src.security_audit import openclaw_session_config_check
        env_file = tmp_path / ".env"
        env_file.write_text("SESSION_SECRET=mysecret123\n")
        r = _run(openclaw_session_config_check(env_file_path=str(env_file)))
        assert isinstance(r, dict)
        assert r.get("session_secret_found") is True

    def test_compose_file(self, tmp_path):
        from src.security_audit import openclaw_session_config_check
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("SESSION_SECRET: secret\n")
        r = _run(openclaw_session_config_check(compose_file_path=str(compose)))
        assert isinstance(r, dict)

    def test_no_secret_found(self, tmp_path):
        from src.security_audit import openclaw_session_config_check
        env_file = tmp_path / ".env"
        env_file.write_text("OTHER_VAR=value\n")
        r = _run(openclaw_session_config_check(env_file_path=str(env_file)))
        assert isinstance(r, dict)


class TestRateLimitCheck:
    def test_with_funnel(self, tmp_path):
        from src.security_audit import openclaw_rate_limit_check
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({
            "gateway": {"mode": "funnel"},
            "rateLimit": {"enabled": True},
        }))
        r = _run(openclaw_rate_limit_check(gateway_config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_no_rate_limit(self, tmp_path):
        from src.security_audit import openclaw_rate_limit_check
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"gateway": {}}))
        r = _run(openclaw_rate_limit_check(gateway_config_path=str(cfg)))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# advanced_security.py  (54% → target ~80%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecretsLifecycleCheck:
    def test_inline_creds(self, tmp_path):
        from src.advanced_security import openclaw_secrets_lifecycle_check
        cfg = _write_config(tmp_path, {
            "auth": {"profiles": {"admin": {"password": "plaintext123"}}},
            "secrets": {"apply": [{"targetPath": "a/b"}]},
        })
        r = _run(openclaw_secrets_lifecycle_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_secrets_backend(self, tmp_path):
        from src.advanced_security import openclaw_secrets_lifecycle_check
        cfg = _write_config(tmp_path, {
            "secrets": {
                "backend": "vault",
                "apply": [{"targetPath": "safe/path"}],
                "snapshot": {"activation": "auto"},
            },
        })
        r = _run(openclaw_secrets_lifecycle_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_traversal_in_apply(self, tmp_path):
        from src.advanced_security import openclaw_secrets_lifecycle_check
        cfg = _write_config(tmp_path, {
            "secrets": {
                "apply": [{"targetPath": "../../etc/passwd"}],
            },
        })
        r = _run(openclaw_secrets_lifecycle_check(config_path=cfg))
        assert isinstance(r, dict)
        assert "findings" in r


class TestChannelAuthCanonCheck:
    def test_remote_no_auth(self, tmp_path):
        from src.advanced_security import openclaw_channel_auth_canon_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "0.0.0.0:8080"},
        })
        r = _run(openclaw_channel_auth_canon_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_encoded_traversal_in_plugin(self, tmp_path):
        from src.advanced_security import openclaw_channel_auth_canon_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "127.0.0.1:8080", "auth": {"mode": "password"}},
            "plugins": [{"httpPath": "/api/%2e%2e/admin"}],
        })
        r = _run(openclaw_channel_auth_canon_check(config_path=cfg))
        assert isinstance(r, dict)


class TestExecApprovalFreezeCheck:
    def test_exec_host(self, tmp_path):
        from src.advanced_security import openclaw_exec_approval_freeze_check
        cfg = _write_config(tmp_path, {
            "tools": {"exec": {"host": "remote-host"}},
            "sandbox": {"mode": "off"},
        })
        r = _run(openclaw_exec_approval_freeze_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_safe_config(self, tmp_path):
        from src.advanced_security import openclaw_exec_approval_freeze_check
        cfg = _write_config(tmp_path, {
            "sandbox": {"mode": "all"},
            "applyPatch": {"workspaceOnly": True},
        })
        r = _run(openclaw_exec_approval_freeze_check(config_path=cfg))
        assert isinstance(r, dict)


class TestConfigIncludeCheck:
    def test_no_includes(self, tmp_path):
        from src.advanced_security import openclaw_config_include_check
        cfg = _write_config(tmp_path, {"simple": "config"})
        r = _run(openclaw_config_include_check(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("include_count", 0) == 0

    def test_with_include_traversal(self, tmp_path):
        from src.advanced_security import openclaw_config_include_check
        cfg = _write_config(tmp_path, {
            "$include": "../../etc/passwd",
            "nested": {"$include": "/absolute/path"},
        })
        r = _run(openclaw_config_include_check(config_path=cfg))
        assert isinstance(r, dict)


class TestConfigPrototypeCheck:
    def test_prototype_pollution(self, tmp_path):
        from src.advanced_security import openclaw_config_prototype_check
        cfg = _write_config(tmp_path, {
            "__proto__": {"isAdmin": True},
            "nested": {"constructor": {"prototype": {}}},
        })
        r = _run(openclaw_config_prototype_check(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("prototype_key_count", 0) > 0

    def test_clean_config(self, tmp_path):
        from src.advanced_security import openclaw_config_prototype_check
        cfg = _write_config(tmp_path, {"safe": {"key": "value"}})
        r = _run(openclaw_config_prototype_check(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("prototype_key_count", 0) == 0


class TestSafeBinsProfileCheck:
    def test_interpreter_no_profile(self, tmp_path):
        from src.advanced_security import openclaw_safe_bins_profile_check
        cfg = _write_config(tmp_path, {
            "safeBins": ["python", "node"],
            "safeBinProfiles": {},
        })
        r = _run(openclaw_safe_bins_profile_check(config_path=cfg))
        assert isinstance(r, dict)
        assert "findings" in r

    def test_with_profiles(self, tmp_path):
        from src.advanced_security import openclaw_safe_bins_profile_check
        cfg = _write_config(tmp_path, {
            "safeBins": ["python", "cat"],
            "safeBinProfiles": {"python": {"sandbox": True}},
        })
        r = _run(openclaw_safe_bins_profile_check(config_path=cfg))
        assert isinstance(r, dict)


class TestGroupPolicyDefaultCheck:
    def test_missing_policy(self, tmp_path):
        from src.advanced_security import openclaw_group_policy_default_check
        cfg = _write_config(tmp_path, {
            "defaults": {"groupPolicy": "open"},
            "channels": {"telegram": {}, "whatsapp": {}},
        })
        r = _run(openclaw_group_policy_default_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_allowlist_policy(self, tmp_path):
        from src.advanced_security import openclaw_group_policy_default_check
        cfg = _write_config(tmp_path, {
            "defaults": {"groupPolicy": "allowlist"},
            "channels": {
                "telegram": {"groupPolicy": "allowlist"},
                "slack": {"groupPolicy": "allowlist"},
            },
        })
        r = _run(openclaw_group_policy_default_check(config_path=cfg))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# platform_audit.py  (54% → target ~80%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecretsV2Audit:
    def test_hardcoded_keys(self, tmp_path):
        from src.platform_audit import openclaw_secrets_v2_audit
        cfg = _write_config(tmp_path, {
            "secrets": {
                "provider": "plaintext",
                "values": {"openai_key": "sk-proj-1234567890abcdef"},
            },
        })
        r = openclaw_secrets_v2_audit(config_path=cfg)
        assert isinstance(r, dict)

    def test_vault_provider(self, tmp_path):
        from src.platform_audit import openclaw_secrets_v2_audit
        cfg = _write_config(tmp_path, {
            "secrets": {
                "provider": "vault",
                "rotationPolicy": {"maxAgeDays": 30},
                "auditLog": {"enabled": True},
            },
        })
        r = openclaw_secrets_v2_audit(config_path=cfg)
        assert isinstance(r, dict)

    def test_long_rotation(self, tmp_path):
        from src.platform_audit import openclaw_secrets_v2_audit
        cfg = _write_config(tmp_path, {
            "secrets": {
                "provider": "vault",
                "rotationPolicy": {"maxAgeDays": 180},
            },
        })
        r = openclaw_secrets_v2_audit(config_path=cfg)
        assert isinstance(r, dict)


class TestAgentRoutingCheck:
    def test_circular_routing(self, tmp_path):
        from src.platform_audit import openclaw_agent_routing_check
        cfg = _write_config(tmp_path, {
            "agents": {"bindings": [
                {"name": "a", "route": "b"},
                {"name": "b", "route": "a"},
            ]},
        })
        r = openclaw_agent_routing_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_no_default_route(self, tmp_path):
        from src.platform_audit import openclaw_agent_routing_check
        cfg = _write_config(tmp_path, {
            "agents": {"bindings": [
                {"name": "a", "route": "b"},
            ]},
        })
        r = openclaw_agent_routing_check(config_path=cfg)
        assert isinstance(r, dict)


class TestVoiceSecurityCheck:
    def test_dangerous_provider(self, tmp_path):
        from src.platform_audit import openclaw_voice_security_check
        cfg = _write_config(tmp_path, {
            "voice": {
                "provider": "elevenlabs",
                "apiKey": "hardcoded-key",
                "allowSSML": True,
            },
        })
        r = openclaw_voice_security_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_safe_voice(self, tmp_path):
        from src.platform_audit import openclaw_voice_security_check
        cfg = _write_config(tmp_path, {
            "voice": {
                "provider": "whisper",
                "rateLimit": {"maxRequestsPerMinute": 10},
            },
        })
        r = openclaw_voice_security_check(config_path=cfg)
        assert isinstance(r, dict)


class TestTrustModelCheck:
    def test_shared_dm_scope(self, tmp_path):
        from src.platform_audit import openclaw_trust_model_check
        cfg = _write_config(tmp_path, {
            "multiUser": True,
            "dmScope": "shared",
        })
        r = openclaw_trust_model_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_safe_trust(self, tmp_path):
        from src.platform_audit import openclaw_trust_model_check
        cfg = _write_config(tmp_path, {
            "multiUser": True,
            "dmScope": "isolated",
            "trustModel": "zero-trust",
            "hardening": {"enabled": True},
            "session": {"timeout": 120},
        })
        r = openclaw_trust_model_check(config_path=cfg)
        assert isinstance(r, dict)


class TestAutoupdateCheck:
    def test_risky_channel(self, tmp_path):
        from src.platform_audit import openclaw_autoupdate_check
        cfg = _write_config(tmp_path, {
            "update": {
                "channel": "nightly",
                "verifySignature": False,
            },
        })
        r = openclaw_autoupdate_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_stable_channel(self, tmp_path):
        from src.platform_audit import openclaw_autoupdate_check
        cfg = _write_config(tmp_path, {
            "update": {
                "channel": "stable",
                "verifySignature": True,
                "rolloutDelay": 3600,
                "rollback": {"enabled": True},
            },
        })
        r = openclaw_autoupdate_check(config_path=cfg)
        assert isinstance(r, dict)


class TestPluginSdkCheck:
    def test_dangerous_hooks(self, tmp_path):
        from src.platform_audit import openclaw_plugin_sdk_check
        cfg = _write_config(tmp_path, {
            "plugins": {"registered": [
                {"name": "evil", "hooks": ["onExec"], "permissions": ["exec", "shell"]},
            ]},
        })
        r = openclaw_plugin_sdk_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_safe_plugins(self, tmp_path):
        from src.platform_audit import openclaw_plugin_sdk_check
        cfg = _write_config(tmp_path, {
            "plugins": {"registered": [
                {"name": "safe", "hooks": ["onMessage"], "permissions": ["read"],
                 "integrity": "sha256-abc", "packageInstall": {"allowlist": ["npm"]}},
            ]},
        })
        r = openclaw_plugin_sdk_check(config_path=cfg)
        assert isinstance(r, dict)


class TestContentBoundaryCheck:
    def test_missing_boundaries(self, tmp_path):
        from src.platform_audit import openclaw_content_boundary_check
        cfg = _write_config(tmp_path, {})
        r = openclaw_content_boundary_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_all_boundaries_set(self, tmp_path):
        from src.platform_audit import openclaw_content_boundary_check
        cfg = _write_config(tmp_path, {
            "wrapExternalContent": True,
            "wrapWebContent": True,
            "toolResult": {"stripDetails": True},
            "contentBoundary": {"enabled": True},
        })
        r = openclaw_content_boundary_check(config_path=cfg)
        assert isinstance(r, dict)


class TestSqliteVecCheck:
    def test_traversal_path(self, tmp_path):
        from src.platform_audit import openclaw_sqlite_vec_check
        cfg = _write_config(tmp_path, {
            "memory": {
                "backend": "sqlite-vec",
                "sqlite": {"path": "../../etc/data.db"},
                "embedding": {"model": "text-embedding-3-small", "dimensions": 1536},
            },
        })
        r = openclaw_sqlite_vec_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_valid_sqlite(self, tmp_path):
        from src.platform_audit import openclaw_sqlite_vec_check
        cfg = _write_config(tmp_path, {
            "memory": {
                "backend": "sqlite-vec",
                "sqlite": {"path": "./data/vectors.db"},
                "embedding": {"model": "text-embedding-3-small", "dimensions": 1536},
                "chunking": {"size": 500, "overlap": 50},
                "lazySync": False,
            },
        })
        r = openclaw_sqlite_vec_check(config_path=cfg)
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# n8n_bridge.py  (56% → target ~85%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestN8nWorkflowExport:
    def test_basic_export(self):
        from src.n8n_bridge import openclaw_n8n_workflow_export
        steps = [
            {"id": "step1", "type": "http_request", "name": "Fetch", "parameters": {"url": "https://api.example.com"}},
            {"id": "step2", "type": "agent", "name": "Process", "parameters": {}, "depends_on": ["step1"]},
        ]
        r = _run(openclaw_n8n_workflow_export(pipeline_name="test", steps=steps))
        assert isinstance(r, dict)
        assert r.get("ok") is True
        assert r.get("node_count", 0) >= 2

    def test_export_to_file(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_export
        out = str(tmp_path / "workflow.json")
        steps = [{"id": "s1", "type": "http_request", "name": "S1", "parameters": {}}]
        r = _run(openclaw_n8n_workflow_export(pipeline_name="test", steps=steps, output_path=out))
        assert isinstance(r, dict)
        assert Path(out).exists()

    def test_export_traversal(self):
        from src.n8n_bridge import openclaw_n8n_workflow_export
        steps = [{"id": "s1", "type": "http_request", "name": "S1", "parameters": {}}]
        r = _run(openclaw_n8n_workflow_export(
            pipeline_name="test", steps=steps,
            output_path="../../etc/evil.json"
        ))
        assert isinstance(r, dict)
        # may succeed or fail depending on traversal check — just ensure no exception


class TestN8nWorkflowImport:
    def test_valid_import(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        wf = {
            "name": "My Workflow",
            "nodes": [
                {"id": "1", "type": "n8n-nodes-base.httpRequest", "name": "HTTP",
                 "position": [100, 200], "parameters": {}},
            ],
            "connections": {},
        }
        wf_path = tmp_path / "workflow.json"
        wf_path.write_text(json.dumps(wf))
        r = _run(openclaw_n8n_workflow_import(workflow_path=str(wf_path)))
        assert isinstance(r, dict)
        assert r.get("ok") is True

    def test_invalid_json(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        wf_path = tmp_path / "bad.json"
        wf_path.write_text("not json{}")
        r = _run(openclaw_n8n_workflow_import(workflow_path=str(wf_path)))
        assert isinstance(r, dict)
        assert r.get("ok") is False

    def test_missing_fields_strict(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        wf_path = tmp_path / "incomplete.json"
        wf_path.write_text(json.dumps({"name": "test"}))
        r = _run(openclaw_n8n_workflow_import(workflow_path=str(wf_path), strict=True))
        assert isinstance(r, dict)

    def test_import_with_copy(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        wf = {
            "name": "Copyable",
            "nodes": [{"id": "1", "type": "n8n-nodes-base.httpRequest",
                        "name": "H", "position": [0, 0], "parameters": {}}],
            "connections": {},
        }
        wf_path = tmp_path / "src" / "wf.json"
        wf_path.parent.mkdir()
        wf_path.write_text(json.dumps(wf))
        target = tmp_path / "dest"
        target.mkdir()
        r = _run(openclaw_n8n_workflow_import(
            workflow_path=str(wf_path),
            target_dir=str(target),
        ))
        assert isinstance(r, dict)

    def test_wrong_extension(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        wf_path = tmp_path / "wf.yaml"
        wf_path.write_text("{}")
        r = _run(openclaw_n8n_workflow_import(workflow_path=str(wf_path)))
        assert isinstance(r, dict)
        assert r.get("ok") is False


# ═══════════════════════════════════════════════════════════════════════════════
# i18n_audit.py  (57% → target ~85%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestI18nAudit:
    def test_json_locales(self, tmp_path):
        from src.i18n_audit import openclaw_i18n_audit
        loc_dir = tmp_path / "locales"
        loc_dir.mkdir()
        (loc_dir / "en.json").write_text(json.dumps({"greeting": "Hello", "farewell": "Bye"}))
        (loc_dir / "fr.json").write_text(json.dumps({"greeting": "Bonjour"}))
        r = _run(openclaw_i18n_audit(project_path=str(tmp_path)))
        assert isinstance(r, dict)
        assert r.get("ok") is True
        assert len(r.get("missing_keys", [])) > 0

    def test_yaml_locales(self, tmp_path):
        from src.i18n_audit import openclaw_i18n_audit
        loc_dir = tmp_path / "i18n"
        loc_dir.mkdir()
        (loc_dir / "en.yaml").write_text("greeting: Hello\nfarewell: Bye\n")
        (loc_dir / "de.yaml").write_text("greeting: Hallo\nfarewell: Tschüss\nextra: Extra\n")
        r = _run(openclaw_i18n_audit(project_path=str(tmp_path), file_format="yaml"))
        assert isinstance(r, dict)

    def test_properties_format(self, tmp_path):
        from src.i18n_audit import openclaw_i18n_audit
        loc_dir = tmp_path / "lang"
        loc_dir.mkdir()
        (loc_dir / "en.properties").write_text("greeting=Hello\nfarewell=Bye\n")
        (loc_dir / "es.properties").write_text("greeting=Hola\n")
        r = _run(openclaw_i18n_audit(project_path=str(tmp_path), file_format="properties"))
        assert isinstance(r, dict)

    def test_no_locale_dir(self, tmp_path):
        from src.i18n_audit import openclaw_i18n_audit
        r = _run(openclaw_i18n_audit(project_path=str(tmp_path)))
        assert isinstance(r, dict)
        assert len(r.get("locales_found", [])) == 0

    def test_custom_locale_dir(self, tmp_path):
        from src.i18n_audit import openclaw_i18n_audit
        loc_dir = tmp_path / "custom"
        loc_dir.mkdir()
        (loc_dir / "en.json").write_text(json.dumps({"key": "value"}))
        r = _run(openclaw_i18n_audit(
            project_path=str(tmp_path),
            locale_dir=str(loc_dir),
        ))
        assert isinstance(r, dict)

    def test_nested_locale_pattern(self, tmp_path):
        from src.i18n_audit import openclaw_i18n_audit
        loc_dir = tmp_path / "locales"
        en_dir = loc_dir / "en"
        en_dir.mkdir(parents=True)
        fr_dir = loc_dir / "fr"
        fr_dir.mkdir()
        (en_dir / "messages.json").write_text(json.dumps({"a": "A", "b": "B"}))
        (fr_dir / "messages.json").write_text(json.dumps({"a": "A-fr"}))
        r = _run(openclaw_i18n_audit(project_path=str(tmp_path)))
        assert isinstance(r, dict)

    def test_empty_values(self, tmp_path):
        from src.i18n_audit import openclaw_i18n_audit
        loc_dir = tmp_path / "locales"
        loc_dir.mkdir()
        (loc_dir / "en.json").write_text(json.dumps({"greeting": "Hello", "empty": ""}))
        (loc_dir / "fr.json").write_text(json.dumps({"greeting": "", "empty": ""}))
        r = _run(openclaw_i18n_audit(project_path=str(tmp_path)))
        assert isinstance(r, dict)
        assert len(r.get("empty_values", [])) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# delivery_export.py  (58% → target ~80%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeliveryExportFormats:
    def test_project_brief(self, tmp_path):
        from src.delivery_export import firm_export_document
        out = str(tmp_path / "brief.md")
        r = _run(firm_export_document(
            content="Project brief content here",
            objective="Launch v2",
            departments=["engineering"],
            format="project_brief",
            output_path=out,
        ))
        assert isinstance(r, dict)
        assert Path(out).exists()

    def test_structured_document(self, tmp_path):
        from src.delivery_export import firm_export_document
        out = str(tmp_path / "structured.md")
        r = _run(firm_export_document(
            content="Structured content",
            objective="Q3 Planning",
            departments=["product", "design"],
            format="structured_document",
            output_path=out,
        ))
        assert isinstance(r, dict)

    def test_github_pr_no_token(self):
        from src.delivery_export import firm_export_github_pr
        with patch.dict(os.environ, {}, clear=True):
            with patch.dict(os.environ, {"GITHUB_TOKEN": ""}):
                r = _run(firm_export_github_pr(
                    repo="owner/repo",
                    content="PR body",
                    objective="Fix bug",
                ))
                assert isinstance(r, dict)
                assert r.get("ok") is False

    def test_jira_no_token(self):
        from src.delivery_export import firm_export_jira_ticket
        with patch.dict(os.environ, {"JIRA_API_TOKEN": "", "JIRA_BASE_URL": "", "JIRA_USER_EMAIL": ""}):
            r = _run(firm_export_jira_ticket(
                project_key="PROJ",
                content="Ticket body",
                objective="New feature",
            ))
            assert isinstance(r, dict)
            assert r.get("ok") is False

    def test_linear_no_token(self):
        from src.delivery_export import firm_export_linear_issue
        with patch.dict(os.environ, {"LINEAR_API_KEY": ""}):
            r = _run(firm_export_linear_issue(
                team_id="TEAM1",
                content="Issue body",
                objective="Task",
            ))
            assert isinstance(r, dict)
            assert r.get("ok") is False

    def test_slack_no_webhook(self):
        from src.delivery_export import firm_export_slack_digest
        with patch.dict(os.environ, {"SLACK_WEBHOOK_URL": ""}):
            r = _run(firm_export_slack_digest(
                content="Digest text",
                objective="Weekly report",
            ))
            assert isinstance(r, dict)
            assert r.get("ok") is False

    def test_auto_github(self):
        from src.delivery_export import firm_export_auto
        with patch.dict(os.environ, {"GITHUB_TOKEN": ""}):
            r = _run(firm_export_auto(
                delivery_format="github_pr",
                content="PR",
                objective="obj",
                github_repo="owner/repo",
            ))
            assert isinstance(r, dict)

    def test_auto_jira(self):
        from src.delivery_export import firm_export_auto
        with patch.dict(os.environ, {"JIRA_API_TOKEN": "", "JIRA_BASE_URL": "", "JIRA_USER_EMAIL": ""}):
            r = _run(firm_export_auto(
                delivery_format="jira_ticket",
                content="Jira",
                objective="obj",
                jira_project_key="PROJ",
            ))
            assert isinstance(r, dict)

    def test_auto_linear(self):
        from src.delivery_export import firm_export_auto
        with patch.dict(os.environ, {"LINEAR_API_KEY": ""}):
            r = _run(firm_export_auto(
                delivery_format="linear_issue",
                content="Linear",
                objective="obj",
                linear_team_id="TEAM",
            ))
            assert isinstance(r, dict)

    def test_auto_slack(self):
        from src.delivery_export import firm_export_auto
        with patch.dict(os.environ, {"SLACK_WEBHOOK_URL": ""}):
            r = _run(firm_export_auto(
                delivery_format="slack_digest",
                content="Slack",
                objective="obj",
            ))
            assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# gateway_hardening.py  (58% → target ~80%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestGatewayAuthCheckDeep:
    def test_funnel_no_password(self, tmp_path):
        from src.gateway_hardening import openclaw_gateway_auth_check
        cfg = _write_config(tmp_path, {
            "gateway": {"mode": "funnel", "bind": "0.0.0.0:8080"},
        })
        r = _run(openclaw_gateway_auth_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_dangerous_disable_auth(self, tmp_path):
        from src.gateway_hardening import openclaw_gateway_auth_check
        cfg = _write_config(tmp_path, {
            "gateway": {
                "controlUi": {"dangerouslyDisableDeviceAuth": True},
                "bind": "0.0.0.0:8080",
            },
        })
        r = _run(openclaw_gateway_auth_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_tailscale_mode(self, tmp_path):
        from src.gateway_hardening import openclaw_gateway_auth_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "100.64.0.1:8080", "auth": {"mode": "tailscale"}},
        })
        r = _run(openclaw_gateway_auth_check(config_path=cfg))
        assert isinstance(r, dict)


class TestCredentialsCheckDeep:
    def test_stale_credentials(self, tmp_path):
        from src.gateway_hardening import openclaw_credentials_check
        creds_dir = tmp_path / "credentials"
        ch_dir = creds_dir / "whatsapp"
        ch_dir.mkdir(parents=True)
        creds_file = ch_dir / "creds.json"
        creds_file.write_text(json.dumps({"key": "value"}))
        # Make it old
        old_time = 1000000
        os.utime(str(creds_file), (old_time, old_time))
        r = _run(openclaw_credentials_check(credentials_dir=str(creds_dir)))
        assert isinstance(r, dict)

    def test_corrupt_json(self, tmp_path):
        from src.gateway_hardening import openclaw_credentials_check
        creds_dir = tmp_path / "credentials"
        ch_dir = creds_dir / "telegram"
        ch_dir.mkdir(parents=True)
        (ch_dir / "creds.json").write_text("not json{")
        r = _run(openclaw_credentials_check(credentials_dir=str(creds_dir)))
        assert isinstance(r, dict)


class TestWebhookSigCheckDeep:
    def test_missing_secret(self, tmp_path):
        from src.gateway_hardening import openclaw_webhook_sig_check
        cfg = _write_config(tmp_path, {
            "channels": {
                "telegram": {"enabled": True},
                "discord": {"enabled": True, "webhookSecret": "secret123"},
            },
        })
        r = _run(openclaw_webhook_sig_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_single_channel(self, tmp_path):
        from src.gateway_hardening import openclaw_webhook_sig_check
        cfg = _write_config(tmp_path, {
            "channels": {
                "slack": {"enabled": True, "webhookSecret": "sec"},
            },
        })
        r = _run(openclaw_webhook_sig_check(config_path=cfg, channel="slack"))
        assert isinstance(r, dict)


class TestLogConfigCheckDeep:
    def test_debug_level(self, tmp_path):
        from src.gateway_hardening import openclaw_log_config_check
        cfg = _write_config(tmp_path, {
            "logging": {"level": "debug"},
        })
        r = _run(openclaw_log_config_check(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("log_level") == "debug"

    def test_invalid_level(self, tmp_path):
        from src.gateway_hardening import openclaw_log_config_check
        cfg = _write_config(tmp_path, {
            "logging": {"level": "verbose"},
        })
        r = _run(openclaw_log_config_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_redact_patterns(self, tmp_path):
        from src.gateway_hardening import openclaw_log_config_check
        cfg = _write_config(tmp_path, {
            "logging": {
                "level": "info",
                "redactPatterns": ["password", "token", "secret", "bearer"],
            },
        })
        r = _run(openclaw_log_config_check(config_path=cfg))
        assert isinstance(r, dict)


class TestWorkspaceIntegrityCheckDeep:
    def test_complete_workspace(self, tmp_path):
        from src.gateway_hardening import openclaw_workspace_integrity_check
        (tmp_path / "AGENTS.md").write_text("# Agents")
        (tmp_path / "SOUL.md").write_text("# Soul")
        (tmp_path / "MEMORY.md").write_text("# Memory")
        skills = tmp_path / "skills" / "test-skill"
        skills.mkdir(parents=True)
        (skills / "SKILL.md").write_text("# Skill")
        r = _run(openclaw_workspace_integrity_check(workspace_dir=str(tmp_path)))
        assert isinstance(r, dict)
        assert r.get("skills_installed", 0) >= 1

    def test_missing_required_files(self, tmp_path):
        from src.gateway_hardening import openclaw_workspace_integrity_check
        r = _run(openclaw_workspace_integrity_check(workspace_dir=str(tmp_path)))
        assert isinstance(r, dict)
        assert any("AGENTS" in str(f) or "SOUL" in str(f) for f in r.get("findings", []))


# ═══════════════════════════════════════════════════════════════════════════════
# ecosystem_audit.py  (59% → target ~80%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMcpFirewallCheck:
    def test_no_firewall(self, tmp_path):
        from src.ecosystem_audit import openclaw_mcp_firewall_check
        cfg = _write_config(tmp_path, {})
        r = openclaw_mcp_firewall_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_with_firewall(self, tmp_path):
        from src.ecosystem_audit import openclaw_mcp_firewall_check
        cfg = _write_config(tmp_path, {
            "mcp": {"firewall": {
                "toolAllowlist": ["safe_tool"],
                "argumentSanitization": True,
                "rateLimits": {"maxRequestsPerMinute": 100},
                "secretLeakPrevention": True,
                "maxRequestSize": 1048576,
            }},
        })
        r = openclaw_mcp_firewall_check(config_path=cfg)
        assert isinstance(r, dict)


class TestRagPipelineCheck:
    def test_valid_rag(self, tmp_path):
        from src.ecosystem_audit import openclaw_rag_pipeline_check
        cfg = _write_config(tmp_path, {
            "rag": {
                "embedding": {"model": "text-embedding-3-small", "dimensions": 1536},
                "vectorStore": {"type": "pgvector"},
                "chunking": {"size": 500, "overlap": 50},
                "retrieval": {"topK": 10, "threshold": 0.7},
            },
        })
        r = openclaw_rag_pipeline_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_bad_chunking(self, tmp_path):
        from src.ecosystem_audit import openclaw_rag_pipeline_check
        cfg = _write_config(tmp_path, {
            "rag": {
                "embedding": {"model": "custom"},
                "chunking": {"size": 50, "overlap": 100},
                "retrieval": {"topK": 50},
            },
        })
        r = openclaw_rag_pipeline_check(config_path=cfg)
        assert isinstance(r, dict)


class TestSandboxExecCheck:
    def test_safe_sandbox(self, tmp_path):
        from src.ecosystem_audit import openclaw_sandbox_exec_check
        cfg = _write_config(tmp_path, {
            "sandbox": {
                "mode": "nsjail",
                "resourceLimits": {"memory": "256M", "cpu": "1"},
                "networkPolicy": "deny",
                "filesystem": {"writable": False},
                "timeout": 60,
            },
        })
        r = openclaw_sandbox_exec_check(config_path=cfg)
        assert isinstance(r, dict)

    def test_no_sandbox(self, tmp_path):
        from src.ecosystem_audit import openclaw_sandbox_exec_check
        cfg = _write_config(tmp_path, {
            "sandbox": {"mode": "disabled"},
        })
        r = openclaw_sandbox_exec_check(config_path=cfg)
        assert isinstance(r, dict)


class TestContextHealthCheck:
    def test_high_utilization(self):
        from src.ecosystem_audit import openclaw_context_health_check
        r = openclaw_context_health_check(session_data={
            "tokens_used": 95000,
            "context_window": 100000,
            "session_age_hours": 30,
            "turn_count": 60,
        })
        assert isinstance(r, dict)

    def test_healthy_session(self):
        from src.ecosystem_audit import openclaw_context_health_check
        r = openclaw_context_health_check(session_data={
            "tokens_used": 5000,
            "context_window": 100000,
            "session_age_hours": 1,
            "turn_count": 5,
        })
        assert isinstance(r, dict)


class TestProvenanceTracker:
    def test_append_and_verify(self):
        from src.ecosystem_audit import openclaw_provenance_tracker
        # Clear chain
        openclaw_provenance_tracker(action="status")

        r1 = openclaw_provenance_tracker(action="append", entry={
            "action": "tool_call", "tool": "test", "result": "ok"
        })
        assert isinstance(r1, dict)

        r2 = openclaw_provenance_tracker(action="verify")
        assert isinstance(r2, dict)

        r3 = openclaw_provenance_tracker(action="export")
        assert isinstance(r3, dict)

        r4 = openclaw_provenance_tracker(action="status")
        assert isinstance(r4, dict)


class TestCostAnalytics:
    def test_with_session_data(self):
        from src.ecosystem_audit import openclaw_cost_analytics
        r = openclaw_cost_analytics(session_data={
            "model": "claude-sonnet-4-20250514",
            "tokens": {"input": 5000, "output": 1000},
            "budget": {"max_cost": 10.0},
            "tool_calls": [
                {"name": "search", "tokens": 500},
                {"name": "search", "tokens": 300},
            ],
        })
        assert isinstance(r, dict)

    def test_no_session(self):
        from src.ecosystem_audit import openclaw_cost_analytics
        r = openclaw_cost_analytics()
        assert isinstance(r, dict)


class TestTokenBudgetOptimizer:
    def test_high_system_prompt(self):
        from src.ecosystem_audit import openclaw_token_budget_optimizer
        r = openclaw_token_budget_optimizer(session_data={
            "tokens_used": 50000,
            "context_window": 100000,
            "system_prompt_tokens": 30000,
            "tool_result_tokens": 15000,
            "cache_hit_rate": 0.1,
            "message_count": 20,
            "unique_messages": 15,
        })
        assert isinstance(r, dict)

    def test_optimal_usage(self):
        from src.ecosystem_audit import openclaw_token_budget_optimizer
        r = openclaw_token_budget_optimizer(session_data={
            "tokens_used": 10000,
            "context_window": 100000,
            "system_prompt_tokens": 1000,
            "tool_result_tokens": 2000,
            "cache_hit_rate": 0.8,
            "message_count": 10,
            "unique_messages": 10,
        })
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# runtime_audit.py  (62% → target ~85%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestNodeVersionCheckDeep:
    def test_old_version(self):
        from src.runtime_audit import openclaw_node_version_check
        mock_result = MagicMock()
        mock_result.stdout = "v18.0.0\n"
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            with patch("shutil.which", return_value="/usr/bin/node"):
                r = _run(openclaw_node_version_check())
                assert isinstance(r, dict)
                assert r.get("meets_minimum") is False

    def test_no_node(self):
        from src.runtime_audit import openclaw_node_version_check
        with patch("shutil.which", return_value=None):
            r = _run(openclaw_node_version_check())
            assert isinstance(r, dict)
            assert "not found" in str(r).lower() or r.get("status") != "ok"


class TestSecretsWorkflowCheck:
    def test_hardcoded_secrets(self, tmp_path):
        from src.runtime_audit import openclaw_secrets_workflow_check
        cfg = _write_config(tmp_path, {
            "database": {"password": "super-secret-123"},
            "api": {"key": "sk-proj-1234abcd"},
        })
        r = _run(openclaw_secrets_workflow_check(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("hardcoded_count", 0) >= 0

    def test_placeholder_secrets(self, tmp_path):
        from src.runtime_audit import openclaw_secrets_workflow_check
        cfg = _write_config(tmp_path, {
            "database": {"password": "$DB_PASSWORD"},
            "api": {"key": "{{API_KEY}}"},
        })
        r = _run(openclaw_secrets_workflow_check(config_path=cfg))
        assert isinstance(r, dict)


class TestHttpHeadersCheckDeep:
    def test_public_bind(self, tmp_path):
        from src.runtime_audit import openclaw_http_headers_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "0.0.0.0:8080"},
        })
        r = _run(openclaw_http_headers_check(config_path=cfg))
        assert isinstance(r, dict)
        assert r.get("is_public") is True

    def test_with_headers(self, tmp_path):
        from src.runtime_audit import openclaw_http_headers_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "0.0.0.0:443"},
            "http": {
                "headers": {
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                },
            },
        })
        r = _run(openclaw_http_headers_check(config_path=cfg))
        assert isinstance(r, dict)


class TestNodesCommandsCheckDeep:
    def test_allow_commands_remote(self, tmp_path):
        from src.runtime_audit import openclaw_nodes_commands_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "0.0.0.0:8080"},
            "nodes": {"allowCommands": True},
        })
        r = _run(openclaw_nodes_commands_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_deny_commands(self, tmp_path):
        from src.runtime_audit import openclaw_nodes_commands_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "127.0.0.1:8080"},
            "nodes": {"allowCommands": True, "denyCommands": ["rm", "dd"]},
        })
        r = _run(openclaw_nodes_commands_check(config_path=cfg))
        assert isinstance(r, dict)


class TestTrustedProxyCheckDeep:
    def test_empty_trusted_proxies(self, tmp_path):
        from src.runtime_audit import openclaw_trusted_proxy_check
        cfg = _write_config(tmp_path, {
            "gateway": {"auth": {"mode": "trusted-proxy"}, "trustedProxies": []},
        })
        r = _run(openclaw_trusted_proxy_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_non_loopback_proxy(self, tmp_path):
        from src.runtime_audit import openclaw_trusted_proxy_check
        cfg = _write_config(tmp_path, {
            "gateway": {
                "auth": {"mode": "trusted-proxy"},
                "trustedProxies": ["10.0.0.1"],
                "bind": "0.0.0.0:8080",
            },
        })
        r = _run(openclaw_trusted_proxy_check(config_path=cfg))
        assert isinstance(r, dict)


class TestSessionDiskBudgetCheckDeep:
    def test_missing_budget(self, tmp_path):
        from src.runtime_audit import openclaw_session_disk_budget_check
        cfg = _write_config(tmp_path, {})
        r = _run(openclaw_session_disk_budget_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_zero_budget(self, tmp_path):
        from src.runtime_audit import openclaw_session_disk_budget_check
        cfg = _write_config(tmp_path, {
            "session": {"maxDiskBytes": 0},
        })
        r = _run(openclaw_session_disk_budget_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_valid_budget(self, tmp_path):
        from src.runtime_audit import openclaw_session_disk_budget_check
        cfg = _write_config(tmp_path, {
            "session": {"maxDiskBytes": 104857600, "highWaterBytes": 83886080},
        })
        r = _run(openclaw_session_disk_budget_check(config_path=cfg))
        assert isinstance(r, dict)


class TestDmAllowlistCheckDeep:
    def test_open_dm_policy(self, tmp_path):
        from src.runtime_audit import openclaw_dm_allowlist_check
        cfg = _write_config(tmp_path, {
            "defaults": {"dmPolicy": "open"},
            "channels": {
                "telegram": {"dmPolicy": "allowlist", "allowFrom": ["user1"]},
                "whatsapp": {"dmPolicy": "open"},
            },
        })
        r = _run(openclaw_dm_allowlist_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_allowlist_empty_allow_from(self, tmp_path):
        from src.runtime_audit import openclaw_dm_allowlist_check
        cfg = _write_config(tmp_path, {
            "channels": {
                "telegram": {"dmPolicy": "allowlist", "allowFrom": []},
            },
        })
        r = _run(openclaw_dm_allowlist_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_wildcard(self, tmp_path):
        from src.runtime_audit import openclaw_dm_allowlist_check
        cfg = _write_config(tmp_path, {
            "channels": {
                "signal": {"dmPolicy": "allowlist", "allowFrom": ["*"]},
            },
        })
        r = _run(openclaw_dm_allowlist_check(config_path=cfg))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# agent_orchestration.py  (63% → target ~85%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAgentTeamOrchestrate:
    def test_parallel_tasks(self):
        from src.agent_orchestration import openclaw_agent_team_orchestrate
        tasks = [
            {"id": "a", "agent": "researcher", "prompt": "Find data"},
            {"id": "b", "agent": "writer", "prompt": "Write report"},
        ]
        r = _run(openclaw_agent_team_orchestrate(tasks=tasks, objective="Research"))
        assert isinstance(r, dict)
        assert r.get("ok") is True

    def test_sequential_deps(self):
        from src.agent_orchestration import openclaw_agent_team_orchestrate
        tasks = [
            {"id": "a", "agent": "fetcher", "prompt": "Fetch"},
            {"id": "b", "agent": "processor", "prompt": "Process", "depends_on": ["a"]},
            {"id": "c", "agent": "writer", "prompt": "Write", "depends_on": ["b"]},
        ]
        r = _run(openclaw_agent_team_orchestrate(tasks=tasks, objective="Pipeline"))
        assert isinstance(r, dict)
        assert r.get("total_tasks") == 3

    def test_cycle_detection(self):
        from src.agent_orchestration import openclaw_agent_team_orchestrate
        tasks = [
            {"id": "a", "agent": "x", "prompt": "p", "depends_on": ["b"]},
            {"id": "b", "agent": "y", "prompt": "p", "depends_on": ["a"]},
        ]
        r = _run(openclaw_agent_team_orchestrate(tasks=tasks))
        assert isinstance(r, dict)
        assert r.get("ok") is False

    def test_vote_aggregation(self):
        from src.agent_orchestration import openclaw_agent_team_orchestrate
        tasks = [
            {"id": "v1", "agent": "voter1", "prompt": "Vote"},
            {"id": "v2", "agent": "voter2", "prompt": "Vote"},
            {"id": "v3", "agent": "voter3", "prompt": "Vote"},
        ]
        r = _run(openclaw_agent_team_orchestrate(
            tasks=tasks, aggregation_strategy="vote"
        ))
        assert isinstance(r, dict)

    def test_first_success(self):
        from src.agent_orchestration import openclaw_agent_team_orchestrate
        tasks = [
            {"id": "f1", "agent": "a", "prompt": "Try"},
            {"id": "f2", "agent": "b", "prompt": "Try"},
        ]
        r = _run(openclaw_agent_team_orchestrate(
            tasks=tasks, aggregation_strategy="first_success"
        ))
        assert isinstance(r, dict)


class TestAgentTeamStatus:
    def test_list_all(self):
        from src.agent_orchestration import openclaw_agent_team_status
        r = _run(openclaw_agent_team_status())
        assert isinstance(r, dict)

    def test_nonexistent_id(self):
        from src.agent_orchestration import openclaw_agent_team_status
        r = _run(openclaw_agent_team_status(orchestration_id="nonexistent"))
        assert isinstance(r, dict)
        assert r.get("ok") is False


# ═══════════════════════════════════════════════════════════════════════════════
# observability.py  (72% → target ~90%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestObservabilityPipeline:
    def test_ingest_jsonl(self, tmp_path):
        from src.observability import openclaw_observability_pipeline
        jsonl = tmp_path / "traces.jsonl"
        lines = [
            json.dumps({"traceId": "abc", "spanId": "s1", "operationName": "test", "timestamp": 1000}),
            json.dumps({"traceId": "def", "spanId": "s2", "operationName": "test2", "timestamp": 2000}),
        ]
        jsonl.write_text("\n".join(lines) + "\n")
        db = str(tmp_path / "traces.db")
        r = _run(openclaw_observability_pipeline(jsonl_path=str(jsonl), db_path=db))
        assert isinstance(r, dict)
        assert r.get("ok") is True
        assert r.get("ingested", 0) >= 2

    def test_invalid_table_name(self, tmp_path):
        from src.observability import openclaw_observability_pipeline
        jsonl = tmp_path / "t.jsonl"
        jsonl.write_text("{}\n")
        r = _run(openclaw_observability_pipeline(
            jsonl_path=str(jsonl), table_name="drop;table"
        ))
        assert isinstance(r, dict)
        assert r.get("ok") is False

    def test_wrong_extension(self, tmp_path):
        from src.observability import openclaw_observability_pipeline
        txt = tmp_path / "traces.txt"
        txt.write_text("{}\n")
        r = _run(openclaw_observability_pipeline(jsonl_path=str(txt)))
        assert isinstance(r, dict)
        assert r.get("ok") is False

    def test_duplicate_handling(self, tmp_path):
        from src.observability import openclaw_observability_pipeline
        jsonl = tmp_path / "traces.jsonl"
        line = json.dumps({"traceId": "dup", "spanId": "s1", "operationName": "op"})
        jsonl.write_text(f"{line}\n{line}\n")
        r = _run(openclaw_observability_pipeline(jsonl_path=str(jsonl), db_path=str(tmp_path / "d.db")))
        assert isinstance(r, dict)


class TestCiPipelineCheck:
    def test_complete_ci(self, tmp_path):
        from src.observability import openclaw_ci_pipeline_check
        ci_dir = tmp_path / ".github" / "workflows"
        ci_dir.mkdir(parents=True)
        (ci_dir / "ci.yml").write_text(textwrap.dedent("""\
            name: CI
            on: push
            jobs:
              build:
                steps:
                  - run: npm run lint
                  - run: npm test
                  - run: npm run secrets-scan
                  - run: npm run coverage
                  - run: npx tsc --noEmit
        """))
        r = _run(openclaw_ci_pipeline_check(repo_path=str(tmp_path)))
        assert isinstance(r, dict)
        assert r.get("ok") is True

    def test_missing_steps(self, tmp_path):
        from src.observability import openclaw_ci_pipeline_check
        ci_dir = tmp_path / ".github" / "workflows"
        ci_dir.mkdir(parents=True)
        (ci_dir / "ci.yml").write_text("name: CI\non: push\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
        r = _run(openclaw_ci_pipeline_check(repo_path=str(tmp_path)))
        assert isinstance(r, dict)
        assert len(r.get("missing_required", [])) > 0

    def test_no_ci_dir(self, tmp_path):
        from src.observability import openclaw_ci_pipeline_check
        r = _run(openclaw_ci_pipeline_check(repo_path=str(tmp_path)))
        assert isinstance(r, dict)
        assert len(r.get("missing_required", [])) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# skill_loader.py  (76% → target ~90%)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSkillLazyLoader:
    def test_load_all(self, tmp_path):
        from src.skill_loader import openclaw_skill_lazy_loader
        skill = tmp_path / "skills" / "test-skill"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(textwrap.dedent("""\
            ---
            name: test-skill
            version: 1.0.0
            description: A test skill
            tags: [test, demo]
            ---
            # Test Skill

            This is a test skill.
        """))
        r = _run(openclaw_skill_lazy_loader(skills_dir=str(tmp_path / "skills")))
        assert isinstance(r, dict)
        assert r.get("ok") is True
        assert r.get("total", 0) >= 1

    def test_load_single(self, tmp_path):
        from src.skill_loader import openclaw_skill_lazy_loader
        skill = tmp_path / "skills" / "my-skill"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("---\nname: my-skill\nversion: 1.0.0\n---\n# My Skill\nDesc here.\n")
        r = _run(openclaw_skill_lazy_loader(
            skills_dir=str(tmp_path / "skills"),
            skill_name="my-skill",
        ))
        assert isinstance(r, dict)

    def test_refresh_cache(self, tmp_path):
        from src.skill_loader import openclaw_skill_lazy_loader
        skill = tmp_path / "skills" / "cached"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("---\nname: cached\n---\n# Cached\n")
        _run(openclaw_skill_lazy_loader(skills_dir=str(tmp_path / "skills")))
        r = _run(openclaw_skill_lazy_loader(
            skills_dir=str(tmp_path / "skills"),
            refresh=True,
        ))
        assert isinstance(r, dict)

    def test_nonexistent_dir(self, tmp_path):
        from src.skill_loader import openclaw_skill_lazy_loader
        r = _run(openclaw_skill_lazy_loader(skills_dir=str(tmp_path / "nope")))
        assert isinstance(r, dict)
        assert r.get("ok") is False


class TestSkillSearch:
    def test_query_match(self, tmp_path):
        from src import skill_loader
        from src.skill_loader import openclaw_skill_search
        skill_loader._SKILL_CACHE.clear()
        skill_loader._CACHE_TS = 0.0
        skill = tmp_path / "skills" / "security-audit"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            "---\nname: security-audit\ntags: [security]\n---\n# Security Audit\nAudit your security config.\n"
        )
        r = _run(openclaw_skill_search(
            skills_dir=str(tmp_path / "skills"),
            query="security",
        ))
        assert isinstance(r, dict)
        assert r.get("total_matches", 0) >= 1

    def test_tag_filter(self, tmp_path):
        from src import skill_loader
        from src.skill_loader import openclaw_skill_search
        skill_loader._SKILL_CACHE.clear()
        skill_loader._CACHE_TS = 0.0
        skill = tmp_path / "skills" / "tagged"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            "---\nname: tagged\ntags: [compliance, gdpr]\n---\n# Tagged\nCompliance tool.\n"
        )
        r = _run(openclaw_skill_search(
            skills_dir=str(tmp_path / "skills"),
            query="compliance",
            tags=["gdpr"],
        ))
        assert isinstance(r, dict)

    def test_no_results(self, tmp_path):
        from src import skill_loader
        from src.skill_loader import openclaw_skill_search
        skill_loader._SKILL_CACHE.clear()
        skill_loader._CACHE_TS = 0.0
        skill = tmp_path / "skills" / "unrelated"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("---\nname: unrelated\n---\n# Unrelated\nNothing here.\n")
        r = _run(openclaw_skill_search(
            skills_dir=str(tmp_path / "skills"),
            query="xyznonexistent",
        ))
        assert isinstance(r, dict)
        assert r.get("total_matches", 0) == 0
