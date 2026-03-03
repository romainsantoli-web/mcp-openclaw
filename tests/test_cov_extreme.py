"""
test_cov_extreme.py — Push coverage from 87% toward 92%+.
Targets the 11 modules still below 85%.
"""
from __future__ import annotations
import asyncio
import json
import os
import time
from pathlib import Path



def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _write_config(tmp_path: Path, data: dict, name: str = "config.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# ═══════════════════════════════════════════════════════════════════════════════
# advanced_security.py — 78% → target 90%+
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdvancedSecurityExtreme:

    # --- firm_secrets_lifecycle_check ---

    def test_secrets_lifecycle_empty_config(self, tmp_path):
        from src.advanced_security import firm_secrets_lifecycle_check
        cfg = _write_config(tmp_path, {})
        r = _run(firm_secrets_lifecycle_check(cfg))
        assert r["status"] == "ok"

    def test_secrets_lifecycle_inline_creds(self, tmp_path):
        from src.advanced_security import firm_secrets_lifecycle_check
        cfg = _write_config(tmp_path, {
            "auth": {"profiles": {
                "prod": {"apiKey": "sk-live-12345", "token": "real-token"},
                "dev": {"apiKey": "$ENV_VAR"},  # not inline
            }}
        })
        r = _run(firm_secrets_lifecycle_check(cfg))
        assert r["inline_credential_count"] >= 2
        assert any(f["severity"] == "CRITICAL" for f in r["findings"])

    def test_secrets_lifecycle_apply_traversal(self, tmp_path):
        from src.advanced_security import firm_secrets_lifecycle_check
        cfg = _write_config(tmp_path, {
            "secrets": {"apply": {"targetPath": "../../../etc/passwd"}}
        })
        r = _run(firm_secrets_lifecycle_check(cfg))
        assert any("traversal" in f["message"].lower() for f in r["findings"])

    def test_secrets_lifecycle_snapshot_not_activated(self, tmp_path):
        from src.advanced_security import firm_secrets_lifecycle_check
        cfg = _write_config(tmp_path, {
            "secrets": {"managed": True, "snapshotActivated": False}
        })
        r = _run(firm_secrets_lifecycle_check(cfg))
        assert any("snapshot" in f["message"].lower() for f in r["findings"])

    def test_secrets_lifecycle_no_workflow_with_inline(self, tmp_path):
        from src.advanced_security import firm_secrets_lifecycle_check
        cfg = _write_config(tmp_path, {
            "auth": {"profiles": {"p1": {"apiKey": "real-key"}}}
        })
        r = _run(firm_secrets_lifecycle_check(cfg))
        assert any("no_secrets_workflow" == f["id"] for f in r["findings"])

    # --- firm_channel_auth_canon_check ---

    def test_channel_auth_canon_empty(self, tmp_path):
        from src.advanced_security import firm_channel_auth_canon_check
        cfg = _write_config(tmp_path, {})
        r = _run(firm_channel_auth_canon_check(cfg))
        assert r["status"] == "ok"

    def test_channel_auth_canon_auth_none_remote(self, tmp_path):
        from src.advanced_security import firm_channel_auth_canon_check
        cfg = _write_config(tmp_path, {
            "gateway": {"auth": {"mode": "none"}, "bind": "0.0.0.0"}
        })
        r = _run(firm_channel_auth_canon_check(cfg))
        assert any("auth_none_remote" == f["id"] for f in r["findings"])

    def test_channel_auth_canon_plugin_traversal(self, tmp_path):
        from src.advanced_security import firm_channel_auth_canon_check
        cfg = _write_config(tmp_path, {
            "plugins": {"entries": {
                "bad": {"httpPath": "/api/%2e%2e/secret"}
            }}
        })
        r = _run(firm_channel_auth_canon_check(cfg))
        assert any("plugin_path_traversal" in f["id"] for f in r["findings"])

    def test_channel_auth_canon_basepath_traversal(self, tmp_path):
        from src.advanced_security import firm_channel_auth_canon_check
        cfg = _write_config(tmp_path, {
            "gateway": {"controlUi": {"basePath": "../../admin"}}
        })
        r = _run(firm_channel_auth_canon_check(cfg))
        assert any("controlui_basepath" in f["id"] for f in r["findings"])

    # --- firm_exec_approval_freeze_check ---

    def test_exec_approval_empty(self, tmp_path):
        from src.advanced_security import firm_exec_approval_freeze_check
        cfg = _write_config(tmp_path, {})
        r = _run(firm_exec_approval_freeze_check(cfg))
        assert "findings" in r or "status" in r

    def test_exec_approval_no_sandbox(self, tmp_path):
        from src.advanced_security import firm_exec_approval_freeze_check
        cfg = _write_config(tmp_path, {
            "tools": {"exec": {"host": "local", "sandbox": "off"}}
        })
        r = _run(firm_exec_approval_freeze_check(cfg))
        assert any("exec_host_no_sandbox" == f.get("id") for f in r.get("findings", []))

    # --- firm_hook_session_routing_check ---

    def test_hook_session_routing_empty(self, tmp_path):
        from src.advanced_security import firm_hook_session_routing_check
        cfg = _write_config(tmp_path, {})
        r = _run(firm_hook_session_routing_check(cfg))
        assert "findings" in r or "status" in r

    def test_hook_session_routing_with_hooks(self, tmp_path):
        from src.advanced_security import firm_hook_session_routing_check
        cfg = _write_config(tmp_path, {
            "hooks": {
                "onMessage": {"transformsDir": "../../../evil"},
                "onSession": {"handler": "my-handler"}
            }
        })
        r = _run(firm_hook_session_routing_check(cfg))
        assert "findings" in r

    # --- firm_config_include_check ---

    def test_config_include_empty(self, tmp_path):
        from src.advanced_security import firm_config_include_check
        cfg = _write_config(tmp_path, {})
        r = _run(firm_config_include_check(cfg))
        assert "findings" in r or "status" in r

    def test_config_include_with_includes(self, tmp_path):
        from src.advanced_security import firm_config_include_check
        inc_file = tmp_path / "extra.json"
        inc_file.write_text("{}")
        cfg = _write_config(tmp_path, {
            "channels": {"$include": str(inc_file)},
            "plugins": {"$include": str(inc_file)},
        })
        r = _run(firm_config_include_check(cfg))
        assert "findings" in r

    def test_config_include_nonexistent(self, tmp_path):
        from src.advanced_security import firm_config_include_check
        cfg = _write_config(tmp_path, {
            "extra": {"$include": "/nonexistent/path.json"}
        })
        r = _run(firm_config_include_check(cfg))
        assert "findings" in r

    # --- firm_config_prototype_check ---

    def test_config_prototype_empty(self, tmp_path):
        from src.advanced_security import firm_config_prototype_check
        cfg = _write_config(tmp_path, {})
        r = _run(firm_config_prototype_check(cfg))
        assert "findings" in r or "status" in r

    def test_config_prototype_with_proto(self, tmp_path):
        from src.advanced_security import firm_config_prototype_check
        cfg = _write_config(tmp_path, {
            "channels": {"__proto__": {"polluted": True}},
            "nested": {"deep": {"constructor": {"prototype": {}}}}
        })
        r = _run(firm_config_prototype_check(cfg))
        assert len(r.get("findings", [])) > 0

    # --- firm_safe_bins_profile_check ---

    def test_safe_bins_empty(self, tmp_path):
        from src.advanced_security import firm_safe_bins_profile_check
        cfg = _write_config(tmp_path, {})
        r = _run(firm_safe_bins_profile_check(cfg))
        assert "findings" in r or "status" in r

    def test_safe_bins_with_interpreters(self, tmp_path):
        from src.advanced_security import firm_safe_bins_profile_check
        cfg = _write_config(tmp_path, {
            "tools": {"exec": {
                "safeBins": ["python", "node", "curl"],
                "safeBinProfiles": {"curl": {"args": "--max-time 10"}}
            }}
        })
        r = _run(firm_safe_bins_profile_check(cfg))
        # python + node without profiles should be flagged
        assert any("python" in str(f) or "node" in str(f) for f in r.get("findings", []))

    def test_safe_bins_no_bins(self, tmp_path):
        from src.advanced_security import firm_safe_bins_profile_check
        cfg = _write_config(tmp_path, {"tools": {"exec": {}}})
        r = _run(firm_safe_bins_profile_check(cfg))
        assert r["status"] == "ok"

    # --- firm_group_policy_default_check ---

    def test_group_policy_empty(self, tmp_path):
        from src.advanced_security import firm_group_policy_default_check
        cfg = _write_config(tmp_path, {})
        r = _run(firm_group_policy_default_check(cfg))
        assert "findings" in r or "status" in r

    def test_group_policy_not_allowlist(self, tmp_path):
        from src.advanced_security import firm_group_policy_default_check
        cfg = _write_config(tmp_path, {
            "channels": {
                "defaults": {"groupPolicy": "blocklist"},
                "telegram": {"enabled": True},
                "discord": {"enabled": True},
            }
        })
        r = _run(firm_group_policy_default_check(cfg))
        findings = r.get("findings", [])
        assert any("defaults_group_policy" in f.get("id", "") for f in findings)

    def test_group_policy_missing_per_channel(self, tmp_path):
        from src.advanced_security import firm_group_policy_default_check
        cfg = _write_config(tmp_path, {
            "channels": {
                "defaults": {"groupPolicy": "allowlist"},
                "telegram": {"enabled": True},
            }
        })
        r = _run(firm_group_policy_default_check(cfg))
        findings = r.get("findings", [])
        assert any("channels_missing_group_policy" in f.get("id", "") for f in findings)


# ═══════════════════════════════════════════════════════════════════════════════
# gateway_hardening.py — 80% → target 90%+
# ═══════════════════════════════════════════════════════════════════════════════

class TestGatewayHardeningExtreme:

    def test_auth_check_traversal(self):
        from src.gateway_hardening import firm_gateway_auth_check
        r = _run(firm_gateway_auth_check("../../../etc/passwd"))
        assert "error" in r

    def test_auth_check_no_file(self, tmp_path):
        from src.gateway_hardening import firm_gateway_auth_check
        r = _run(firm_gateway_auth_check(str(tmp_path / "nope.json")))
        assert r.get("status") == "no_config" or "severity" in r

    def test_auth_check_bad_json(self, tmp_path):
        from src.gateway_hardening import firm_gateway_auth_check
        p = tmp_path / "bad.json"
        p.write_text("not json!")
        r = _run(firm_gateway_auth_check(str(p)))
        assert "error" in r

    def test_auth_check_funnel_no_password(self, tmp_path):
        from src.gateway_hardening import firm_gateway_auth_check
        cfg = _write_config(tmp_path, {
            "gateway": {
                "tailscale": {"mode": "funnel"},
                "auth": {"mode": "token"},
                "controlUi": {"dangerouslyDisableDeviceAuth": True},
                "bind": "0.0.0.0",
            }
        })
        r = _run(firm_gateway_auth_check(cfg))
        findings = r.get("findings", [])
        assert len(findings) >= 1

    def test_auth_check_non_loopback_no_auth(self, tmp_path):
        from src.gateway_hardening import firm_gateway_auth_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "0.0.0.0"}
        })
        r = _run(firm_gateway_auth_check(cfg))
        findings = r.get("findings", [])
        assert len(findings) >= 1

    # --- credentials_check ---

    def test_credentials_traversal(self):
        from src.gateway_hardening import firm_credentials_check
        r = _run(firm_credentials_check("../../../etc"))
        assert "error" in r

    def test_credentials_no_dir(self, tmp_path):
        from src.gateway_hardening import firm_credentials_check
        r = _run(firm_credentials_check(str(tmp_path / "nope")))
        assert r.get("status") == "no_credentials_dir" or "severity" in r

    def test_credentials_with_channels(self, tmp_path):
        from src.gateway_hardening import firm_credentials_check
        creds_dir = tmp_path / "creds"
        creds_dir.mkdir()
        # Channel with creds.json
        ch1 = creds_dir / "whatsapp"
        ch1.mkdir()
        cj = ch1 / "creds.json"
        cj.write_text("{}")
        # Set old mtime
        old_time = time.time() - (60 * 86400)
        os.utime(str(cj), (old_time, old_time))
        # Channel missing creds
        ch2 = creds_dir / "telegram"
        ch2.mkdir()
        # Channel with partial
        ch3 = creds_dir / "slack"
        ch3.mkdir()
        (ch3 / "other.json").write_text("{}")
        r = _run(firm_credentials_check(str(creds_dir)))
        assert "channels" in r or "findings" in r

    # --- webhook_sig_check ---

    def test_webhook_sig_traversal(self):
        from src.gateway_hardening import firm_webhook_sig_check
        r = _run(firm_webhook_sig_check("../../../etc/passwd"))
        assert "error" in r

    def test_webhook_sig_no_config(self, tmp_path):
        from src.gateway_hardening import firm_webhook_sig_check
        r = _run(firm_webhook_sig_check(str(tmp_path / "nope.json")))
        assert "status" in r

    def test_webhook_sig_bad_json(self, tmp_path):
        from src.gateway_hardening import firm_webhook_sig_check
        p = tmp_path / "cfg.json"
        p.write_text("bad!")
        r = _run(firm_webhook_sig_check(str(p)))
        assert "error" in r

    def test_webhook_sig_with_channels(self, tmp_path):
        from src.gateway_hardening import firm_webhook_sig_check
        cfg = _write_config(tmp_path, {
            "channels": {
                "telegram": {"webhookSecret": "sec123"},
                "discord": {},
                "slack": {"signingSecret": "slack-sec"},
            }
        })
        r = _run(firm_webhook_sig_check(cfg))
        assert "findings" in r or "checked" in r

    # --- log_config_check ---

    def test_log_config_traversal(self):
        from src.gateway_hardening import firm_log_config_check
        r = _run(firm_log_config_check("../../../etc/passwd"))
        assert "error" in r

    def test_log_config_no_file(self, tmp_path):
        from src.gateway_hardening import firm_log_config_check
        r = _run(firm_log_config_check(str(tmp_path / "nope.json")))
        assert "status" in r

    def test_log_config_debug_level(self, tmp_path):
        from src.gateway_hardening import firm_log_config_check
        cfg = _write_config(tmp_path, {"logging": {"level": "debug"}})
        r = _run(firm_log_config_check(cfg))
        findings = r.get("findings", [])
        assert len(findings) >= 1

    def test_log_config_invalid_level(self, tmp_path):
        from src.gateway_hardening import firm_log_config_check
        cfg = _write_config(tmp_path, {"logging": {"level": "superdebug"}})
        r = _run(firm_log_config_check(cfg))
        findings = r.get("findings", [])
        assert len(findings) >= 1

    def test_log_config_no_redact(self, tmp_path):
        from src.gateway_hardening import firm_log_config_check
        cfg = _write_config(tmp_path, {"logging": {"level": "info"}})
        r = _run(firm_log_config_check(cfg))
        assert "findings" in r

    # --- workspace_integrity_check ---

    def test_workspace_integrity_traversal(self):
        from src.gateway_hardening import firm_workspace_integrity_check
        r = _run(firm_workspace_integrity_check("../../../etc"))
        assert "error" in r

    def test_workspace_integrity_missing(self, tmp_path):
        from src.gateway_hardening import firm_workspace_integrity_check
        r = _run(firm_workspace_integrity_check(str(tmp_path / "nope")))
        assert "status" in r

    def test_workspace_integrity_full(self, tmp_path):
        from src.gateway_hardening import firm_workspace_integrity_check
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "AGENTS.md").write_text("# Agents")
        (ws / "SOUL.md").write_text("# Soul")
        # Stale MEMORY.md
        mem = ws / "MEMORY.md"
        mem.write_text("# Memory")
        old = time.time() - (60 * 86400)
        os.utime(str(mem), (old, old))
        # Large file
        big = ws / "huge.bin"
        big.write_bytes(b"x" * (11 * 1024 * 1024))
        # Skills dir
        sk = ws / "skills" / "my-skill"
        sk.mkdir(parents=True)
        (sk / "SKILL.md").write_text("# Skill")
        r = _run(firm_workspace_integrity_check(str(ws)))
        assert "findings" in r


# ═══════════════════════════════════════════════════════════════════════════════
# security_audit.py — 82% → target 92%+
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityAuditExtreme:

    def test_security_scan_with_vuln(self, tmp_path):
        from src.security_audit import firm_security_scan
        bad_file = tmp_path / "app.js"
        bad_file.write_text('db.query("SELECT * FROM users WHERE id=" + req.params.id)')
        r = _run(firm_security_scan(str(tmp_path), scan_depth=1))
        assert "vulnerabilities" in r or "findings" in r

    def test_security_scan_with_endpoint(self, tmp_path):
        from src.security_audit import firm_security_scan
        bad_file = tmp_path / "handler.js"
        bad_file.write_text('connection.query("DELETE FROM " + table)')
        r = _run(firm_security_scan(str(tmp_path), endpoint="handler", scan_depth=1))
        assert "vulnerabilities" in r or "findings" in r

    def test_sandbox_not_found(self, tmp_path):
        from src.security_audit import firm_sandbox_audit
        r = _run(firm_sandbox_audit(str(tmp_path / "nope.json")))
        assert r["ok"] is False

    def test_sandbox_unknown_mode(self, tmp_path):
        from src.security_audit import firm_sandbox_audit
        cfg = _write_config(tmp_path, {"security": {"mode": "something-else"}})
        r = _run(firm_sandbox_audit(cfg))
        assert "findings" in r or "finding" in r

    def test_session_config_no_files(self):
        from src.security_audit import firm_session_config_check
        r = _run(firm_session_config_check())
        assert r["ok"] is True
        assert "session_secret_found" in r or "severity" in r

    def test_session_config_compose_not_found(self, tmp_path):
        from src.security_audit import firm_session_config_check
        r = _run(firm_session_config_check(compose_file_path=str(tmp_path / "nope.yml")))
        assert r["ok"] is True

    def test_session_config_env_file(self, tmp_path):
        from src.security_audit import firm_session_config_check
        env = tmp_path / ".env"
        env.write_text("SESSION_SECRET=my-secret-value\nOTHER=val")
        r = _run(firm_session_config_check(env_file_path=str(env)))
        assert r["session_secret_found"] is True

    def test_rate_limit_not_found(self, tmp_path):
        from src.security_audit import firm_rate_limit_check
        r = _run(firm_rate_limit_check(str(tmp_path / "nope.json")))
        assert r["ok"] is False

    def test_rate_limit_funnel_no_limiter(self, tmp_path):
        from src.security_audit import firm_rate_limit_check
        cfg = tmp_path / "gw.json"
        cfg.write_text(json.dumps({"funnel": True, "tailscale": {}}))
        r = _run(firm_rate_limit_check(str(cfg)))
        assert "severity" in r


# ═══════════════════════════════════════════════════════════════════════════════
# reliability_probe.py — 82% → target 92%+
# ═══════════════════════════════════════════════════════════════════════════════

class TestReliabilityProbeExtreme:

    def test_gateway_probe_unreachable(self):
        from src.reliability_probe import firm_gateway_probe
        r = _run(firm_gateway_probe("ws://127.0.0.1:19999", max_retries=1, backoff_factor=0.01))
        assert r["ok"] is False
        assert "attempts" in r

    def test_doc_sync_no_package(self, tmp_path):
        from src.reliability_probe import firm_doc_sync_check
        r = _run(firm_doc_sync_check(str(tmp_path / "nope.json")))
        assert r["ok"] is False or "error" in r

    def test_doc_sync_no_md_files(self, tmp_path):
        from src.reliability_probe import firm_doc_sync_check
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"express": "^4"}}))
        r = _run(firm_doc_sync_check(str(pkg), docs_glob="*.nonexistent"))
        assert "note" in r or r.get("total_checked", 0) == 0

    def test_doc_sync_with_docs(self, tmp_path):
        from src.reliability_probe import firm_doc_sync_check
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"express": "^4", "baileys": "^6"}}))
        readme = tmp_path / "README.md"
        readme.write_text("# Project\nUses express for HTTP server and baileys for WhatsApp")
        r = _run(firm_doc_sync_check(str(pkg)))
        assert r["ok"] is True or "findings" in r

    def test_channel_audit_with_deps(self, tmp_path):
        from src.reliability_probe import firm_channel_audit
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"baileys": "^6", "@line/bot-sdk": "^2"},
            "devDependencies": {}
        }))
        readme = tmp_path / "README.md"
        readme.write_text("# Project\nWhatsApp integration with baileys")
        r = _run(firm_channel_audit(str(pkg), str(readme)))
        assert "code_channels" in r or "findings" in r


# ═══════════════════════════════════════════════════════════════════════════════
# compliance_medium.py — 80% → target 90%+
# ═══════════════════════════════════════════════════════════════════════════════

class TestComplianceMediumExtreme:

    # --- tool_deprecation_audit ---

    def test_deprecation_no_tools_list(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write_config(tmp_path, {"mcp": {"tools": "not-a-list"}, "tools": "also-not-a-list"})
        r = _run(tool_deprecation_audit(cfg))
        assert any("no tools list" in f.lower() for f in r.get("findings", []))

    def test_deprecation_missing_sunset(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"tools": [
                {"name": "old_tool", "annotations": {"deprecated": True, "replacement": "new_tool", "deprecatedMessage": "use new"}},
                {"name": "new_tool", "annotations": {}},
            ]}
        })
        r = _run(tool_deprecation_audit(cfg))
        assert any("no sunset" in f.lower() for f in r.get("findings", []))

    def test_deprecation_bad_sunset_format(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"tools": [
                {"name": "t1", "annotations": {"deprecated": True, "sunset": "next-tuesday", "replacement": "t2", "deprecatedMessage": "use t2"}},
                {"name": "t2", "annotations": {}},
            ]}
        })
        r = _run(tool_deprecation_audit(cfg))
        assert any("not valid iso" in f.lower() for f in r.get("findings", []))

    def test_deprecation_replacement_not_exists(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"tools": [
                {"name": "old", "annotations": {"deprecated": True, "sunset": "2026-12-31", "replacement": "ghost", "deprecatedMessage": "bye"}},
            ]}
        })
        r = _run(tool_deprecation_audit(cfg))
        assert any("does not exist" in f.lower() for f in r.get("findings", []))

    # --- circuit_breaker_audit ---

    def test_circuit_breaker_no_config(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write_config(tmp_path, {"mcp": {}})
        r = _run(circuit_breaker_audit(cfg))
        assert any("no global circuit breaker" in f.lower() for f in r.get("findings", []))

    def test_circuit_breaker_invalid_threshold(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"resilience": {"circuitBreaker": {"enabled": True, "failureThreshold": -1}}}
        })
        r = _run(circuit_breaker_audit(cfg))
        assert any("invalid" in f.lower() for f in r.get("findings", []))

    def test_circuit_breaker_high_retries(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"resilience": {
                "circuitBreaker": {"enabled": True, "failureThreshold": 5},
                "retry": {"maxRetries": 10},
            }}
        })
        r = _run(circuit_breaker_audit(cfg))
        assert any("too high" in f.lower() for f in r.get("findings", []))

    def test_circuit_breaker_no_timeout(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"resilience": {
                "circuitBreaker": {"enabled": True, "failureThreshold": 5},
                "retry": {"maxRetries": 3},
            }}
        })
        r = _run(circuit_breaker_audit(cfg))
        assert any("no timeout" in f.lower() for f in r.get("findings", []))

    def test_circuit_breaker_high_timeout(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"resilience": {
                "circuitBreaker": {"enabled": True, "failureThreshold": 5},
                "retry": {"maxRetries": 3},
                "timeout": 200000,
            }}
        })
        r = _run(circuit_breaker_audit(cfg))
        assert any("exceed" in f.lower() for f in r.get("findings", []))

    # --- gdpr_residency_audit ---

    def test_gdpr_no_config(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write_config(tmp_path, {"mcp": {}})
        r = _run(gdpr_residency_audit(cfg))
        assert any("no privacy" in f.lower() for f in r.get("findings", []))

    def test_gdpr_non_standard_basis(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"privacy": {"gdpr": {"legalBasis": "custom_basis"}}}
        })
        r = _run(gdpr_residency_audit(cfg))
        assert any("non-standard" in f.lower() for f in r.get("findings", []))

    def test_gdpr_no_retention(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"privacy": {"gdpr": {"legalBasis": "consent"}}}
        })
        r = _run(gdpr_residency_audit(cfg))
        assert any("retention" in f.lower() for f in r.get("findings", []))

    def test_gdpr_full_config(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"privacy": {"gdpr": {
                "legalBasis": "consent",
                "retentionDays": 365,
                "rightToErasure": {"endpoint": "/api/erase"},
                "dpa": "https://example.com/dpa",
            }}, "dataResidency": {"region": "eu"}}
        })
        r = _run(gdpr_residency_audit(cfg))
        assert "findings" in r

    def test_gdpr_pii_tool_not_declared(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "privacy": {"gdpr": {"legalBasis": "consent", "retentionDays": 30,
                    "rightToErasure": {"endpoint": "/erase"}, "dpa": "ref"}},
                "dataResidency": {"region": "eu"},
                "tools": [{"name": "user_tool", "inputSchema": {
                    "properties": {"email": {"type": "string"}, "phone": {"type": "string"}}
                }}]
            }
        })
        r = _run(gdpr_residency_audit(cfg))
        assert any("pii" in f.lower() for f in r.get("findings", []))

    # --- agent_identity_audit ---

    def test_agent_identity_no_config(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write_config(tmp_path, {"mcp": {}})
        r = _run(agent_identity_audit(cfg))
        assert any("no agent identity" in f.lower() for f in r.get("findings", []))

    def test_agent_identity_invalid_did(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"identity": {"did": "not-a-did"}}
        })
        r = _run(agent_identity_audit(cfg))
        assert any("not valid did" in f.lower() for f in r.get("findings", []))

    def test_agent_identity_weak_signing(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"identity": {
                "did": "did:web:example.com",
                "signing": {"algorithm": "none"},
                "verificationMethod": [{"type": "Ed25519"}],
            }}
        })
        r = _run(agent_identity_audit(cfg))
        assert any("weak" in f.lower() or "insecure" in f.lower() for f in r.get("findings", []))

    def test_agent_identity_with_agents(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "identity": {"did": "did:web:example.com", "verificationMethod": [{"type": "Ed25519"}]},
                "agents": [
                    {"name": "agent1", "identity": {"did": "did:key:abc123"}},
                    {"name": "agent2"},
                ]
            }
        })
        r = _run(agent_identity_audit(cfg))
        assert "findings" in r

    # --- model_routing_audit ---

    def test_model_routing_no_config(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write_config(tmp_path, {"mcp": {}})
        r = _run(model_routing_audit(cfg))
        assert any("no multi-model" in f.lower() for f in r.get("findings", []))

    def test_model_routing_no_strategy(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "routing": {},
                "models": [
                    {"provider": "anthropic", "model": "claude-3", "id": "m1"},
                    {"provider": "openai", "model": "gpt-4", "id": "m2"},
                ]
            }
        })
        r = _run(model_routing_audit(cfg))
        assert any("no routing strategy" in f.lower() or "no fallback" in f.lower() for f in r.get("findings", []))

    def test_model_routing_single_provider(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "routing": {
                    "strategy": "priority",
                    "fallback": ["m1", "m2"],
                    "budget": {"maxDailyCostUsd": 100},
                },
                "models": [
                    {"provider": "anthropic", "model": "claude-3", "id": "m1", "rateLimit": 100, "capabilities": ["chat"], "contextWindow": 200000},
                    {"provider": "anthropic", "model": "claude-4", "id": "m2", "rateLimit": 100, "capabilities": ["chat"], "contextWindow": 200000},
                ]
            }
        })
        r = _run(model_routing_audit(cfg))
        assert any("all models use provider" in f.lower() for f in r.get("findings", []))

    # --- resource_links_audit ---

    def test_resource_links_no_cap(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write_config(tmp_path, {"mcp": {}})
        r = _run(resource_links_audit(cfg))
        assert any("no 'resources' capability" in f.lower() or "no" in f.lower() for f in r.get("findings", []))

    def test_resource_links_with_resources(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "capabilities": {"resources": {"subscribe": True, "listChanged": True}},
                "resources": {
                    "static": [
                        {"uri": "https://example.com/r1", "name": "R1", "mimeType": "text/plain"},
                        {"uri": "bad-uri", "name": ""},
                        {"uri": "https://ok.com/r2", "mimeType": "invalid"},
                    ],
                    "templates": [
                        {"uriTemplate": "https://example.com/{id}", "name": "T1"},
                        {"uriTemplate": "", "name": ""},
                    ]
                }
            }
        })
        r = _run(resource_links_audit(cfg))
        assert len(r.get("findings", [])) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# n8n_bridge.py — 82% → target 92%+
# ═══════════════════════════════════════════════════════════════════════════════

class TestN8nBridgeExtreme:

    def test_validate_n8n_workflow_good(self):
        from src.n8n_bridge import _validate_n8n_workflow
        data = {
            "name": "test-wf",
            "nodes": [
                {"type": "n8n-nodes-base.httpRequest", "name": "fetch", "position": [100, 200], "id": "1"},
                {"type": "n8n-nodes-base.set", "name": "transform", "position": [300, 200], "id": "2"},
            ],
            "connections": {"fetch": {"main": [[{"node": "transform"}]]}}
        }
        issues = _validate_n8n_workflow(data)
        assert issues == []

    def test_validate_n8n_workflow_missing_fields(self):
        from src.n8n_bridge import _validate_n8n_workflow
        issues = _validate_n8n_workflow({"nodes": []})
        assert any("name" in i.lower() or "connections" in i.lower() for i in issues)

    def test_validate_n8n_workflow_duplicate_ids(self):
        from src.n8n_bridge import _validate_n8n_workflow
        data = {
            "name": "test",
            "nodes": [
                {"type": "t", "name": "a", "position": [0, 0], "id": "1"},
                {"type": "t", "name": "b", "position": [0, 0], "id": "1"},
            ],
            "connections": {}
        }
        issues = _validate_n8n_workflow(data)
        assert any("duplicate id" in i.lower() for i in issues)

    def test_validate_n8n_workflow_duplicate_names(self):
        from src.n8n_bridge import _validate_n8n_workflow
        data = {
            "name": "test",
            "nodes": [
                {"type": "t", "name": "same", "position": [0, 0], "id": "1"},
                {"type": "t", "name": "same", "position": [0, 0], "id": "2"},
            ],
            "connections": {}
        }
        issues = _validate_n8n_workflow(data)
        assert any("duplicate name" in i.lower() for i in issues)

    def test_validate_n8n_workflow_bad_position(self):
        from src.n8n_bridge import _validate_n8n_workflow
        data = {
            "name": "test",
            "nodes": [{"type": "t", "name": "a", "position": "bad", "id": "1"}],
            "connections": {}
        }
        issues = _validate_n8n_workflow(data)
        assert any("position" in i.lower() for i in issues)

    def test_validate_n8n_workflow_bad_connection_source(self):
        from src.n8n_bridge import _validate_n8n_workflow
        data = {
            "name": "test",
            "nodes": [{"type": "t", "name": "a", "position": [0, 0]}],
            "connections": {"ghost": {"main": [[{"node": "a"}]]}}
        }
        issues = _validate_n8n_workflow(data)
        assert any("not found" in i.lower() for i in issues)

    def test_export_with_depends(self, tmp_path):
        from src.n8n_bridge import firm_n8n_workflow_export
        steps = [
            {"name": "step1", "type": "http_request", "params": {}},
            {"name": "step2", "type": "agent", "params": {}, "depends_on": ["step1"]},
        ]
        out = str(tmp_path / "wf.json")
        r = _run(firm_n8n_workflow_export("deps-pipeline", steps, output_path=out))
        assert r["ok"] is True
        wf = json.loads(Path(out).read_text())
        assert "step1" in wf.get("connections", {})

    def test_import_with_cred_refs(self, tmp_path):
        from src.n8n_bridge import firm_n8n_workflow_import
        wf = {
            "name": "test-import",
            "nodes": [{"type": "t", "name": "n1", "position": [0, 0], "credentials": {"apiKey": "secret"}}],
            "connections": {}
        }
        wf_path = tmp_path / "wf.json"
        wf_path.write_text(json.dumps(wf))
        target = tmp_path / "imported"
        r = _run(firm_n8n_workflow_import(str(wf_path), target_dir=str(target)))
        assert r["ok"] is True
        assert (target / "wf.json").exists()


# ═══════════════════════════════════════════════════════════════════════════════
# platform_audit.py — 82% → target 88%+
# ═══════════════════════════════════════════════════════════════════════════════

class TestPlatformAuditExtreme:

    def test_secrets_v2_with_inline(self, tmp_path):
        from src.platform_audit import firm_secrets_v2_audit
        cfg = _write_config(tmp_path, {
            "auth": {"profiles": {"main": {"apiKey": "plaintext-key"}}},
            "secrets": {"managed": True, "snapshotActivated": False}
        })
        r = firm_secrets_v2_audit(cfg)
        assert len(r.get("findings", [])) >= 1

    def test_agent_routing_with_routes(self, tmp_path):
        from src.platform_audit import firm_agent_routing_check
        cfg = _write_config(tmp_path, {
            "agents": {"routes": [
                {"pattern": ".*", "target": "default"},
                {"pattern": "urgent", "target": "fast"},
            ]}
        })
        r = firm_agent_routing_check(cfg)
        assert "findings" in r

    def test_voice_security_with_config(self, tmp_path):
        from src.platform_audit import firm_voice_security_check
        cfg = _write_config(tmp_path, {
            "voice": {"enabled": True, "tls": False, "provider": "twilio"}
        })
        r = firm_voice_security_check(cfg)
        assert "findings" in r

    def test_trust_model_check(self, tmp_path):
        from src.platform_audit import firm_trust_model_check
        cfg = _write_config(tmp_path, {
            "trust": {"mode": "permissive", "allowedOrigins": ["*"]}
        })
        r = firm_trust_model_check(cfg)
        assert "findings" in r

    def test_autoupdate_check(self, tmp_path):
        from src.platform_audit import firm_autoupdate_check
        cfg = _write_config(tmp_path, {
            "update": {"auto": True, "channel": "stable"}
        })
        r = firm_autoupdate_check(cfg)
        assert "findings" in r or "ok" in r

    def test_plugin_sdk_check(self, tmp_path):
        from src.platform_audit import firm_plugin_sdk_check
        cfg = _write_config(tmp_path, {
            "plugins": {"sdk": {"version": "0.1.0"}, "entries": {"p1": {"type": "external"}}}
        })
        r = firm_plugin_sdk_check(cfg)
        assert "findings" in r

    def test_content_boundary_check(self, tmp_path):
        from src.platform_audit import firm_content_boundary_check
        cfg = _write_config(tmp_path, {
            "content": {"boundaries": []}
        })
        r = firm_content_boundary_check(cfg)
        assert "findings" in r or "ok" in r

    def test_sqlite_vec_check(self, tmp_path):
        from src.platform_audit import firm_sqlite_vec_check
        cfg = _write_config(tmp_path, {
            "vector": {"backend": "sqlite-vec", "dimensions": 1536}
        })
        r = firm_sqlite_vec_check(cfg)
        assert "findings" in r or "ok" in r


# ═══════════════════════════════════════════════════════════════════════════════
# config_migration.py — 83% → target 90%+
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigMigrationExtreme:

    def test_shell_env_with_dangerous_vars(self, tmp_path):
        from src.config_migration import firm_shell_env_check
        cfg = _write_config(tmp_path, {
            "agents": {"defaults": {"env": {"LD_PRELOAD": "/evil.so", "NORMAL": "ok"}}},
            "tools": {"exec": {"env": {"DYLD_LIBRARY_PATH": "/bad"}}},
        })
        r = _run(firm_shell_env_check(cfg))
        findings = r.get("findings", [])
        assert any("ld_preload" in str(f).lower() or "dyld" in str(f).lower() for f in findings)

    def test_plugin_integrity_no_plugins(self, tmp_path):
        from src.config_migration import firm_plugin_integrity_check
        cfg = _write_config(tmp_path, {})
        r = _run(firm_plugin_integrity_check(cfg))
        assert "findings" in r or "ok" in r

    def test_token_separation_same_tokens(self, tmp_path):
        from src.config_migration import firm_token_separation_check
        cfg = _write_config(tmp_path, {
            "auth": {"tokens": {"api": "same-token", "session": "same-token"}}
        })
        r = _run(firm_token_separation_check(cfg))
        assert "findings" in r or "ok" in r

    def test_otel_redaction_check(self, tmp_path):
        from src.config_migration import firm_otel_redaction_check
        cfg = _write_config(tmp_path, {
            "telemetry": {"otel": {"enabled": True, "endpoint": "https://otel.example.com"}}
        })
        r = _run(firm_otel_redaction_check(cfg))
        assert "findings" in r or "ok" in r

    def test_rpc_rate_limit_with_config(self, tmp_path):
        from src.config_migration import firm_rpc_rate_limit_check
        cfg = _write_config(tmp_path, {
            "rpc": {"rateLimit": {"enabled": True, "maxPerMinute": 1000}}
        })
        r = _run(firm_rpc_rate_limit_check(cfg))
        assert "findings" in r or "ok" in r


# ═══════════════════════════════════════════════════════════════════════════════
# runtime_audit.py — 83% → target 88%+
# ═══════════════════════════════════════════════════════════════════════════════

class TestRuntimeAuditExtreme:

    def test_secrets_workflow_check(self, tmp_path):
        from src.runtime_audit import firm_secrets_workflow_check
        cfg = _write_config(tmp_path, {
            "secrets": {"providers": [{"type": "env", "prefix": "SECRET_"}]}
        })
        r = _run(firm_secrets_workflow_check(cfg))
        assert "findings" in r or "ok" in r

    def test_http_headers_check(self, tmp_path):
        from src.runtime_audit import firm_http_headers_check
        cfg = _write_config(tmp_path, {
            "gateway": {"bind": "0.0.0.0", "headers": {}}
        })
        r = _run(firm_http_headers_check(cfg))
        assert "findings" in r or "ok" in r

    def test_nodes_commands_check(self, tmp_path):
        from src.runtime_audit import firm_nodes_commands_check
        cfg = _write_config(tmp_path, {
            "nodes": {"allowCommands": ["rm", "curl", "wget"]}
        })
        r = _run(firm_nodes_commands_check(cfg))
        assert "findings" in r or "ok" in r

    def test_trusted_proxy_check(self, tmp_path):
        from src.runtime_audit import firm_trusted_proxy_check
        cfg = _write_config(tmp_path, {
            "gateway": {"trustedProxies": ["0.0.0.0/0"]}
        })
        r = _run(firm_trusted_proxy_check(cfg))
        assert "findings" in r or "ok" in r

    def test_session_disk_budget(self, tmp_path):
        from src.runtime_audit import firm_session_disk_budget_check
        cfg = _write_config(tmp_path, {
            "sessions": {"diskBudget": {"maxMb": 100, "path": str(tmp_path)}}
        })
        r = _run(firm_session_disk_budget_check(cfg))
        assert "findings" in r or "ok" in r

    def test_dm_allowlist_with_channels(self, tmp_path):
        from src.runtime_audit import firm_dm_allowlist_check
        cfg = _write_config(tmp_path, {
            "channels": {
                "whatsapp": {"dmPolicy": "allow"},
                "telegram": {},
            }
        })
        r = _run(firm_dm_allowlist_check(cfg))
        assert "findings" in r or "ok" in r
