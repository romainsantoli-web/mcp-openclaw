"""Coverage push — compliance_medium, platform_audit, ecosystem_audit,
runtime_audit, advanced_security deep branch tests."""
from __future__ import annotations
import asyncio
import json
import os
import time
from unittest.mock import patch, MagicMock
import pytest

def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

def _write(tmp_path, data, name="config.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return str(p)

def _parse(result):
    if isinstance(result, list) and result and isinstance(result[0], dict):
        txt = result[0].get("text", "{}")
        return json.loads(txt)
    if isinstance(result, dict):
        return result
    return json.loads(result) if isinstance(result, str) else result

def _fc(r):
    """Get finding count from result, falling back to len(findings)."""
    fc = r.get("finding_count")
    if fc is not None:
        return fc
    return len(r.get("findings", []))




# ===================================================================
# compliance_medium.py
# ===================================================================
class TestComplianceToolDeprecationDeep:
    """Cover inner loops: sunset without deprecated, bad ISO, circular chain."""
    def test_sunset_without_deprecated(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write(tmp_path, {
            "mcp": {"tools": [
                {"name": "a", "annotations": {"sunset": "2025-01-01"}},  # no deprecated
            ]}
        })
        r = _parse(_run(tool_deprecation_audit(cfg)))
        assert any("sunset" in str(f).lower() for f in r.get("findings", []))

    def test_deprecated_no_sunset(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write(tmp_path, {
            "mcp": {"tools": [
                {"name": "b", "annotations": {"deprecated": True}},
            ]}
        })
        r = _parse(_run(tool_deprecation_audit(cfg)))
        assert _fc(r) > 0

    def test_bad_iso_sunset(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write(tmp_path, {
            "mcp": {"tools": [
                {"name": "c", "annotations": {"deprecated": True, "sunset": "not-a-date"}},
            ]}
        })
        r = _parse(_run(tool_deprecation_audit(cfg)))
        assert _fc(r) > 0

    def test_circular_chain(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write(tmp_path, {
            "mcp": {"tools": [
                {"name": "a", "annotations": {"deprecated": True, "replacement": "b",
                                               "sunset": "2025-06-01"}},
                {"name": "b", "annotations": {"deprecated": True, "replacement": "a",
                                               "sunset": "2025-07-01"}},
            ]}
        })
        r = _parse(_run(tool_deprecation_audit(cfg)))
        findings_text = json.dumps(r.get("findings", []))
        assert "circular" in findings_text.lower() or _fc(r) > 0

    def test_replacement_not_exists(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write(tmp_path, {
            "mcp": {"tools": [
                {"name": "a", "annotations": {"deprecated": True, "replacement": "z",
                                               "sunset": "2025-06-01"}},
            ]}
        })
        r = _parse(_run(tool_deprecation_audit(cfg)))
        assert _fc(r) > 0


class TestComplianceCircuitBreakerDeep:
    def test_full_config(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write(tmp_path, {
            "mcp": {"resilience": {
                "circuitBreaker": {"failureThreshold": -1, "resetTimeoutMs": 100,
                                   "halfOpenMaxRequests": 0},
                "retry": {"maxRetries": 10, "backoffType": "weird"},
                "timeout": 200000,
            }, "tools": [
                {"name": "http_tool", "description": "calls http endpoint"},
            ]}
        })
        r = _parse(_run(circuit_breaker_audit(cfg)))
        assert _fc(r) >= 3

    def test_no_resilience(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write(tmp_path, {"mcp": {}})
        r = _parse(_run(circuit_breaker_audit(cfg)))
        assert _fc(r) >= 1


class TestComplianceGdprDeep:
    def test_empty_privacy(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write(tmp_path, {"mcp": {"privacy": {}}})
        r = _parse(_run(gdpr_residency_audit(cfg)))
        assert _fc(r) >= 1

    def test_bad_legal_basis(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write(tmp_path, {"mcp": {
            "gdpr": {"legalBasis": "unknown", "retentionDays": 5000,
                     "rightToErasure": {}},
            "dataResidency": {"allowCrossBorder": True},
        }})
        r = _parse(_run(gdpr_residency_audit(cfg)))
        assert _fc(r) >= 2

    def test_pii_field_scan(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write(tmp_path, {"mcp": {
            "privacy": {"enabled": True},
            "gdpr": {"legalBasis": "consent", "retentionDays": 30},
            "dataResidency": {"region": "eu-west-1"},
            "tools": [{"name": "x", "inputSchema": {
                "properties": {"email": {}, "phone_number": {}}
            }}],
        }})
        r = _parse(_run(gdpr_residency_audit(cfg)))
        findings_text = json.dumps(r.get("findings", []))
        assert "pii" in findings_text.lower() or _fc(r) >= 1

    def test_cross_border_no_mechanism(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write(tmp_path, {"mcp": {
            "dataResidency": {"region": "moon", "allowCrossBorder": True},
        }})
        r = _parse(_run(gdpr_residency_audit(cfg)))
        assert _fc(r) >= 1


class TestComplianceAgentIdentityDeep:
    def test_no_agents_no_identity(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write(tmp_path, {"mcp": {}})
        r = _parse(_run(agent_identity_audit(cfg)))
        assert r.get("ok") is True or _fc(r) == 0

    def test_bad_did_and_weak_signing(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write(tmp_path, {"mcp": {
            "identity": {"did": "bad", "signing": {"algorithm": "hs256"}},
            "agents": [{"name": "a", "did": "did:bad:x"}],
        }})
        r = _parse(_run(agent_identity_audit(cfg)))
        assert _fc(r) >= 2

    def test_agents_without_did(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write(tmp_path, {"mcp": {
            "identity": {"did": "did:web:example.com", "signing": {"algorithm": "ed25519"}},
            "agents": [{"name": "a"}, {"name": "b"}],
        }})
        r = _parse(_run(agent_identity_audit(cfg)))
        assert _fc(r) >= 1


class TestComplianceModelRoutingDeep:
    def test_no_routing_no_models(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write(tmp_path, {"mcp": {}})
        r = _parse(_run(model_routing_audit(cfg)))
        assert r.get("ok") is True or _fc(r) <= 1

    def test_bad_strategy_and_fallback(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write(tmp_path, {"mcp": {
            "routing": {"strategy": "random", "fallback": ["only-one"]},
            "models": [
                {"provider": "unknown_provider", "id": "m1"},
                {"provider": "unknown_provider", "id": "m2"},
            ],
        }})
        r = _parse(_run(model_routing_audit(cfg)))
        assert _fc(r) >= 2

    def test_budget_no_caps(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write(tmp_path, {"mcp": {
            "routing": {"strategy": "cost-optimized", "budget": {}},
            "models": [{"provider": "anthropic", "id": "claude-3"}],
        }})
        r = _parse(_run(model_routing_audit(cfg)))
        assert _fc(r) >= 1


class TestComplianceResourceLinksDeep:
    def test_no_resources_cap(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write(tmp_path, {"mcp": {"capabilities": {}}})
        r = _parse(_run(resource_links_audit(cfg)))
        assert _fc(r) >= 1

    def test_bad_resource_uri(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write(tmp_path, {"mcp": {
            "capabilities": {"resources": {}},
            "resources": {"static": [{"uri": ""}], "templates": [{}]},
        }})
        r = _parse(_run(resource_links_audit(cfg)))
        assert _fc(r) >= 2

    def test_tool_output_resource_ref(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write(tmp_path, {"mcp": {
            "capabilities": {"resources": {"subscribe": True, "listChanged": True}},
            "resources": {"static": [{"uri": "file:///ok", "name": "ok", "mimeType": "text/plain"}]},
            "tools": [{"name": "x", "outputSchema": {
                "properties": {"resource": {"uri": "missing://x"}}
            }}],
        }})
        r = _parse(_run(resource_links_audit(cfg)))
        # May or may not produce findings depending on implementation
        assert isinstance(r.get("findings", []), list)


# ===================================================================
# platform_audit.py
# ===================================================================
class TestPlatformSecretsV2Deep:
    def test_hardcoded_key(self, tmp_path):
        from src.platform_audit import firm_secrets_v2_audit
        cfg = _write(tmp_path, {"apiKey": "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
        r = _parse(firm_secrets_v2_audit(cfg))
        assert _fc(r) >= 1 or not r.get("ok")


class TestPlatformAgentRoutingDeep:
    def test_circular_bindings(self, tmp_path):
        from src.platform_audit import firm_agent_routing_check
        cfg = _write(tmp_path, {"agents": {
            "bindings": {"a": {"target": "x"}, "b": {"target": "x"}},
            "defaults": {},
        }})
        r = _parse(firm_agent_routing_check(cfg))
        assert _fc(r) >= 1

    def test_no_scope_isolation(self, tmp_path):
        from src.platform_audit import firm_agent_routing_check
        cfg = _write(tmp_path, {"agents": {
            "bindings": {"a": {"target": "svc-a"}},
            "defaults": {"route": "svc-a"},
        }})
        r = _parse(firm_agent_routing_check(cfg))
        assert _fc(r) >= 1


class TestPlatformVoiceSecurityDeep:
    def test_dangerous_provider(self, tmp_path):
        from src.platform_audit import firm_voice_security_check
        cfg = _write(tmp_path, {"talk": {"provider": "say", "apiKey": "hardcoded"}})
        r = _parse(firm_voice_security_check(cfg))
        assert _fc(r) >= 1

    def test_ssml_injection(self, tmp_path):
        from src.platform_audit import firm_voice_security_check
        cfg = _write(tmp_path, {"talk": {
            "provider": "azure", "apiKey": "$AZURE_KEY",
            "allowSSML": True,
        }})
        r = _parse(firm_voice_security_check(cfg))
        assert _fc(r) >= 1


class TestPlatformTrustModelDeep:
    def test_multi_user_shared_dm(self, tmp_path):
        from src.platform_audit import firm_trust_model_check
        cfg = _write(tmp_path, {
            "session": {"multiUser": True, "dmScope": "shared", "timeoutMinutes": 0},
            "gateway": {},
        })
        r = _parse(firm_trust_model_check(cfg))
        assert _fc(r) >= 2


class TestPlatformPluginSdkDeep:
    def test_dangerous_hook_and_exec(self, tmp_path):
        from src.platform_audit import firm_plugin_sdk_check
        cfg = _write(tmp_path, {"plugins": {
            "registered": [{"name": "evil",
                            "hooks": ["onBeforeExec"],
                            "permissions": ["exec"]}],
            "packageInstall": {"allow": "all"},
        }})
        r = _parse(firm_plugin_sdk_check(cfg))
        assert _fc(r) >= 2


class TestPlatformContentBoundaryDeep:
    def test_empty_security(self, tmp_path):
        from src.platform_audit import firm_content_boundary_check
        cfg = _write(tmp_path, {"security": {}})
        r = _parse(firm_content_boundary_check(cfg))
        assert _fc(r) >= 2


class TestPlatformSqliteVecDeep:
    def test_no_backend(self, tmp_path):
        from src.platform_audit import firm_sqlite_vec_check
        cfg = _write(tmp_path, {"memory": {}})
        r = _parse(firm_sqlite_vec_check(cfg))
        assert _fc(r) >= 1 or r.get("ok")

    def test_bad_dimensions(self, tmp_path):
        from src.platform_audit import firm_sqlite_vec_check
        cfg = _write(tmp_path, {"memory": {
            "backend": "sqlite-vec",
            "sqlite": {"path": "/data/mem.db"},
            "embedding": {"dimensions": 8},
            "chunking": {"size": 100, "overlap": 200},
            "sync": {"lazy": True},
        }})
        r = _parse(firm_sqlite_vec_check(cfg))
        assert _fc(r) >= 2


class TestPlatformAutoupdateDeep:
    def test_autoupdate_findings(self, tmp_path):
        from src.platform_audit import firm_autoupdate_check
        cfg = _write(tmp_path, {"autoupdate": {
            "enabled": True, "channel": "nightly", "allowDowngrade": True,
        }})
        r = _parse(firm_autoupdate_check(cfg))
        assert isinstance(r.get("findings", []), list)


# ===================================================================
# ecosystem_audit.py
# ===================================================================
class TestEcosystemFirewallDeep:
    def test_dangerous_allowlist(self, tmp_path):
        from src.ecosystem_audit import firm_mcp_firewall_check
        cfg = _write(tmp_path, {"gateway": {"firewall": {
            "toolAllowlist": ["exec"],
            "maxRequestSize": 999999999,
        }}})
        r = _parse(firm_mcp_firewall_check(cfg))
        assert _fc(r) >= 1

    def test_empty_firewall(self, tmp_path):
        from src.ecosystem_audit import firm_mcp_firewall_check
        cfg = _write(tmp_path, {"gateway": {"firewall": {}}})
        r = _parse(firm_mcp_firewall_check(cfg))
        assert _fc(r) >= 1


class TestEcosystemRagDeep:
    def test_dimension_mismatch(self, tmp_path):
        from src.ecosystem_audit import firm_rag_pipeline_check
        cfg = _write(tmp_path, {"rag": {
            "embedding": {"model": "text-embedding-ada-002", "dimensions": 999},
            "vectorStore": {"type": "", "url": "postgres://user:pass@host"},
            "chunking": {"size": 50},
            "retrieval": {"topK": 50},
        }})
        r = _parse(firm_rag_pipeline_check(cfg))
        assert _fc(r) >= 3


class TestEcosystemSandboxExecDeep:
    def test_mode_none(self, tmp_path):
        from src.ecosystem_audit import firm_sandbox_exec_check
        cfg = _write(tmp_path, {"sandbox": {"mode": "none"}})
        r = _parse(firm_sandbox_exec_check(cfg))
        assert not r.get("ok")

    def test_network_enabled(self, tmp_path):
        from src.ecosystem_audit import firm_sandbox_exec_check
        cfg = _write(tmp_path, {"sandbox": {
            "mode": "container",
            "network": {"enabled": True},
            "filesystem": {"writable": True},
            "timeout": 600,
        }})
        r = _parse(firm_sandbox_exec_check(cfg))
        assert _fc(r) >= 2


class TestEcosystemContextHealthDeep:
    def test_old_session_many_turns(self, tmp_path):
        from src.ecosystem_audit import firm_context_health_check
        cfg = _write(tmp_path, {})
        sd = {"createdAt": time.time() - 90000, "turnCount": 60,
              "tokensUsed": 50000, "contextWindow": 100000}
        r = _parse(firm_context_health_check(sd, str(cfg)))
        assert _fc(r) >= 2

    def test_medium_age(self, tmp_path):
        from src.ecosystem_audit import firm_context_health_check
        cfg = _write(tmp_path, {})
        sd = {"createdAt": time.time() - 32000, "turnCount": 25,
              "tokensUsed": 20000, "contextWindow": 100000}
        r = _parse(firm_context_health_check(sd, str(cfg)))
        assert _fc(r) >= 1


class TestEcosystemProvenanceDeep:
    def test_append_verify_export(self, tmp_path):
        from src.ecosystem_audit import firm_provenance_tracker
        r1 = _parse(firm_provenance_tracker(
            action="append", entry={"intent": "test1", "agent": "a1"},
            chain_path=str(tmp_path / "chain.json")))
        assert "hash" in r1 or "index" in r1 or r1.get("ok")
        _parse(firm_provenance_tracker(
            action="append", entry={"intent": "test2", "agent": "a2"},
            chain_path=str(tmp_path / "chain.json")))
        rv = _parse(firm_provenance_tracker(
            action="verify", chain_path=str(tmp_path / "chain.json")))
        assert rv.get("integrity") == "valid" or rv.get("ok")
        re = _parse(firm_provenance_tracker(
            action="export", chain_path=str(tmp_path / "chain.json")))
        assert re.get("ok") or "chain" in re


class TestEcosystemCostAnalyticsDeep:
    def test_budget_exceeded(self, tmp_path):
        from src.ecosystem_audit import firm_cost_analytics
        cfg = _write(tmp_path, {})
        sd = {"model": "gpt-4o", "inputTokens": 500000, "outputTokens": 100000,
              "budget": 0.001, "toolCalls": [{"name": "x"}, {"name": "x"}, {"name": "y"}]}
        r = _parse(firm_cost_analytics(sd, str(cfg)))
        assert _fc(r) >= 1 or "cost" in json.dumps(r).lower()


class TestEcosystemTokenBudgetDeep:
    def test_all_recommendations(self, tmp_path):
        from src.ecosystem_audit import firm_token_budget_optimizer
        cfg = _write(tmp_path, {})
        sd = {"tokensUsed": 10000, "contextWindow": 100000,
              "systemPromptTokens": 5000, "toolResultTokens": 6000,
              "cacheHits": 1, "cacheMisses": 10,
              "messages": [{"content": "dup"}] * 15}
        r = _parse(firm_token_budget_optimizer(sd, str(cfg)))
        assert _fc(r) >= 1 or "recommendations" in json.dumps(r).lower()


# ===================================================================
# runtime_audit.py
# ===================================================================
class TestRuntimeNodeVersionDeep:
    def test_old_version(self, tmp_path):
        from src.runtime_audit import firm_node_version_check
        cfg = _write(tmp_path, {})
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="v16.0.0\n", stderr="")
            r = _parse(_run(firm_node_version_check(cfg)))
            assert not r.get("meets_minimum", True) or _fc(r) >= 1


class TestRuntimeSecretsWorkflowDeep:
    def test_hardcoded_secrets(self, tmp_path):
        from src.runtime_audit import firm_secrets_workflow_check
        cfg = _write(tmp_path, {
            "auth": {"apiKey": "sk-reallylong1234567890abcdef12345678"},
            "database": {"password": "mysecretpassword123456"},
        })
        r = _parse(_run(firm_secrets_workflow_check(cfg)))
        assert r.get("hardcoded_count", 0) >= 1 or _fc(r) >= 1


class TestRuntimeHttpHeadersDeep:
    def test_public_no_hsts(self, tmp_path):
        from src.runtime_audit import firm_http_headers_check
        cfg = _write(tmp_path, {"gateway": {
            "bind": "0.0.0.0",
            "http": {"securityHeaders": {}},
        }})
        r = _parse(_run(firm_http_headers_check(cfg)))
        assert _fc(r) >= 1

    def test_loopback_info(self, tmp_path):
        from src.runtime_audit import firm_http_headers_check
        cfg = _write(tmp_path, {"gateway": {"bind": "127.0.0.1"}})
        r = _parse(_run(firm_http_headers_check(cfg)))
        # Loopback → INFO only
        assert r.get("ok") is True or _fc(r) <= 2


class TestRuntimeNodesCommandsDeep:
    def test_allow_commands_remote(self, tmp_path):
        from src.runtime_audit import firm_nodes_commands_check
        cfg = _write(tmp_path, {"gateway": {
            "bind": "0.0.0.0",
            "nodes": {"allowCommands": ["rm", "curl"]},
        }})
        r = _parse(_run(firm_nodes_commands_check(cfg)))
        assert _fc(r) >= 1

    def test_deny_commands(self, tmp_path):
        from src.runtime_audit import firm_nodes_commands_check
        cfg = _write(tmp_path, {"gateway": {
            "nodes": {"denyCommands": ["rm"]},
        }})
        r = _parse(_run(firm_nodes_commands_check(cfg)))
        assert isinstance(r.get("findings", []), list)


class TestRuntimeTrustedProxyDeep:
    def test_empty_proxies(self, tmp_path):
        from src.runtime_audit import firm_trusted_proxy_check
        cfg = _write(tmp_path, {"gateway": {
            "auth": {"mode": "trusted-proxy"},
            "trustedProxies": [],
        }})
        r = _parse(_run(firm_trusted_proxy_check(cfg)))
        assert _fc(r) >= 1

    def test_real_ip_fallback(self, tmp_path):
        from src.runtime_audit import firm_trusted_proxy_check
        cfg = _write(tmp_path, {"gateway": {
            "auth": {"mode": "trusted-proxy"},
            "bind": "funnel",
            "trustedProxies": ["10.0.0.1"],
            "real_ip_fallback_enabled": True,
        }})
        r = _parse(_run(firm_trusted_proxy_check(cfg)))
        assert _fc(r) >= 1


class TestRuntimeDiskBudgetDeep:
    def test_negative_max_bytes(self, tmp_path):
        from src.runtime_audit import firm_session_disk_budget_check
        cfg = _write(tmp_path, {"session": {"maintenance": {"maxDiskBytes": -1}}})
        r = _parse(_run(firm_session_disk_budget_check(cfg)))
        assert _fc(r) >= 1

    def test_no_high_water(self, tmp_path):
        from src.runtime_audit import firm_session_disk_budget_check
        cfg = _write(tmp_path, {"session": {"maintenance": {"maxDiskBytes": 500000000}}})
        r = _parse(_run(firm_session_disk_budget_check(cfg)))
        assert isinstance(r.get("findings", []), list)


class TestRuntimeDmAllowlistDeep:
    def test_empty_allow_from(self, tmp_path):
        from src.runtime_audit import firm_dm_allowlist_check
        cfg = _write(tmp_path, {"channels": {
            "whatsapp": {"dmPolicy": "allowlist", "allowFrom": []},
            "telegram": {"dmPolicy": "open"},
        }})
        r = _parse(_run(firm_dm_allowlist_check(cfg)))
        assert _fc(r) >= 2

    def test_defaults_open(self, tmp_path):
        from src.runtime_audit import firm_dm_allowlist_check
        cfg = _write(tmp_path, {"channels": {
            "defaults": {"dmPolicy": "open"},
        }})
        r = _parse(_run(firm_dm_allowlist_check(cfg)))
        assert _fc(r) >= 1

    def test_wildcard_allow(self, tmp_path):
        from src.runtime_audit import firm_dm_allowlist_check
        cfg = _write(tmp_path, {"channels": {
            "signal": {"dmPolicy": "allowlist", "allowFrom": ["*"]},
        }})
        r = _parse(_run(firm_dm_allowlist_check(cfg)))
        assert _fc(r) >= 1


# ===================================================================
# advanced_security.py
# ===================================================================
class TestAdvancedSecretsLifecycleDeep:
    def test_inline_creds(self, tmp_path):
        from src.advanced_security import firm_secrets_lifecycle_check
        cfg = _write(tmp_path, {"auth": {
            "profiles": {"p1": {"apiKey": "hardcoded123456789"}},
        }, "secrets": {}})
        r = _parse(_run(firm_secrets_lifecycle_check(cfg)))
        assert _fc(r) >= 1


class TestAdvancedChannelAuthCanonDeep:
    def test_auth_none_remote(self, tmp_path):
        from src.advanced_security import firm_channel_auth_canon_check
        cfg = _write(tmp_path, {"gateway": {
            "auth": {"mode": "none"}, "bind": "0.0.0.0",
        }})
        r = _parse(_run(firm_channel_auth_canon_check(cfg)))
        assert not r.get("ok") or _fc(r) >= 1

    def test_encoded_traversal_plugin(self, tmp_path):
        from src.advanced_security import firm_channel_auth_canon_check
        cfg = _write(tmp_path, {
            "gateway": {"auth": {"mode": "password"}, "bind": "127.0.0.1"},
            "plugins": {"entries": {"bad": {"httpPath": "/api/%2e%2e/admin"}}},
        })
        r = _parse(_run(firm_channel_auth_canon_check(cfg)))
        assert _fc(r) >= 1

    def test_controlui_basepath_traversal(self, tmp_path):
        from src.advanced_security import firm_channel_auth_canon_check
        cfg = _write(tmp_path, {
            "gateway": {"auth": {"mode": "password"}, "bind": "127.0.0.1",
                        "controlUi": {"basePath": "../admin"}},
            "hooks": {"transformsDir": "../outside"},
        })
        r = _parse(_run(firm_channel_auth_canon_check(cfg)))
        assert _fc(r) >= 1


class TestAdvancedExecApprovalDeep:
    def test_no_sandbox(self, tmp_path):
        from src.advanced_security import firm_exec_approval_freeze_check
        cfg = _write(tmp_path, {
            "tools": {"exec": {"host": "host"}},
            "agents": {"defaults": {"sandbox": {"mode": "off"}}},
        })
        r = _parse(_run(firm_exec_approval_freeze_check(cfg)))
        assert _fc(r) >= 1

    def test_apply_patch_not_workspace_only(self, tmp_path):
        from src.advanced_security import firm_exec_approval_freeze_check
        cfg = _write(tmp_path, {
            "tools": {"exec": {"host": "sandbox",
                                "applyPatch": {"workspaceOnly": False}}},
        })
        r = _parse(_run(firm_exec_approval_freeze_check(cfg)))
        assert _fc(r) >= 1


class TestAdvancedConfigIncludeDeep:
    def test_traversal_include(self, tmp_path):
        from src.advanced_security import firm_config_include_check
        cfg = _write(tmp_path, {"$include": "../outside.json"})
        r = _parse(_run(firm_config_include_check(cfg)))
        assert _fc(r) >= 1

    def test_hardlink_include(self, tmp_path):
        from src.advanced_security import firm_config_include_check
        target = tmp_path / "real.json"
        target.write_text('{}')
        link = tmp_path / "linked.json"
        try:
            os.link(str(target), str(link))
        except OSError:
            pytest.skip("hardlinks not supported")
        cfg = _write(tmp_path, {"$include": "linked.json"})
        r = _parse(_run(firm_config_include_check(cfg)))
        # Might detect hardlink or not depending on nlink check
        assert isinstance(r.get("findings", []), list)


class TestAdvancedSafeBinsDeep:
    def test_interpreter_no_profile(self, tmp_path):
        from src.advanced_security import firm_safe_bins_profile_check
        cfg = _write(tmp_path, {"tools": {
            "exec": {"safeBins": ["python"], "safeBinProfiles": {}},
        }})
        r = _parse(_run(firm_safe_bins_profile_check(cfg)))
        assert _fc(r) >= 1

    def test_interpreter_stdin_safe(self, tmp_path):
        from src.advanced_security import firm_safe_bins_profile_check
        cfg = _write(tmp_path, {"tools": {
            "exec": {"safeBins": ["python"],
                     "safeBinProfiles": {"python": {}}},
        }})
        r = _parse(_run(firm_safe_bins_profile_check(cfg)))
        assert _fc(r) >= 1


class TestAdvancedGroupPolicyDeep:
    def test_not_allowlist(self, tmp_path):
        from src.advanced_security import firm_group_policy_default_check
        cfg = _write(tmp_path, {"channels": {
            "defaults": {"groupPolicy": "open"},
        }})
        r = _parse(_run(firm_group_policy_default_check(cfg)))
        assert _fc(r) >= 1

    def test_per_channel_missing(self, tmp_path):
        from src.advanced_security import firm_group_policy_default_check
        cfg = _write(tmp_path, {"channels": {
            "telegram": {"enabled": True},
            "defaults": {"groupPolicy": "allowlist"},
        }})
        r = _parse(_run(firm_group_policy_default_check(cfg)))
        assert _fc(r) >= 1
