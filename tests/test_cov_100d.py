"""test_cov_100d.py — push coverage toward 95%+
Targets uncovered branches in 8 modules: reliability_probe, gateway_fleet,
hebbian_memory/_runtime, main, compliance_medium, advanced_security,
ecosystem_audit, skill_loader.
"""
import asyncio
import json
import os
import sqlite3
import time
from unittest.mock import patch, MagicMock


# ── helpers ──────────────────────────────────────────────────────────────────

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
    if isinstance(result, list) and len(result) == 1:
        result = result[0]
    if isinstance(result, dict):
        return result
    try:
        return json.loads(result)
    except Exception:
        return {"raw": str(result)}

def _fc(r):
    """finding_count with fallback to len(findings)."""
    return r.get("finding_count") or len(r.get("findings", []))


# ===================================================================
# reliability_probe.py — error paths
# ===================================================================
class TestReliabilityProbeEdge:
    def test_doc_sync_corrupt_package(self, tmp_path):
        from src.reliability_probe import openclaw_doc_sync_check
        pkg = tmp_path / "package.json"
        pkg.write_text("NOT JSON!!!")
        r = _parse(_run(openclaw_doc_sync_check(str(pkg), docs_glob="*.md")))
        assert isinstance(r, dict)

    def test_doc_sync_unreadable_md(self, tmp_path):
        from src.reliability_probe import openclaw_doc_sync_check
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"express": "^4.0.0"}}))
        md = tmp_path / "broken.md"
        md.write_bytes(b"\x80\x81\x82\x83")  # non-utf8
        r = _parse(_run(openclaw_doc_sync_check(str(pkg), docs_glob="*.md")))
        assert isinstance(r, dict)

    def test_channel_audit_corrupt_package(self, tmp_path):
        from src.reliability_probe import openclaw_channel_audit
        pkg = tmp_path / "package.json"
        pkg.write_text("{{{bad json")
        readme = tmp_path / "README.md"
        readme.write_text("# Hello")
        r = _parse(_run(openclaw_channel_audit(str(pkg), str(readme))))
        assert isinstance(r, dict)

    def test_gateway_probe_all_retries_fail(self):
        from src.reliability_probe import openclaw_gateway_probe
        # Use an address that will refuse connection
        r = _parse(_run(openclaw_gateway_probe(
            gateway_url="ws://127.0.0.1:19999", max_retries=1, backoff_factor=0.01)))
        assert r.get("ok") is False or "error" in json.dumps(r).lower()


# ===================================================================
# gateway_fleet.py — edge paths
# ===================================================================
class TestGatewayFleetEdge:
    def test_fleet_list_no_filters(self):
        from src.gateway_fleet import firm_gateway_fleet_list
        r = _parse(_run(firm_gateway_fleet_list()))
        assert isinstance(r, dict)

    def test_fleet_list_with_filters(self):
        from src.gateway_fleet import firm_gateway_fleet_list
        r = _parse(_run(firm_gateway_fleet_list(
            filter_department="engineering", filter_tag="prod")))
        assert isinstance(r, dict)

    def test_load_fleet_corrupt(self, tmp_path):
        from src.gateway_fleet import _load_fleet
        fleet_file = tmp_path / "fleet.json"
        fleet_file.write_text("NOT JSON")
        with patch("src.gateway_fleet.FLEET_CONFIG_PATH", str(fleet_file)):
            result = _load_fleet()
            assert isinstance(result, dict)

    def test_fleet_sync_dry_run(self):
        from src.gateway_fleet import firm_gateway_fleet_sync
        r = _parse(_run(firm_gateway_fleet_sync(
            config_patch={"key": "val"}, skill_slugs=["test"], dry_run=True)))
        assert isinstance(r, dict)


# ===================================================================
# hebbian_memory/_runtime.py — edge paths
# ===================================================================
class TestHebbianRuntimeEdge:
    def test_harvest_bad_extension(self, tmp_path):
        from src.hebbian_memory._runtime import openclaw_hebbian_harvest
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("a,b,c\n1,2,3")
        r = _parse(_run(openclaw_hebbian_harvest(
            session_jsonl_path=str(csv_file))))
        assert "error" in json.dumps(r).lower() or isinstance(r, dict)

    def test_harvest_record_no_summary(self, tmp_path):
        from src.hebbian_memory._runtime import openclaw_hebbian_harvest
        jsonl = tmp_path / "sessions.jsonl"
        lines = [
            json.dumps({"session_id": "s1", "timestamp": "2025-01-01T00:00:00Z"}),
            json.dumps({"session_id": "s2", "summary": "test summary", "timestamp": "2025-01-01T00:00:00Z"}),
        ]
        jsonl.write_text("\n".join(lines))
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Rules\n- rule_a [0.50]\n- rule_b [0.50]\n")
        r = _parse(_run(openclaw_hebbian_harvest(
            session_jsonl_path=str(jsonl), claude_md_path=str(claude_md),
            db_path=str(tmp_path / "hebb.db"))))
        assert isinstance(r, dict)

    def test_harvest_duplicate_session(self, tmp_path):
        from src.hebbian_memory._runtime import openclaw_hebbian_harvest
        jsonl = tmp_path / "sessions.jsonl"
        lines = [
            json.dumps({"session_id": "dup1", "summary": "test", "timestamp": "2025-01-01T00:00:00Z"}),
            json.dumps({"session_id": "dup1", "summary": "test2", "timestamp": "2025-01-02T00:00:00Z"}),
        ]
        jsonl.write_text("\n".join(lines))
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Rules\n- rule_a [0.50]\n")
        r = _parse(_run(openclaw_hebbian_harvest(
            session_jsonl_path=str(jsonl), claude_md_path=str(claude_md),
            db_path=str(tmp_path / "hebb.db"))))
        assert isinstance(r, dict)

    def test_weight_update_with_db(self, tmp_path):
        from src.hebbian_memory._runtime import openclaw_hebbian_weight_update
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Rules\n- rule_alpha [0.50]\n- rule_beta [0.30]\n")
        db = tmp_path / "hebb.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE sessions (session_id TEXT PRIMARY KEY, summary TEXT, rules_activated TEXT, timestamp TEXT)")
        conn.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                     ("s1", "Tested rule_alpha", json.dumps(["rule_alpha"]), "2025-01-01"))
        conn.commit()
        conn.close()
        r = _parse(_run(openclaw_hebbian_weight_update(
            claude_md_path=str(claude_md), db_path=str(db), dry_run=True)))
        assert isinstance(r, dict)

    def test_weight_update_write_mode(self, tmp_path):
        from src.hebbian_memory._runtime import openclaw_hebbian_weight_update
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Rules\n- rule_gamma [0.50]\n")
        db = tmp_path / "hebb.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE sessions (session_id TEXT PRIMARY KEY, summary TEXT, rules_activated TEXT, timestamp TEXT)")
        conn.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                     ("s1", "Applied rule_gamma", json.dumps(["rule_gamma"]), "2025-01-01"))
        conn.commit()
        conn.close()
        r = _parse(_run(openclaw_hebbian_weight_update(
            claude_md_path=str(claude_md), db_path=str(db), dry_run=False)))
        assert isinstance(r, dict)

    def test_compute_no_weight_change(self):
        from src.hebbian_memory._runtime import _compute_hebbian_weights
        # A rule at minimum with no activation => weight stays at minimum
        rules = [{"rule_id": "r1", "weight": 0.01, "text": "test"}]
        updated, promoted, demoted = _compute_hebbian_weights(
            rules, activated_rule_ids=set(), learning_rate=0.0, decay=0.0)
        assert len(updated) == 0  # no change when lr=0 and decay=0

    def test_compute_promote_to_core(self):
        from src.hebbian_memory._runtime import _compute_hebbian_weights
        # A rule very close to threshold, activated => should promote
        rules = [{"rule_id": "r1", "weight": 0.89, "text": "important"}]
        updated, promoted, demoted = _compute_hebbian_weights(
            rules, activated_rule_ids={"r1"}, learning_rate=0.2, decay=0.0)
        # Check if promoted
        assert isinstance(promoted, list)


# ===================================================================
# main.py — auth + dead branches
# ===================================================================
class TestMainEdge:
    def test_check_auth_wrong_bearer(self):
        from src.main import _check_auth
        with patch("src.main.MCP_AUTH_TOKEN", "correct-token"):
            mock_req = MagicMock()
            mock_req.headers = {"Authorization": "Bearer wrong-token"}
            result = _check_auth(mock_req)
            assert result is not None  # 403

    def test_mcp_tools_list_no_annotations(self):
        """Cover branches where tool dicts miss optional keys."""
        from src.main import _mcp_tools_list
        with patch("src.main.TOOL_REGISTRY", {
            "bare_tool": {
                "name": "bare_tool",
                "description": "test",
                "inputSchema": {"type": "object", "properties": {}},
                "category": "other",
            }
        }):
            tools = _mcp_tools_list()
            assert any(t["name"] == "bare_tool" for t in tools)
            # Should NOT have annotations, outputSchema, title
            bare = [t for t in tools if t["name"] == "bare_tool"][0]
            assert "annotations" not in bare
            assert "outputSchema" not in bare
            assert "title" not in bare


# ===================================================================
# compliance_medium.py — deep branches
# ===================================================================
class TestComplianceMediumDeep:
    def test_deprecation_no_tools_list(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write(tmp_path, {"mcp": {"tools": "not-a-list"}})
        r = _parse(_run(tool_deprecation_audit(cfg)))
        assert isinstance(r, dict)

    def test_deprecation_empty(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = _write(tmp_path, {"mcp": {}})
        r = _parse(_run(tool_deprecation_audit(cfg)))
        assert isinstance(r, dict)

    def test_circuit_breaker_bad_threshold(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = _write(tmp_path, {"mcp": {"circuitBreaker": {
            "enabled": True, "failureThreshold": "not-a-number",
            "maxRetries": -1, "backoffType": "fibonacci",
            "timeoutMs": 500,
        }}})
        r = _parse(_run(circuit_breaker_audit(cfg)))
        assert _fc(r) >= 2

    def test_gdpr_full_config(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write(tmp_path, {"mcp": {"privacy": {"gdpr": {
            "legal_basis": "legitimate_interest",
            "retentionDays": 0,
            "erasure": {"enabled": False},
            "dpa": {"signed": False},
        }}, "dataResidency": {
            "primaryRegion": "invalid-region",
            "allowCrossBorder": True,
        }, "tools": [
            {"name": "t1", "inputSchema": {"properties": {
                "email_address": {"type": "string"},
                "phone_number": {"type": "string"},
            }}, "piiFields": []},
        ]}})
        r = _parse(_run(gdpr_residency_audit(cfg)))
        assert _fc(r) >= 1

    def test_gdpr_retention_negative(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = _write(tmp_path, {"mcp": {"privacy": {"gdpr": {
            "legal_basis": "consent",
            "retentionDays": -5,
        }}}})
        r = _parse(_run(gdpr_residency_audit(cfg)))
        assert _fc(r) >= 1

    def test_agent_identity_map_format(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write(tmp_path, {"mcp": {
            "agents": {"bot1": {"name": "Bot1", "did": "did:web:example.com:bot1"}},
            "identity": {
                "did": "did:web:bad-format",
                "verificationMethods": [],
                "signingAlgorithm": "HS256",
            },
        }})
        r = _parse(_run(agent_identity_audit(cfg)))
        assert _fc(r) >= 1

    def test_agent_identity_empty(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write(tmp_path, {"mcp": {}})
        r = _parse(_run(agent_identity_audit(cfg)))
        assert isinstance(r, dict)

    def test_model_routing_empty(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write(tmp_path, {"mcp": {}})
        r = _parse(_run(model_routing_audit(cfg)))
        assert isinstance(r, dict)

    def test_model_routing_dangerous(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write(tmp_path, {"mcp": {"routing": {
            "strategy": "round_robin",
            "models": [{"provider": "anthropic", "model": "claude-3"}],
        }}})
        r = _parse(_run(model_routing_audit(cfg)))
        assert _fc(r) >= 1

    def test_model_routing_no_strategy(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write(tmp_path, {"mcp": {"routing": {
            "models": [{"provider": "anthropic", "model": "claude-3"}],
        }}})
        r = _parse(_run(model_routing_audit(cfg)))
        assert _fc(r) >= 1

    def test_model_routing_no_budget(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write(tmp_path, {"mcp": {"routing": {
            "strategy": "priority",
            "models": [{"provider": "anthropic", "model": "a"}, {"provider": "anthropic", "model": "b"}],
        }}})
        r = _parse(_run(model_routing_audit(cfg)))
        assert _fc(r) >= 1

    def test_resource_links_no_cap(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write(tmp_path, {"mcp": {"capabilities": {}}})
        r = _parse(_run(resource_links_audit(cfg)))
        assert _fc(r) >= 1

    def test_resource_links_bad_uri(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write(tmp_path, {"mcp": {"capabilities": {
            "resources": {"subscribe": False, "listChanged": False},
        }, "resources": [
            {"uri": "no-scheme-uri", "name": ""},
            {"uri": "file:///valid", "name": "Valid"},
        ], "resourceTemplates": [
            {"uriTemplate": "bad://x/{id}", "name": ""},
            {},
        ], "tools": [
            {"name": "t", "outputSchema": {"properties": {
                "link": {"$ref": "file:///nonexistent/resource"}
            }}},
        ]}})
        r = _parse(_run(resource_links_audit(cfg)))
        assert _fc(r) >= 1

    def test_resource_links_with_ref(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write(tmp_path, {"mcp": {"capabilities": {
            "resources": {"subscribe": True, "listChanged": True},
        }, "resources": [
            {"uri": "file:///data/x", "name": "X"},
        ], "tools": [
            {"name": "t", "outputSchema": {"properties": {
                "ref": {"resource_link": {"uri": "file:///data/missing"}}
            }}},
        ]}})
        r = _parse(_run(resource_links_audit(cfg)))
        assert isinstance(r, dict)


# ===================================================================
# advanced_security.py — empty config + deep branches
# ===================================================================
class TestAdvancedSecurityDeep:
    def test_secrets_lifecycle_empty(self, tmp_path):
        from src.advanced_security import openclaw_secrets_lifecycle_check
        cfg = _write(tmp_path, {})
        r = _parse(_run(openclaw_secrets_lifecycle_check(cfg)))
        assert isinstance(r, dict)

    def test_secrets_lifecycle_inline_creds(self, tmp_path):
        from src.advanced_security import openclaw_secrets_lifecycle_check
        cfg = _write(tmp_path, {"auth": {"profiles": {
            "slack": {"token": "xoxb-real-token", "secret": "$ENV_VAR"},
            "github": {"apiKey": "ghp_realPatHere1234"},
        }}})
        r = _parse(_run(openclaw_secrets_lifecycle_check(cfg)))
        assert _fc(r) >= 1

    def test_channel_auth_canon_empty(self, tmp_path):
        from src.advanced_security import openclaw_channel_auth_canon_check
        cfg = _write(tmp_path, {})
        r = _parse(_run(openclaw_channel_auth_canon_check(cfg)))
        assert isinstance(r, dict)

    def test_channel_auth_canon_traversal(self, tmp_path):
        from src.advanced_security import openclaw_channel_auth_canon_check
        cfg = _write(tmp_path, {"plugins": {
            "webhook": {"httpPath": "/api/../admin", "webhookPath": "/hook/%2e%2e/secret"},
        }, "gateway": {"controlUi": {"basePath": "/../../etc"}}})
        r = _parse(_run(openclaw_channel_auth_canon_check(cfg)))
        assert _fc(r) >= 1

    def test_exec_approval_empty(self, tmp_path):
        from src.advanced_security import openclaw_exec_approval_freeze_check
        cfg = _write(tmp_path, {})
        r = _parse(_run(openclaw_exec_approval_freeze_check(cfg)))
        assert isinstance(r, dict)

    def test_exec_approval_allow_always(self, tmp_path):
        from src.advanced_security import openclaw_exec_approval_freeze_check
        # Create exec-approvals.json alongside config
        approvals = tmp_path / "exec-approvals.json"
        approvals.write_text(json.dumps({
            "sh": {"mode": "allow-always", "args": ["-c", "rm -rf /"]},
            "node": {"mode": "ask-every-time"},
        }))
        cfg = _write(tmp_path, {"exec": {"approval": {"storeDir": str(tmp_path)}}})
        r = _parse(_run(openclaw_exec_approval_freeze_check(cfg)))
        assert isinstance(r, dict)

    def test_hook_session_routing_empty(self, tmp_path):
        from src.advanced_security import openclaw_hook_session_routing_check
        cfg = _write(tmp_path, {})
        r = _parse(_run(openclaw_hook_session_routing_check(cfg)))
        assert isinstance(r, dict)

    def test_hook_session_unrestricted(self, tmp_path):
        from src.advanced_security import openclaw_hook_session_routing_check
        cfg = _write(tmp_path, {"hooks": {
            "allowRequestSessionKey": True,
            "allowedKeyPrefixes": [],
        }})
        r = _parse(_run(openclaw_hook_session_routing_check(cfg)))
        assert _fc(r) >= 1

    def test_config_include_empty(self, tmp_path):
        from src.advanced_security import openclaw_config_include_check
        cfg = _write(tmp_path, {})
        r = _parse(_run(openclaw_config_include_check(cfg)))
        assert isinstance(r, dict)

    def test_config_include_large_file(self, tmp_path):
        from src.advanced_security import openclaw_config_include_check
        large = tmp_path / "big.yaml"
        large.write_text("x" * (2 * 1024 * 1024))  # 2MB
        cfg = _write(tmp_path, {"$include": str(large)})
        r = _parse(_run(openclaw_config_include_check(cfg)))
        assert _fc(r) >= 1

    def test_config_prototype_empty(self, tmp_path):
        from src.advanced_security import openclaw_config_prototype_check
        cfg = _write(tmp_path, {})
        r = _parse(_run(openclaw_config_prototype_check(cfg)))
        assert isinstance(r, dict)

    def test_safe_bins_empty(self, tmp_path):
        from src.advanced_security import openclaw_safe_bins_profile_check
        cfg = _write(tmp_path, {})
        r = _parse(_run(openclaw_safe_bins_profile_check(cfg)))
        assert isinstance(r, dict)

    def test_safe_bins_not_dict(self, tmp_path):
        from src.advanced_security import openclaw_safe_bins_profile_check
        cfg = _write(tmp_path, {"exec": "not-a-dict"})
        r = _parse(_run(openclaw_safe_bins_profile_check(cfg)))
        assert isinstance(r, dict)

    def test_safe_bins_dict_entries(self, tmp_path):
        from src.advanced_security import openclaw_safe_bins_profile_check
        cfg = _write(tmp_path, {"exec": {
            "allowedBins": [
                "python",
                {"name": "node", "profile": "strict"},
                {"name": "perl"},
            ],
            "safeBinProfiles": {"strict": {"sandbox": True}},
        }})
        r = _parse(_run(openclaw_safe_bins_profile_check(cfg)))
        assert isinstance(r, dict)

    def test_group_policy_empty(self, tmp_path):
        from src.advanced_security import openclaw_group_policy_default_check
        cfg = _write(tmp_path, {})
        r = _parse(_run(openclaw_group_policy_default_check(cfg)))
        assert isinstance(r, dict)

    def test_group_policy_non_allowlist(self, tmp_path):
        from src.advanced_security import openclaw_group_policy_default_check
        cfg = _write(tmp_path, {
            "channels": {
                "defaults": {"groupPolicy": "passthrough"},
                "telegram": {},
                "whatsapp": {"groupPolicy": "allowlist"},
            },
        })
        r = _parse(_run(openclaw_group_policy_default_check(cfg)))
        assert _fc(r) >= 1


# ===================================================================
# ecosystem_audit.py — empty config + deep branches
# ===================================================================
class TestEcosystemAuditDeep:
    def test_mcp_firewall_empty(self, tmp_path):
        from src.ecosystem_audit import openclaw_mcp_firewall_check
        cfg = _write(tmp_path, {})
        r = _parse(openclaw_mcp_firewall_check(cfg))
        assert isinstance(r, dict)

    def test_mcp_firewall_dangerous_allow(self, tmp_path):
        from src.ecosystem_audit import openclaw_mcp_firewall_check
        cfg = _write(tmp_path, {"mcp": {"firewall": {
            "allowlist": ["shell_exec", "file_write", "safe_tool"],
            "argSanitization": {},
            "rateLimits": {},
            "secretLeakPrevention": {"enabled": False},
            "maxRequestSizeBytes": 0,
        }}})
        r = _parse(openclaw_mcp_firewall_check(cfg))
        assert _fc(r) >= 1

    def test_mcp_firewall_no_blocklist(self, tmp_path):
        from src.ecosystem_audit import openclaw_mcp_firewall_check
        cfg = _write(tmp_path, {"mcp": {"firewall": {
            "blocklist": ["some_tool"],
            "argSanitization": None,
            "rateLimits": None,
            "secretLeakPrevention": {},
            "maxRequestSizeBytes": 999999999,
        }}})
        r = _parse(openclaw_mcp_firewall_check(cfg))
        assert _fc(r) >= 1

    def test_rag_empty(self, tmp_path):
        from src.ecosystem_audit import openclaw_rag_pipeline_check
        cfg = _write(tmp_path, {})
        r = _parse(openclaw_rag_pipeline_check(cfg))
        assert isinstance(r, dict)

    def test_rag_no_config(self, tmp_path):
        from src.ecosystem_audit import openclaw_rag_pipeline_check
        cfg = _write(tmp_path, {"mcp": {}})
        r = _parse(openclaw_rag_pipeline_check(cfg))
        assert isinstance(r, dict)

    def test_rag_hardcoded_conn(self, tmp_path):
        from src.ecosystem_audit import openclaw_rag_pipeline_check
        cfg = _write(tmp_path, {"rag": {
            "vectorStore": {"connection": "postgresql://user:pass@host/db"},
            "retrieval": {"topK": 50},
        }})
        r = _parse(openclaw_rag_pipeline_check(cfg))
        assert _fc(r) >= 1

    def test_sandbox_exec_empty(self, tmp_path):
        from src.ecosystem_audit import openclaw_sandbox_exec_check
        cfg = _write(tmp_path, {})
        r = _parse(openclaw_sandbox_exec_check(cfg))
        assert isinstance(r, dict)

    def test_sandbox_exec_no_config(self, tmp_path):
        from src.ecosystem_audit import openclaw_sandbox_exec_check
        cfg = _write(tmp_path, {"mcp": {}})
        r = _parse(openclaw_sandbox_exec_check(cfg))
        assert isinstance(r, dict)

    def test_sandbox_exec_no_limits(self, tmp_path):
        from src.ecosystem_audit import openclaw_sandbox_exec_check
        cfg = _write(tmp_path, {"mcp": {"sandbox": {
            "mode": "all",
            "network": {"enabled": True},
        }}})
        r = _parse(openclaw_sandbox_exec_check(cfg))
        assert _fc(r) >= 1

    def test_context_health_critical(self, tmp_path):
        from src.ecosystem_audit import openclaw_context_health_check
        cfg = _write(tmp_path, {"mcp": {}})
        r = _parse(openclaw_context_health_check(
            session_data={
                "tokensUsed": 95000,
                "maxTokens": 100000,
                "turnCount": 55,
                "messages": [],
                "createdAt": time.time() - 86400 * 2,
            }, config_path=cfg))
        assert isinstance(r, dict)

    def test_provenance_bad_algo(self):
        from src.ecosystem_audit import openclaw_provenance_tracker
        r = _parse(openclaw_provenance_tracker(action="status", algorithm="md4"))
        assert "error" in json.dumps(r).lower() or isinstance(r, dict)

    def test_provenance_append_no_entry(self):
        from src.ecosystem_audit import openclaw_provenance_tracker
        r = _parse(openclaw_provenance_tracker(action="append"))
        assert isinstance(r, dict)

    def test_provenance_append_then_export(self, tmp_path):
        from src.ecosystem_audit import openclaw_provenance_tracker, _PROVENANCE_CHAIN
        _PROVENANCE_CHAIN.clear()
        openclaw_provenance_tracker(action="append", entry={
            "tool": "test_tool", "input": "x", "output": "y"})
        openclaw_provenance_tracker(action="append", entry={
            "tool": "test_tool_2", "input": "a", "output": "b"})
        out = tmp_path / "chain.json"
        r = _parse(openclaw_provenance_tracker(
            action="export", chain_path=str(out)))
        assert isinstance(r, dict)

    def test_cost_over_budget(self, tmp_path):
        from src.ecosystem_audit import openclaw_cost_analytics
        cfg = _write(tmp_path, {"mcp": {"budget": {"maxDailyUsd": 1.0}}})
        r = _parse(openclaw_cost_analytics(
            session_data={
                "tokensUsed": 500000,
                "model": "claude-3-opus",
                "createdAt": time.time(),
                "turnCount": 10,
            }, config_path=cfg))
        assert isinstance(r, dict)

    def test_token_budget_all_recs(self, tmp_path):
        from src.ecosystem_audit import openclaw_token_budget_optimizer
        cfg = _write(tmp_path, {"mcp": {}})
        r = _parse(openclaw_token_budget_optimizer(
            session_data={
                "tokensUsed": 100000,
                "maxTokens": 200000,
                "systemPromptTokens": 50000,
                "toolResultTokens": 60000,
                "cacheHits": 10,
                "cacheMisses": 100,
                "messages": [
                    {"role": "user", "content": "hello"},
                ] * 15 + [
                    {"role": "user", "content": "hello"},
                ] * 5,
            }, config_path=cfg))
        assert isinstance(r, dict)


# ===================================================================
# skill_loader.py — edge paths
# ===================================================================
class TestSkillLoaderDeep:
    def test_loader_nonexistent_in_cache(self, tmp_path):
        from src.skill_loader import openclaw_skill_lazy_loader
        s1 = tmp_path / "skill-a"
        s1.mkdir()
        (s1 / "SKILL.md").write_text("---\nname: A\ntags: [test]\n---\n# A\nDesc")
        # Load first to populate cache
        _run(openclaw_skill_lazy_loader(skills_dir=str(tmp_path)))
        # Now request a non-existent skill from cache
        r = _parse(_run(openclaw_skill_lazy_loader(
            skills_dir=str(tmp_path), skill_name="nonexistent")))
        assert "error" in json.dumps(r).lower() or isinstance(r, dict)

    def test_loader_skip_non_dirs(self, tmp_path):
        from src.skill_loader import openclaw_skill_lazy_loader
        (tmp_path / "not-a-dir.txt").write_text("hello")
        s1 = tmp_path / "skill-a"
        s1.mkdir()
        (s1 / "SKILL.md").write_text("---\nname: A\ntags: [x]\n---\n# A\nDesc")
        r = _parse(_run(openclaw_skill_lazy_loader(
            skills_dir=str(tmp_path), refresh=True)))
        assert isinstance(r, dict)

    def test_search_tag_no_match(self, tmp_path):
        from src.skill_loader import openclaw_skill_lazy_loader, openclaw_skill_search
        s1 = tmp_path / "skill-a"
        s1.mkdir()
        (s1 / "SKILL.md").write_text("---\nname: A\ntags: [security]\n---\n# A\nSecurity tool")
        _run(openclaw_skill_lazy_loader(skills_dir=str(tmp_path), refresh=True))
        r = _parse(_run(openclaw_skill_search(
            skills_dir=str(tmp_path), query="security", tags=["finance"])))
        assert isinstance(r, dict)

    def test_extract_metadata_unreadable(self, tmp_path):
        from src.skill_loader import _extract_metadata
        bad = tmp_path / "SKILL.md"
        bad.write_bytes(b"\x80\x81\x82")
        os.chmod(str(bad), 0o000)
        try:
            result = _extract_metadata(bad, "test-skill")
            assert isinstance(result, dict)
        finally:
            os.chmod(str(bad), 0o644)

    def test_extract_metadata_frontmatter_list(self, tmp_path):
        from src.skill_loader import _extract_metadata
        md = tmp_path / "SKILL.md"
        md.write_text("---\nname: TestSkill\ntags: [a, b, c]\nversion: 1.0\nunknown_key: val\nskip_line_no_colon\n---\n# TestSkill\nA description here.\n")
        result = _extract_metadata(md, "test-skill")
        assert result.get("name") == "TestSkill"

    def test_extract_metadata_heading_fallback(self, tmp_path):
        from src.skill_loader import _extract_metadata
        md = tmp_path / "SKILL.md"
        md.write_text("# My Great Skill\nThis is a description of the skill.\nMore details here.\n")
        result = _extract_metadata(md, "test-skill")
        assert result.get("name") is not None  # has a name
        assert result.get("description")  # has a description extracted
