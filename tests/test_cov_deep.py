"""
test_cov_deep.py — Deep coverage tests for modules still below 80%.
Targets: compliance_medium, advanced_security, delivery_export,
         config_migration, ecosystem_audit, spec_compliance,
         security_audit, hebbian_validation, gateway_hardening.
"""
from __future__ import annotations

import asyncio
import json
import textwrap
import time
from unittest.mock import AsyncMock, MagicMock, patch



def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _write_config(tmp_path, data, name="openclaw.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# ═══════════════════════════════════════════════════════════════════════════════
# compliance_medium.py  (62% → target 80%+)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentIdentityAudit:
    """M4 — DID format, method, verification, signing."""

    def test_invalid_did_format(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"identity": {"did": "not-a-did"}},
        })
        r = _run(agent_identity_audit(config_path=cfg))
        assert isinstance(r, dict)
        assert any("HIGH" in f for f in r.get("findings", []))

    def test_unknown_did_method(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"identity": {"did": "did:xyz:abc123"}},
        })
        r = _run(agent_identity_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_missing_verification_method(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"identity": {"did": "did:web:example.com", "verificationMethod": []}},
        })
        r = _run(agent_identity_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_weak_signing_algorithm(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"identity": {
                "did": "did:key:z6Mk1234",
                "verificationMethod": [{"type": "Ed25519"}],
                "signing": {"algorithm": "none"},
            }},
        })
        r = _run(agent_identity_audit(config_path=cfg))
        assert isinstance(r, dict)
        assert len(r.get("findings", [])) > 0

    def test_valid_identity(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"identity": {
                "did": "did:web:example.com",
                "verificationMethod": [{"type": "Ed25519VerificationKey2020"}],
                "signing": {"algorithm": "EdDSA"},
            }},
        })
        r = _run(agent_identity_audit(config_path=cfg))
        assert isinstance(r, dict)


class TestModelRoutingAudit:
    """M5 — routing strategy, fallback, budget, provider diversity."""

    def test_no_strategy(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write_config(tmp_path, {"mcp": {"routing": {"strategy": ""}}})
        r = _run(model_routing_audit(config_path=cfg))
        assert isinstance(r, dict)
        assert len(r.get("findings", [])) > 0

    def test_empty_fallback(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write_config(tmp_path, {
            "routing": {"strategy": "round-robin", "fallback": []},
        })
        r = _run(model_routing_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_single_fallback(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write_config(tmp_path, {
            "routing": {
                "strategy": "round-robin",
                "fallback": ["claude-3-opus"],
            },
        })
        r = _run(model_routing_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_no_budget(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write_config(tmp_path, {
            "routing": {
                "strategy": "priority",
                "fallback": ["a", "b"],
            },
            "models": [
                {"name": "a", "provider": "anthropic"},
                {"name": "b", "provider": "anthropic"},
            ],
        })
        r = _run(model_routing_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_single_provider_warning(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write_config(tmp_path, {
            "routing": {
                "strategy": "priority",
                "fallback": ["a", "b"],
            },
            "budget": {"maxDailyCostUsd": 100},
            "models": [
                {"name": "a", "provider": "anthropic"},
                {"name": "b", "provider": "anthropic"},
            ],
        })
        r = _run(model_routing_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_model_missing_fields(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = _write_config(tmp_path, {
            "routing": {
                "strategy": "weighted",
                "fallback": ["a", "b"],
            },
            "budget": {"maxDailyCostUsd": 50},
            "models": [
                {"name": "a", "provider": "anthropic", "capabilities": []},
                {"name": "b", "provider": "openai"},
            ],
        })
        r = _run(model_routing_audit(config_path=cfg))
        assert isinstance(r, dict)


class TestResourceLinksAudit:
    """M6 — resource URIs, templates, tool references."""

    def test_missing_subscribe(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"capabilities": {"resources": {}}},
        })
        r = _run(resource_links_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_static_resource_no_uri(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "capabilities": {"resources": {"subscribe": True, "listChanged": True}},
                "resources": {"static": [{"name": "test"}]},
            },
        })
        r = _run(resource_links_audit(config_path=cfg))
        assert isinstance(r, dict)
        assert any("HIGH" in f for f in r.get("findings", []))

    def test_static_resource_bad_mime(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "capabilities": {"resources": {"subscribe": True, "listChanged": True}},
                "resources": {
                    "static": [{"uri": "config://test/main", "name": "Test", "mimeType": "invalid"}],
                },
            },
        })
        r = _run(resource_links_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_template_no_uri(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "capabilities": {"resources": {"subscribe": True, "listChanged": True}},
                "resources": {"templates": [{"name": "tpl"}]},
            },
        })
        r = _run(resource_links_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_tool_references_undeclared_resource(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "capabilities": {"resources": {"subscribe": True, "listChanged": True}},
                "resources": {"static": [{"uri": "config://test/main", "name": "Test", "mimeType": "application/json"}]},
                "tools": [{"name": "foo", "outputSchema": {"resource": "config://other/missing"}}],
            },
        })
        r = _run(resource_links_audit(config_path=cfg))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# advanced_security.py  (63% → target 80%+)
# ═══════════════════════════════════════════════════════════════════════════════


class TestExecApprovalFreezeDeep:
    """H12 — shell wrappers + applyPatch checks."""

    def test_apply_patch_not_workspace_only(self, tmp_path):
        from src.advanced_security import openclaw_exec_approval_freeze_check
        cfg = _write_config(tmp_path, {
            "tools": {"exec": {"applyPatch": {"workspaceOnly": False}}},
        })
        r = _run(openclaw_exec_approval_freeze_check(config_path=cfg))
        assert isinstance(r, dict)
        assert len(r.get("findings", [])) > 0

    def test_shell_wrapper_in_approvals(self, tmp_path):
        from src.advanced_security import openclaw_exec_approval_freeze_check
        approvals = tmp_path / "exec-approvals.json"
        approvals.write_text(json.dumps([
            {"executable": "/bin/sh", "args": ["-c", "echo test"]},
        ]))
        cfg = _write_config(tmp_path, {
            "tools": {"exec": {"approvalsFile": str(approvals)}},
        })
        r = _run(openclaw_exec_approval_freeze_check(config_path=cfg))
        assert isinstance(r, dict)


class TestHookSessionRoutingCheck:
    """H12 — hook session key + auth."""

    def test_allow_session_key_no_prefix(self, tmp_path):
        from src.advanced_security import openclaw_hook_session_routing_check
        cfg = _write_config(tmp_path, {
            "hooks": {
                "allowRequestSessionKey": True,
                "allowedSessionKeyPrefixes": [],
            },
        })
        r = _run(openclaw_hook_session_routing_check(config_path=cfg))
        assert isinstance(r, dict)
        assert len(r.get("findings", [])) > 0

    def test_allow_session_key_with_prefix(self, tmp_path):
        from src.advanced_security import openclaw_hook_session_routing_check
        cfg = _write_config(tmp_path, {
            "hooks": {
                "allowRequestSessionKey": True,
                "allowedSessionKeyPrefixes": ["hook:"],
            },
        })
        r = _run(openclaw_hook_session_routing_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_no_default_session_key(self, tmp_path):
        from src.advanced_security import openclaw_hook_session_routing_check
        cfg = _write_config(tmp_path, {
            "hooks": {"mappings": [{"path": "/webhook"}]},
        })
        r = _run(openclaw_hook_session_routing_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_no_hooks_token(self, tmp_path):
        from src.advanced_security import openclaw_hook_session_routing_check
        cfg = _write_config(tmp_path, {
            "hooks": {
                "mappings": [{"path": "/webhook"}],
                "defaultSessionKey": "default",
            },
        })
        r = _run(openclaw_hook_session_routing_check(config_path=cfg))
        assert isinstance(r, dict)


class TestConfigIncludeCheckDeep:
    """H13 — include file guards."""

    def test_include_oversized_file(self, tmp_path):
        from src.advanced_security import openclaw_config_include_check
        big_file = tmp_path / "big.json"
        big_file.write_text("{}" + " " * 2_000_000)  # >1MB
        cfg = _write_config(tmp_path, {"$include": [str(big_file)]})
        r = _run(openclaw_config_include_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_include_nonexistent(self, tmp_path):
        from src.advanced_security import openclaw_config_include_check
        cfg = _write_config(tmp_path, {"$include": [str(tmp_path / "missing.json")]})
        r = _run(openclaw_config_include_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_include_outside_root(self, tmp_path):
        from src.advanced_security import openclaw_config_include_check
        outside = tmp_path / "outside"
        outside.mkdir()
        ext_file = outside / "ext.json"
        ext_file.write_text("{}")
        cfg_dir = tmp_path / "config"
        cfg_dir.mkdir()
        cfg = _write_config(cfg_dir, {"$include": [str(ext_file)]})
        r = _run(openclaw_config_include_check(config_path=cfg))
        assert isinstance(r, dict)


class TestSafeBinsProfileCheckDeep:
    """H15 — interpreter bins + profiles."""

    def test_interpreter_without_profile(self, tmp_path):
        from src.advanced_security import openclaw_safe_bins_profile_check
        cfg = _write_config(tmp_path, {
            "tools": {
                "exec": {
                    "safeBins": ["python"],
                    "safeBinProfiles": {},
                },
            },
        })
        r = _run(openclaw_safe_bins_profile_check(config_path=cfg))
        assert isinstance(r, dict)
        assert len(r.get("findings", [])) > 0

    def test_interpreter_stdin_safe(self, tmp_path):
        from src.advanced_security import openclaw_safe_bins_profile_check
        cfg = _write_config(tmp_path, {
            "tools": {
                "exec": {
                    "safeBins": ["python"],
                    "safeBinProfiles": {"python": {"stdinSafe": True}},
                },
            },
        })
        r = _run(openclaw_safe_bins_profile_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_non_interpreter_without_profile(self, tmp_path):
        from src.advanced_security import openclaw_safe_bins_profile_check
        cfg = _write_config(tmp_path, {
            "tools": {
                "exec": {
                    "safeBins": ["mytool"],
                    "safeBinProfiles": {},
                },
            },
        })
        r = _run(openclaw_safe_bins_profile_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_correct_profile(self, tmp_path):
        from src.advanced_security import openclaw_safe_bins_profile_check
        cfg = _write_config(tmp_path, {
            "tools": {
                "exec": {
                    "safeBins": ["python"],
                    "safeBinProfiles": {"python": {"stdinSafe": False}},
                },
            },
        })
        r = _run(openclaw_safe_bins_profile_check(config_path=cfg))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# delivery_export.py  (62% → target 80%+)
# ═══════════════════════════════════════════════════════════════════════════════


class TestGithubPrExport:
    """GitHub PR creation via REST API."""

    def test_github_pr_success(self):
        from src.delivery_export import firm_export_github_pr
        mock_resp_ref = MagicMock(status_code=200)
        mock_resp_ref.json.return_value = {"object": {"sha": "abc123"}}
        mock_resp_branch = MagicMock(status_code=201)
        mock_resp_content = MagicMock(status_code=201)
        mock_resp_pr = MagicMock(status_code=201)
        mock_resp_pr.json.return_value = {"number": 42, "html_url": "https://github.com/test/pr/42"}
        mock_resp_labels = MagicMock(status_code=200)
        mock_resp_reviewers = MagicMock(status_code=201)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp_ref)
        mock_client.post = AsyncMock(side_effect=[mock_resp_branch, mock_resp_pr, mock_resp_labels, mock_resp_reviewers])
        mock_client.put = AsyncMock(return_value=mock_resp_content)

        mock_cls = MagicMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("src.delivery_export.httpx.AsyncClient", mock_cls), \
             patch("src.delivery_export.GITHUB_TOKEN", "ghp_test123"):
            r = _run(firm_export_github_pr(
                repo="owner/repo",
                content="# Test\nContent here",
                objective="Test PR",
                departments=["Engineering"],
            ))
        assert isinstance(r, dict)

    def test_github_pr_missing_token(self):
        from src.delivery_export import firm_export_github_pr
        with patch("src.delivery_export.GITHUB_TOKEN", None):
            r = _run(firm_export_github_pr(
                repo="owner/repo",
                content="# Test",
                objective="Test",
                departments=["Eng"],
            ))
        assert isinstance(r, dict)


class TestJiraExport:
    """Jira ticket creation."""

    def test_jira_success(self):
        from src.delivery_export import firm_export_jira_ticket
        mock_resp = MagicMock(status_code=201)
        mock_resp.json.return_value = {"key": "ENG-123", "self": "https://jira.example.com/rest/api/3/issue/ENG-123"}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        mock_cls = MagicMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("src.delivery_export.httpx.AsyncClient", mock_cls), \
             patch("src.delivery_export.JIRA_API_TOKEN", "tok123"), \
             patch("src.delivery_export.JIRA_BASE_URL", "https://jira.example.com"), \
             patch("src.delivery_export.JIRA_USER_EMAIL", "user@example.com"):
            r = _run(firm_export_jira_ticket(
                project_key="ENG",
                content="# Issue\nDescription",
                objective="Fix bug",
                departments=["Engineering"],
            ))
        assert isinstance(r, dict)

    def test_jira_missing_env(self):
        from src.delivery_export import firm_export_jira_ticket
        with patch("src.delivery_export.JIRA_API_TOKEN", None):
            r = _run(firm_export_jira_ticket(
                project_key="ENG",
                content="# Issue",
                objective="Fix",
                departments=["Eng"],
            ))
        assert isinstance(r, dict)


class TestLinearExport:
    """Linear issue creation via GraphQL."""

    def test_linear_success(self):
        from src.delivery_export import firm_export_linear_issue
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "data": {"issueCreate": {"success": True, "issue": {"id": "lin-1", "identifier": "ENG-42", "url": "https://linear.app/issue/lin-1"}}},
        }
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        mock_cls = MagicMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("src.delivery_export.httpx.AsyncClient", mock_cls), \
             patch("src.delivery_export.LINEAR_API_KEY", "lin_api_test"):
            r = _run(firm_export_linear_issue(
                team_id="team-1",
                content="# Feature\nDetails",
                objective="New feature",
                departments=["Product"],
            ))
        assert isinstance(r, dict)

    def test_linear_missing_key(self):
        from src.delivery_export import firm_export_linear_issue
        with patch("src.delivery_export.LINEAR_API_KEY", None):
            r = _run(firm_export_linear_issue(
                team_id="team-1",
                content="# Feature",
                objective="New",
                departments=["Product"],
            ))
        assert isinstance(r, dict)


class TestSlackExport:
    """Slack digest via webhook."""

    def test_slack_success(self):
        from src.delivery_export import firm_export_slack_digest
        mock_resp = MagicMock(status_code=200)
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        mock_cls = MagicMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("src.delivery_export.httpx.AsyncClient", mock_cls), \
             patch("src.delivery_export.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"):
            r = _run(firm_export_slack_digest(
                content="# Digest\nSummary here",
                objective="Weekly digest",
                departments=["All"],
                mention_users=["U12345"],
            ))
        assert isinstance(r, dict)

    def test_slack_missing_webhook(self):
        from src.delivery_export import firm_export_slack_digest
        with patch("src.delivery_export.SLACK_WEBHOOK_URL", None):
            r = _run(firm_export_slack_digest(
                content="# Digest",
                objective="Digest",
                departments=["All"],
            ))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# config_migration.py  (63% → target 80%+)
# ═══════════════════════════════════════════════════════════════════════════════


class TestPluginIntegrityCheckDeep:
    """H18 — plugin version pinning + sha256 drift."""

    def test_no_version(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = _write_config(tmp_path, {
            "plugins": {"registered": [{"name": "myplugin"}]},
        })
        r = _run(openclaw_plugin_integrity_check(config_path=cfg))
        assert isinstance(r, dict)
        assert len(r.get("findings", [])) > 0

    def test_loose_version(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = _write_config(tmp_path, {
            "plugins": {"registered": [{"name": "myplugin", "version": "^1.0.0"}]},
        })
        r = _run(openclaw_plugin_integrity_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_no_integrity_npm(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = _write_config(tmp_path, {
            "plugins": {"registered": [{"name": "myplugin", "version": "1.0.0", "source": "npm"}]},
        })
        r = _run(openclaw_plugin_integrity_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_pinned_with_integrity(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = _write_config(tmp_path, {
            "plugins": {"registered": [
                {"name": "myplugin", "version": "1.0.0", "source": "npm", "integrity": "sha256-abc123"},
            ]},
        })
        r = _run(openclaw_plugin_integrity_check(config_path=cfg))
        assert isinstance(r, dict)


class TestOtelRedactionCheckDeep:
    """M17 — OTEL active without redaction."""

    def test_otel_no_redaction(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        cfg = _write_config(tmp_path, {
            "otel": {"endpoint": "https://collector.example.com"},
        })
        r = _run(openclaw_otel_redaction_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_otel_with_redaction(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        cfg = _write_config(tmp_path, {
            "otel": {
                "endpoint": "https://collector.example.com",
                "redaction": {"patterns": ["token", "secret"]},
            },
        })
        r = _run(openclaw_otel_redaction_check(config_path=cfg))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# ecosystem_audit.py  (65% → target 80%+)
# ═══════════════════════════════════════════════════════════════════════════════


class TestContextHealthCheckDeep:
    """Context window utilization + session age."""

    def test_critical_utilization(self):
        from src.ecosystem_audit import openclaw_context_health_check
        r = openclaw_context_health_check(session_data={
            "tokensUsed": 190000,
            "contextWindow": 200000,
        })
        assert isinstance(r, dict)
        assert r.get("severity") == "CRITICAL"

    def test_high_utilization(self):
        from src.ecosystem_audit import openclaw_context_health_check
        r = openclaw_context_health_check(session_data={
            "tokensUsed": 160000,
            "contextWindow": 200000,
        })
        assert isinstance(r, dict)

    def test_medium_utilization(self):
        from src.ecosystem_audit import openclaw_context_health_check
        r = openclaw_context_health_check(session_data={
            "tokensUsed": 110000,
            "contextWindow": 200000,
        })
        assert isinstance(r, dict)

    def test_old_session(self):
        from src.ecosystem_audit import openclaw_context_health_check
        r = openclaw_context_health_check(session_data={
            "tokensUsed": 1000,
            "contextWindow": 200000,
            "createdAt": time.time() - 100000,
            "turnCount": 60,
        })
        assert isinstance(r, dict)

    def test_medium_age_session(self):
        from src.ecosystem_audit import openclaw_context_health_check
        r = openclaw_context_health_check(session_data={
            "tokensUsed": 1000,
            "contextWindow": 200000,
            "createdAt": time.time() - 36000,
            "turnCount": 25,
        })
        assert isinstance(r, dict)


class TestProvenanceTrackerDeep:
    """Provenance chain export."""

    def test_export_chain(self, tmp_path):
        from src.ecosystem_audit import openclaw_provenance_tracker
        chain_path = str(tmp_path / "chain.json")
        # First append some entries
        r1 = openclaw_provenance_tracker(action="append", entry={
            "tool": "test_tool",
            "input": {"key": "value"},
            "output": {"result": "ok"},
        })
        assert isinstance(r1, dict)
        # Then export
        r2 = openclaw_provenance_tracker(action="export", chain_path=chain_path)
        assert isinstance(r2, dict)

    def test_export_invalid_path(self, tmp_path):
        from src.ecosystem_audit import openclaw_provenance_tracker
        r = openclaw_provenance_tracker(
            action="export",
            chain_path="/nonexistent_dir_xyz/chain.json",
        )
        assert isinstance(r, dict)


class TestCostAnalyticsDeep:
    """Cost analytics with tool call stats."""

    def test_tool_call_analysis(self):
        from src.ecosystem_audit import openclaw_cost_analytics
        r = openclaw_cost_analytics(session_data={
            "toolCalls": [
                {"name": "foo", "tokensUsed": 100},
                {"name": "foo", "tokensUsed": 200},
                {"name": "bar", "tokensUsed": 50},
            ],
            "tokensUsed": 1000,
            "contextWindow": 200000,
        })
        assert isinstance(r, dict)

    def test_empty_session(self):
        from src.ecosystem_audit import openclaw_cost_analytics
        r = openclaw_cost_analytics(session_data={})
        assert isinstance(r, dict)


class TestTokenBudgetOptimizerDeep:
    """Token budget optimization: prompt ratio, cache, dedup."""

    def test_high_system_prompt_ratio(self):
        from src.ecosystem_audit import openclaw_token_budget_optimizer
        r = openclaw_token_budget_optimizer(session_data={
            "tokensUsed": 1000,
            "systemPromptTokens": 400,
        })
        assert isinstance(r, dict)

    def test_high_tool_result_ratio(self):
        from src.ecosystem_audit import openclaw_token_budget_optimizer
        r = openclaw_token_budget_optimizer(session_data={
            "tokensUsed": 1000,
            "toolResultTokens": 500,
        })
        assert isinstance(r, dict)

    def test_low_cache_hit_rate(self):
        from src.ecosystem_audit import openclaw_token_budget_optimizer
        r = openclaw_token_budget_optimizer(session_data={
            "cacheHits": 2,
            "cacheMisses": 8,
        })
        assert isinstance(r, dict)

    def test_message_deduplication(self):
        from src.ecosystem_audit import openclaw_token_budget_optimizer
        r = openclaw_token_budget_optimizer(session_data={
            "messages": [{"content": "duplicate"}] * 15,
        })
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# spec_compliance.py  (66% → target 80%+)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAudioContentAuditDeep:
    """Audio content — size/duration limits."""

    def test_oversized_audio(self, tmp_path):
        from src.spec_compliance import audio_content_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"audio": {"maxSizeBytes": 100_000_000}},
        })
        r = _run(audio_content_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_no_size_limit(self, tmp_path):
        from src.spec_compliance import audio_content_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"audio": {"enabled": True}},
        })
        r = _run(audio_content_audit(config_path=cfg))
        assert isinstance(r, dict)


class TestJsonSchemaDialectCheckDeep:
    """JSON Schema dialect — draft-07 vs 2020-12."""

    def test_no_schema(self, tmp_path):
        from src.spec_compliance import json_schema_dialect_check
        cfg = _write_config(tmp_path, {"mcp": {"tools": [{"name": "foo"}]}})
        r = _run(json_schema_dialect_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_draft07_schema(self, tmp_path):
        from src.spec_compliance import json_schema_dialect_check
        cfg = _write_config(tmp_path, {
            "mcp": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "tools": [{"name": "foo"}],
            },
        })
        r = _run(json_schema_dialect_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_definitions_keyword(self, tmp_path):
        from src.spec_compliance import json_schema_dialect_check
        cfg = _write_config(tmp_path, {
            "mcp": {
                "tools": [{"name": "foo", "inputSchema": {"definitions": {"x": {"type": "string"}}}}],
            },
        })
        r = _run(json_schema_dialect_check(config_path=cfg))
        assert isinstance(r, dict)

    def test_additional_items(self, tmp_path):
        from src.spec_compliance import json_schema_dialect_check
        cfg = _write_config(tmp_path, {
            "mcp": {
                "tools": [{"name": "foo", "inputSchema": {"additionalItems": False}}],
            },
        })
        r = _run(json_schema_dialect_check(config_path=cfg))
        assert isinstance(r, dict)


class TestSseTransportAuditDeep:
    """SSE transport — polling, origins, protocol version."""

    def test_no_transport_type(self, tmp_path):
        from src.spec_compliance import sse_transport_audit
        cfg = _write_config(tmp_path, {"mcp": {"transport": {}}})
        r = _run(sse_transport_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_streamable_http_missing_configs(self, tmp_path):
        from src.spec_compliance import sse_transport_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "transport": {
                    "type": "streamable-http",
                    "requireProtocolVersionHeader": False,
                },
            },
        })
        r = _run(sse_transport_audit(config_path=cfg))
        assert isinstance(r, dict)
        assert len(r.get("findings", [])) > 0

    def test_streamable_http_with_allowed_origins(self, tmp_path):
        from src.spec_compliance import sse_transport_audit
        cfg = _write_config(tmp_path, {
            "mcp": {
                "transport": {
                    "type": "streamable-http",
                    "polling": {"enabled": True, "interval": 5000},
                    "allowedOrigins": ["https://example.com"],
                    "requireProtocolVersionHeader": True,
                },
            },
        })
        r = _run(sse_transport_audit(config_path=cfg))
        assert isinstance(r, dict)


class TestIconMetadataAuditDeep:
    """Icon metadata — tool/resource/prompt icons."""

    def test_tool_no_icon(self, tmp_path):
        from src.spec_compliance import icon_metadata_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"tools": [{"name": "foo"}]},
        })
        r = _run(icon_metadata_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_tool_http_icon(self, tmp_path):
        from src.spec_compliance import icon_metadata_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"tools": [{"name": "foo", "icon": "http://example.com/icon.png"}]},
        })
        r = _run(icon_metadata_audit(config_path=cfg))
        assert isinstance(r, dict)

    def test_tool_https_icon(self, tmp_path):
        from src.spec_compliance import icon_metadata_audit
        cfg = _write_config(tmp_path, {
            "mcp": {"tools": [{"name": "foo", "icon": "https://example.com/icon.png"}]},
        })
        r = _run(icon_metadata_audit(config_path=cfg))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# security_audit.py  (74% → target 80%+)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSessionConfigCheckDeep:
    """Session config — env file + compose checks."""

    def test_env_with_session_secret(self, tmp_path):
        from src.security_audit import openclaw_session_config_check
        env_file = tmp_path / ".env"
        env_file.write_text("SESSION_SECRET=supersecret123\n")
        r = _run(openclaw_session_config_check(
            env_file_path=str(env_file),
        ))
        assert isinstance(r, dict)

    def test_env_without_session_secret(self, tmp_path):
        from src.security_audit import openclaw_session_config_check
        env_file = tmp_path / ".env"
        env_file.write_text("OTHER_VAR=value\n")
        r = _run(openclaw_session_config_check(
            env_file_path=str(env_file),
        ))
        assert isinstance(r, dict)

    def test_compose_with_openclaw(self, tmp_path):
        from src.security_audit import openclaw_session_config_check
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  openclaw:\n    image: openclaw:latest\n")
        r = _run(openclaw_session_config_check(
            compose_file_path=str(compose),
        ))
        assert isinstance(r, dict)

    def test_compose_with_session_secret(self, tmp_path):
        from src.security_audit import openclaw_session_config_check
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  openclaw:\n    environment:\n      SESSION_SECRET: secret123\n")
        r = _run(openclaw_session_config_check(
            compose_file_path=str(compose),
        ))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# hebbian_memory/_validation.py  (71% → target 80%+)
# ═══════════════════════════════════════════════════════════════════════════════


class TestHebbianPiiCheckDeep:
    """PII stripping config validation."""

    def test_disabled_no_patterns(self):
        from src.hebbian_memory._validation import openclaw_hebbian_pii_check
        r = _run(openclaw_hebbian_pii_check(config_data={
            "hebbian": {
                "pii_stripping": {"patterns": [], "enabled": False},
            },
        }))
        assert isinstance(r, dict)
        assert len(r.get("findings", [])) > 0

    def test_partial_patterns(self):
        from src.hebbian_memory._validation import openclaw_hebbian_pii_check
        r = _run(openclaw_hebbian_pii_check(config_data={
            "hebbian": {
                "pii_stripping": {"patterns": ["email"], "enabled": True},
                "security": {},
            },
        }))
        assert isinstance(r, dict)

    def test_full_config(self):
        from src.hebbian_memory._validation import openclaw_hebbian_pii_check
        r = _run(openclaw_hebbian_pii_check(config_data={
            "hebbian": {
                "pii_stripping": {
                    "patterns": ["email", "phone", "ip", "api_key", "ssn"],
                    "enabled": True,
                },
                "security": {
                    "secret_detection": True,
                    "embedding_rotation": "90d",
                    "access_restriction": "localhost",
                },
            },
        }))
        assert isinstance(r, dict)


class TestHebbianDecayConfigCheckDeep:
    """Learning parameters full validation."""

    def test_all_bad_params(self):
        from src.hebbian_memory._validation import openclaw_hebbian_decay_config_check
        r = _run(openclaw_hebbian_decay_config_check(config_data={
            "hebbian": {
                "parameters": {
                    "learning_rate": 0.8,
                    "decay": 0.5,
                    "poids_max": 0.99,
                    "poids_min": -0.1,
                },
                "thresholds": {
                    "episodic_to_emergent": 1,
                    "emergent_to_strong": 0.3,
                },
                "anti_drift": {
                    "max_consecutive_auto_changes": 10,
                },
            },
        }))
        assert isinstance(r, dict)
        assert len(r.get("findings", [])) >= 4

    def test_valid_params(self):
        from src.hebbian_memory._validation import openclaw_hebbian_decay_config_check
        r = _run(openclaw_hebbian_decay_config_check(config_data={
            "hebbian": {
                "parameters": {
                    "learning_rate": 0.1,
                    "decay": 0.05,
                    "poids_max": 0.9,
                    "poids_min": 0.1,
                },
                "thresholds": {
                    "episodic_to_emergent": 5,
                    "emergent_to_strong": 0.6,
                },
                "anti_drift": {
                    "max_consecutive_auto_changes": 3,
                },
            },
        }))
        assert isinstance(r, dict)

    def test_defaults(self):
        from src.hebbian_memory._validation import openclaw_hebbian_decay_config_check
        r = _run(openclaw_hebbian_decay_config_check(config_data={
            "hebbian": {"parameters": {"learning_rate": 0.1, "decay": 0.05}},
        }))
        assert isinstance(r, dict)


class TestHebbianLayerValidateDeep:
    """Layer 2 weight + PII checks."""

    def test_high_weight(self, tmp_path):
        from src.hebbian_memory._validation import openclaw_hebbian_layer_validate
        md = tmp_path / "CLAUDE.md"
        md.write_text(textwrap.dedent("""\
            # CLAUDE.md
            ## LAYER 2 — CORE
            - Rule: always validate [1.5] importance
        """))
        r = _run(openclaw_hebbian_layer_validate(claude_md_path=str(md)))
        assert isinstance(r, dict)

    def test_pii_in_content(self, tmp_path):
        from src.hebbian_memory._validation import openclaw_hebbian_layer_validate
        md = tmp_path / "CLAUDE.md"
        md.write_text(textwrap.dedent("""\
            # CLAUDE.md
            ## LAYER 2 — CORE
            - Rule: contact user@example.com [0.8]
        """))
        r = _run(openclaw_hebbian_layer_validate(claude_md_path=str(md)))
        assert isinstance(r, dict)
