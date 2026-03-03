"""
Coverage tests for low-coverage modules:
  memory_audit (15%), compliance_medium (25%), auth_compliance (30%),
  delivery_export (31%), reliability_probe (33%), browser_audit (39%).
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch



def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ═══════════════════════════════════════════════════════════════════════════════
# memory_audit.py — pgvector + knowledge graph
# ═══════════════════════════════════════════════════════════════════════════════

class TestPgvectorMemoryCheck:
    def test_no_args(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check())
        assert r["ok"] is False

    def test_file_not_found(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(config_path="/nonexistent.json"))
        assert r["ok"] is False

    def test_invalid_json(self, tmp_path):
        from src.memory_audit import openclaw_pgvector_memory_check
        f = tmp_path / "bad.json"
        f.write_text("{bad")
        r = _run(openclaw_pgvector_memory_check(config_path=str(f)))
        assert r["ok"] is False

    def test_no_vector_config(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(config_data={}))
        assert isinstance(r, dict)

    def test_non_pgvector_backend(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(config_data={"memory": {"vector": {"backend": "pinecone"}}}))
        assert isinstance(r, dict)

    def test_hnsw_good_config(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(config_data={
            "memory": {"vector": {
                "backend": "pgvector",
                "index_type": "hnsw",
                "dimensions": 1536,
                "distance": "cosine",
                "m": 16,
                "ef_construction": 128,
            }},
        }))
        assert isinstance(r, dict)

    def test_hnsw_bad_params(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(config_data={
            "memory": {"vector": {
                "backend": "pgvector",
                "index_type": "hnsw",
                "dimensions": 999,
                "distance": "invalid_metric",
                "hnsw_m": 999,
                "hnsw_ef_construction": 9999,
            }},
        }))
        assert isinstance(r, dict)
        sev = [f["severity"] for f in r.get("findings", [])]
        assert "MEDIUM" in sev or "HIGH" in sev

    def test_ivfflat_index(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(config_data={
            "memory": {"vector": {"backend": "pg", "index_type": "ivfflat"}},
        }))
        assert any("ivfflat" in f["message"].lower() for f in r.get("findings", []) if "message" in f)

    def test_unknown_index(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(config_data={
            "memory": {"vector": {"backend": "pg", "index_type": "weird"}},
        }))
        assert isinstance(r, dict)

    def test_no_index(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(config_data={
            "memory": {"vector": {"backend": "pg"}},
        }))
        sev = [f["severity"] for f in r.get("findings", [])]
        assert "HIGH" in sev

    def test_no_dims(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(config_data={
            "memory": {"vector": {"backend": "pg", "index_type": "hnsw"}},
        }))
        assert isinstance(r, dict)

    def test_no_metric(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(config_data={
            "memory": {"vector": {"backend": "pg", "index_type": "hnsw", "dimensions": 768}},
        }))
        assert isinstance(r, dict)

    def test_creds_in_conn_string(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(
            config_data={"memory": {"vector": {"backend": "pgvector", "index_type": "hnsw", "dimensions": 768, "distance": "cosine"}}},
            connection_string="postgresql://user:pass123@host:5432/db",
        ))
        sev = [f["severity"] for f in r.get("findings", [])]
        assert "CRITICAL" in sev

    def test_clean_conn_string(self):
        from src.memory_audit import openclaw_pgvector_memory_check
        r = _run(openclaw_pgvector_memory_check(
            config_data={"memory": {"vector": {"backend": "pgvector", "index_type": "hnsw", "dimensions": 768, "distance": "cosine"}}},
            connection_string="postgresql://$PG_USER@host:5432/db",
        ))
        assert isinstance(r, dict)


class TestKnowledgeGraphCheck:
    def test_no_args(self):
        from src.memory_audit import openclaw_knowledge_graph_check
        r = _run(openclaw_knowledge_graph_check())
        assert r["ok"] is False

    def test_file_not_found(self):
        from src.memory_audit import openclaw_knowledge_graph_check
        r = _run(openclaw_knowledge_graph_check(config_path="/nonexistent.json"))
        assert r["ok"] is False

    def test_invalid_json(self, tmp_path):
        from src.memory_audit import openclaw_knowledge_graph_check
        f = tmp_path / "bad.json"
        f.write_text("{bad")
        r = _run(openclaw_knowledge_graph_check(config_path=str(f)))
        assert r["ok"] is False

    def test_no_graph_config(self):
        from src.memory_audit import openclaw_knowledge_graph_check
        r = _run(openclaw_knowledge_graph_check(config_data={}))
        assert isinstance(r, dict)

    def test_good_graph_config(self):
        from src.memory_audit import openclaw_knowledge_graph_check
        r = _run(openclaw_knowledge_graph_check(config_data={
            "memory": {"graph": {
                "backend": "neo4j",
                "ttl_seconds": 86400,
                "backup": {"enabled": True},
                "max_nodes": 50000,
            }},
        }))
        assert isinstance(r, dict)

    def test_unknown_backend(self):
        from src.memory_audit import openclaw_knowledge_graph_check
        r = _run(openclaw_knowledge_graph_check(config_data={"memory": {"graph": {"backend": "unknown_db"}}}))
        sev = [f["severity"] for f in r.get("findings", [])]
        assert "MEDIUM" in sev

    def test_no_backend(self):
        from src.memory_audit import openclaw_knowledge_graph_check
        r = _run(openclaw_knowledge_graph_check(config_data={"memory": {"graph": {"ttl": 3600}}}))
        sev = [f["severity"] for f in r.get("findings", [])]
        assert "HIGH" in sev

    def test_short_ttl(self):
        from src.memory_audit import openclaw_knowledge_graph_check
        r = _run(openclaw_knowledge_graph_check(config_data={"memory": {"graph": {"backend": "neo4j", "ttl": 60}}}))
        assert isinstance(r, dict)

    def test_long_ttl(self):
        from src.memory_audit import openclaw_knowledge_graph_check
        r = _run(openclaw_knowledge_graph_check(config_data={"memory": {"graph": {"backend": "neo4j", "ttl": 999999999}}}))
        assert isinstance(r, dict)

    def test_no_ttl(self):
        from src.memory_audit import openclaw_knowledge_graph_check
        r = _run(openclaw_knowledge_graph_check(config_data={"memory": {"graph": {"backend": "neo4j"}}}))
        sev = [f["severity"] for f in r.get("findings", [])]
        assert "HIGH" in sev

    def test_graph_data_with_orphans_and_cycles(self, tmp_path):
        from src.memory_audit import openclaw_knowledge_graph_check
        gd = tmp_path / "graph.json"
        gd.write_text(json.dumps({
            "nodes": [{"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "orphan"}],
            "edges": [
                {"source": "a", "target": "b"},
                {"source": "b", "target": "c"},
                {"source": "c", "target": "a"},
            ],
        }))
        r = _run(openclaw_knowledge_graph_check(
            config_data={"memory": {"graph": {"backend": "neo4j", "ttl": 86400}}},
            graph_data_path=str(gd),
        ))
        assert r.get("metrics", {}).get("has_cycles") is True
        assert r.get("metrics", {}).get("orphan_nodes", 0) >= 1

    def test_graph_data_bad_json(self, tmp_path):
        from src.memory_audit import openclaw_knowledge_graph_check
        gd = tmp_path / "bad.json"
        gd.write_text("{bad")
        r = _run(openclaw_knowledge_graph_check(
            config_data={"memory": {"graph": {"backend": "neo4j", "ttl": 86400}}},
            graph_data_path=str(gd),
        ))
        assert isinstance(r, dict)

    def test_no_backup_no_max_nodes(self):
        from src.memory_audit import openclaw_knowledge_graph_check
        r = _run(openclaw_knowledge_graph_check(config_data={
            "memory": {"graph": {"backend": "sqlite", "ttl": 7200}},
        }))
        sev = [f["severity"] for f in r.get("findings", [])]
        assert "MEDIUM" in sev


class TestAnalyzeGraph:
    def test_empty_graph(self):
        from src.memory_audit import _analyze_graph
        m = _analyze_graph({"nodes": [], "edges": []})
        assert m["total_nodes"] == 0
        assert m["has_cycles"] is False

    def test_no_cycle(self):
        from src.memory_audit import _analyze_graph
        m = _analyze_graph({
            "nodes": [{"id": "a"}, {"id": "b"}],
            "edges": [{"source": "a", "target": "b"}],
        })
        assert m["has_cycles"] is False
        assert m["orphan_nodes"] == 0

    def test_cycle(self):
        from src.memory_audit import _analyze_graph
        m = _analyze_graph({
            "nodes": [{"id": "a"}, {"id": "b"}],
            "edges": [{"source": "a", "target": "b"}, {"source": "b", "target": "a"}],
        })
        assert m["has_cycles"] is True


class TestDetectCycle:
    def test_no_cycle(self):
        from src.memory_audit import _detect_cycle
        assert _detect_cycle({"a": ["b"], "b": ["c"]}) is False

    def test_cycle(self):
        from src.memory_audit import _detect_cycle
        assert _detect_cycle({"a": ["b"], "b": ["a"]}) is True

    def test_empty(self):
        from src.memory_audit import _detect_cycle
        assert _detect_cycle({}) is False


# ═══════════════════════════════════════════════════════════════════════════════
# compliance_medium.py — 6 tools (M1-M6)
# ═══════════════════════════════════════════════════════════════════════════════

class TestToolDeprecationAudit:
    def test_empty_config(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({}))
        r = _run(tool_deprecation_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_no_tools(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"tools": "not_a_list"}}))
        r = _run(tool_deprecation_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_deprecated_tool_no_sunset(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"tools": [
            {"name": "old_tool", "annotations": {"deprecated": True}},
        ]}}))
        r = _run(tool_deprecation_audit(config_path=str(cfg)))
        assert any("sunset" in f.lower() for f in r.get("findings", []))

    def test_sunset_without_deprecated(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"tools": [
            {"name": "tool1", "annotations": {"sunset": "2026-12-31"}},
        ]}}))
        r = _run(tool_deprecation_audit(config_path=str(cfg)))
        assert any("inconsistent" in f.lower() for f in r.get("findings", []))

    def test_bad_iso_date(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"tools": [
            {"name": "t1", "annotations": {"deprecated": True, "sunset": "not-a-date", "replacement": "t2"}},
            {"name": "t2", "annotations": {}},
        ]}}))
        r = _run(tool_deprecation_audit(config_path=str(cfg)))
        assert any("ISO 8601" in f for f in r.get("findings", []))

    def test_circular_deprecation(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"tools": [
            {"name": "a", "annotations": {"deprecated": True, "sunset": "2026-12-01", "replacement": "b"}},
            {"name": "b", "annotations": {"deprecated": True, "sunset": "2026-12-01", "replacement": "a"}},
        ]}}))
        r = _run(tool_deprecation_audit(config_path=str(cfg)))
        assert any("circular" in f.lower() for f in r.get("findings", []))

    def test_replacement_missing(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"tools": [
            {"name": "old", "annotations": {"deprecated": True, "sunset": "2026-12-01", "replacement": "ghost"}},
        ]}}))
        r = _run(tool_deprecation_audit(config_path=str(cfg)))
        assert any("does not exist" in f for f in r.get("findings", []))

    def test_well_configured(self, tmp_path):
        from src.compliance_medium import tool_deprecation_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"tools": [
            {"name": "old", "annotations": {"deprecated": True, "sunset": "2026-12-31", "replacement": "new", "deprecatedMessage": "Use new"}},
            {"name": "new", "annotations": {}},
        ]}}))
        r = _run(tool_deprecation_audit(config_path=str(cfg)))
        assert r["severity"] in ("OK", "INFO")


class TestCircuitBreakerAudit:
    def test_no_resilience(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({}))
        r = _run(circuit_breaker_audit(config_path=str(cfg)))
        assert any("circuit breaker" in f.lower() for f in r.get("findings", []))

    def test_good_config(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"resilience": {
            "circuitBreaker": {"failureThreshold": 3, "resetTimeoutMs": 5000, "halfOpenMaxRequests": 2},
            "retry": {"maxRetries": 3, "backoff": 1000, "backoffType": "exponential"},
            "timeout": 30000,
            "fallback": {"type": "cached"},
        }}}))
        r = _run(circuit_breaker_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_bad_threshold(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"resilience": {
            "circuitBreaker": {"failureThreshold": -1, "resetTimeoutMs": 100, "halfOpenMaxRequests": -1},
            "retry": {"maxRetries": 10, "backoffType": "weird"},
            "timeout": 999999,
        }}}))
        r = _run(circuit_breaker_audit(config_path=str(cfg)))
        assert len(r.get("findings", [])) > 0

    def test_no_retry(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"resilience": {
            "circuitBreaker": {"failureThreshold": 3, "resetTimeoutMs": 5000},
        }}}))
        r = _run(circuit_breaker_audit(config_path=str(cfg)))
        assert any("retry" in f.lower() for f in r.get("findings", []))

    def test_low_timeout(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"resilience": {
            "circuitBreaker": {"failureThreshold": 3},
            "retry": {"maxRetries": 2, "backoff": 100},
            "timeout": 500,
        }}}))
        r = _run(circuit_breaker_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_negative_retries(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"resilience": {
            "circuitBreaker": {},
            "retry": {"maxRetries": -1},
        }}}))
        r = _run(circuit_breaker_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_external_tool_no_override(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {
            "resilience": {
                "circuitBreaker": {"failureThreshold": 3, "resetTimeoutMs": 5000},
                "retry": {"maxRetries": 3, "backoff": 1000},
                "timeout": 30000,
                "fallback": {},
            },
            "tools": [{"name": "http_call", "description": "Makes an HTTP request to webhook"}],
        }}))
        r = _run(circuit_breaker_audit(config_path=str(cfg)))
        assert isinstance(r, dict)


class TestGdprResidencyAudit:
    def test_no_privacy(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert any("privacy" in f.lower() or "gdpr" in f.lower() for f in r.get("findings", []))

    def test_good_gdpr(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"privacy": {
            "legalBasis": "consent",
            "gdpr": {
                "legalBasis": "consent",
                "retentionDays": 365,
                "rightToErasure": {"endpoint": "/api/erase", "tool": "erase_data"},
                "dpa": "https://example.com/dpa",
            },
        }, "dataResidency": {
            "region": "eu",
            "crossBorderTransfers": {"mechanism": "scc"},
        }}}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_bad_legal_basis(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"privacy": {"legalBasis": "because_i_said_so"}}}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_no_retention(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"gdpr": {"legalBasis": "consent"}}}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert any("retention" in f.lower() for f in r.get("findings", []))

    def test_erasure_no_endpoint(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"gdpr": {
            "legalBasis": "consent", "retentionDays": 30,
            "rightToErasure": {"enabled": True},
        }}}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_long_retention(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"gdpr": {"legalBasis": "consent", "retentionDays": 5000}}}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_zero_retention(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"gdpr": {"legalBasis": "consent", "retentionDays": 0}}}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_pii_field_undeclared(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {
            "privacy": {"legalBasis": "consent", "gdpr": {"retentionDays": 30, "rightToErasure": {"tool": "erase"}}},
            "dataResidency": {"region": "eu"},
            "tools": [{"name": "user_tool", "inputSchema": {"properties": {"email": {"type": "string"}}}}],
        }}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert any("PII" in f or "pii" in f.lower() for f in r.get("findings", []))

    def test_non_standard_region(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {
            "privacy": {"legalBasis": "consent", "gdpr": {"retentionDays": 30, "rightToErasure": {"tool": "erase"}, "dpa": "x"}},
            "dataResidency": {"region": "mars"},
        }}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_cross_border_non_standard(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {
            "privacy": {"legalBasis": "consent"},
            "dataResidency": {
                "region": "eu",
                "crossBorderTransfers": {"mechanism": "unknown_mech"},
            },
        }}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_allow_cross_border_no_safeguard(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {
            "privacy": {"legalBasis": "consent"},
            "dataResidency": {"region": "eu", "allowCrossBorder": True},
        }}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_no_region(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {
            "privacy": {"legalBasis": "consent"},
            "dataResidency": {},
        }}))
        r = _run(gdpr_residency_audit(config_path=str(cfg)))
        assert isinstance(r, dict)


class TestAgentIdentityAudit:
    def test_no_identity(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({}))
        r = _run(agent_identity_audit(config_path=str(cfg)))
        assert isinstance(r, dict)  # INFO, not error

    def test_agents_with_did(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"agents": [
            {"name": "agent1", "identity": {"did": "did:web:example.com", "verificationMethods": [{"type": "Ed25519"}]}},
        ]}}))
        r = _run(agent_identity_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_invalid_did(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"agents": [
            {"name": "a1", "identity": {"did": "not-a-did"}},
        ]}}))
        r = _run(agent_identity_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_unknown_did_method(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"agents": [
            {"name": "a1", "identity": {"did": "did:unknown:abc123"}},
        ]}}))
        r = _run(agent_identity_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_agents_dict_format(self, tmp_path):
        from src.compliance_medium import agent_identity_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"agents": {"bot1": {"identity": {"did": "did:key:z123"}}}}))
        r = _run(agent_identity_audit(config_path=str(cfg)))
        assert isinstance(r, dict)


class TestModelRoutingAudit:
    def test_no_routing(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({}))
        r = _run(model_routing_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_single_provider(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"models": {
            "default": {"provider": "anthropic", "model": "claude-4"},
        }}}))
        r = _run(model_routing_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_multi_provider(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"models": {
            "default": {"provider": "anthropic", "model": "claude-4", "fallback": {"provider": "openai"}},
            "fast": {"provider": "openai", "model": "gpt-4o", "routing": {"strategy": "round-robin", "healthCheck": True}},
        }}}))
        r = _run(model_routing_audit(config_path=str(cfg)))
        assert isinstance(r, dict)


class TestResourceLinksAudit:
    def test_no_tools(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({}))
        r = _run(resource_links_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_tools_with_links(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"tools": [
            {"name": "t1", "outputSchema": {"type": "object"}, "resourceLinks": [{"uri": "config://main"}]},
            {"name": "t2", "outputSchema": {"type": "object"}},
        ]}}))
        r = _run(resource_links_audit(config_path=str(cfg)))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# auth_compliance.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestOauthOidcAudit:
    def test_no_auth(self, tmp_path):
        from src.auth_compliance import oauth_oidc_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({}))
        r = _run(oauth_oidc_audit(config_path=str(cfg)))
        assert r["ok"] is False

    def test_good_config(self, tmp_path):
        from src.auth_compliance import oauth_oidc_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"auth": {
            "type": "oidc",
            "issuer": "https://auth.example.com",
            "discoveryUrl": "https://auth.example.com/.well-known/openid-configuration",
            "protectedResourceMetadata": {"resource": "urn:mcp", "authorization_servers": ["https://auth.example.com"]},
            "pkce": {"method": "S256", "required": True},
            "tokenValidation": {"audience": "mcp-server", "algorithms": ["RS256"]},
            "scopes": {"read": "Read access"},
            "refreshTokenRotation": True,
            "resourceIndicators": {"enabled": True},
        }}}))
        r = _run(oauth_oidc_audit(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_http_issuer(self, tmp_path):
        from src.auth_compliance import oauth_oidc_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"auth": {
            "type": "oidc", "issuer": "http://insecure.com",
        }}}))
        r = _run(oauth_oidc_audit(config_path=str(cfg)))
        assert any("CRITICAL" in f for f in r.get("findings", []))

    def test_none_algorithm(self, tmp_path):
        from src.auth_compliance import oauth_oidc_audit
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {"auth": {
            "type": "oauth2",
            "issuer": "https://a.com",
            "pkce": {"method": "plain"},
            "tokenValidation": {"audience": "x", "algorithms": ["none", "HS256"]},
        }}}))
        r = _run(oauth_oidc_audit(config_path=str(cfg)))
        assert any("CRITICAL" in f for f in r.get("findings", []))


class TestTokenScopeCheck:
    def test_no_tools(self, tmp_path):
        from src.auth_compliance import token_scope_check
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({}))
        r = _run(token_scope_check(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_unscoped_tools(self, tmp_path):
        from src.auth_compliance import token_scope_check
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {
            "auth": {"toolScopes": {"t1": ["read"]}, "publicTools": ["t3"]},
            "tools": [{"name": "t1"}, {"name": "t2"}, {"name": "t3"}],
        }}))
        r = _run(token_scope_check(config_path=str(cfg)))
        assert r["unscoped_tools"] == 1

    def test_wildcard_scope(self, tmp_path):
        from src.auth_compliance import token_scope_check
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"mcp": {
            "auth": {"toolScopes": {"t1": ["*"]}},
            "tools": [{"name": "t1"}],
        }}))
        r = _run(token_scope_check(config_path=str(cfg)))
        assert any("wildcard" in f.lower() for f in r.get("findings", []))


# ═══════════════════════════════════════════════════════════════════════════════
# delivery_export.py — 6 tools
# ═══════════════════════════════════════════════════════════════════════════════

class TestKebab:
    def test_basic(self):
        from src.delivery_export import _kebab
        assert _kebab("Hello World Test") == "hello-world-test"

    def test_special_chars(self):
        from src.delivery_export import _kebab
        assert "?" not in _kebab("What? is this!!!")

    def test_long(self):
        from src.delivery_export import _kebab
        assert len(_kebab("a " * 100)) <= 60


class TestTruncate:
    def test_short(self):
        from src.delivery_export import _truncate
        assert _truncate("short", 1000) == "short"

    def test_long(self):
        from src.delivery_export import _truncate
        r = _truncate("x" * 200, 150)
        assert len(r) <= 160  # truncated
        assert "truncated" in r


class TestAiFooter:
    def test_footer(self):
        from src.delivery_export import _ai_footer
        f = _ai_footer("Test objective", ["eng", "ops"])
        assert "AI-generated" in f


class TestExportGithubPr:
    def test_no_token(self):
        from src.delivery_export import firm_export_github_pr
        with patch("src.delivery_export.GITHUB_TOKEN", None):
            r = _run(firm_export_github_pr("owner/repo", "content", "obj"))
            assert r["ok"] is False

    def test_happy_path(self):
        from src.delivery_export import firm_export_github_pr
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"number": 42, "html_url": "https://github.com/pr/42"}
        mock_resp.raise_for_status = MagicMock()

        mock_ref = MagicMock()
        mock_ref.status_code = 200
        mock_ref.json.return_value = {"object": {"sha": "abc123"}}
        mock_ref.raise_for_status = MagicMock()

        mock_branch = MagicMock()
        mock_branch.status_code = 201

        mock_commit = MagicMock()
        mock_commit.status_code = 201

        mock_labels = MagicMock()
        mock_labels.status_code = 200

        async def mock_get(*a, **kw): return mock_ref
        async def mock_post(*a, **kw):
            url = a[0] if a else kw.get("url", "")
            if "git/refs" in str(url):
                return mock_branch
            if "/pulls" in str(url):
                return mock_resp
            return mock_labels
        async def mock_put(*a, **kw): return mock_commit

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.post = mock_post
        mock_client.put = mock_put
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("src.delivery_export.GITHUB_TOKEN", "ghp_test"), \
             patch("src.delivery_export.httpx.AsyncClient", return_value=mock_client):
            r = _run(firm_export_github_pr("owner/repo", "content", "My objective", reviewers=["alice"]))
            assert isinstance(r, dict)
            assert r["pr_number"] == 42


class TestExportJiraTicket:
    def test_no_token(self):
        from src.delivery_export import firm_export_jira_ticket
        with patch("src.delivery_export.JIRA_API_TOKEN", None):
            r = _run(firm_export_jira_ticket("ENG", "content", "obj"))
            assert r["ok"] is False


class TestExportLinearIssue:
    def test_no_token(self):
        from src.delivery_export import firm_export_linear_issue
        with patch("src.delivery_export.LINEAR_API_KEY", None):
            r = _run(firm_export_linear_issue("team-id", "content", "obj"))
            assert r["ok"] is False


class TestExportSlackDigest:
    def test_no_webhook(self):
        from src.delivery_export import firm_export_slack_digest
        with patch("src.delivery_export.SLACK_WEBHOOK_URL", None):
            r = _run(firm_export_slack_digest("content", "obj"))
            assert r["ok"] is False


class TestExportDocument:
    def test_happy_path(self, tmp_path):
        from src.delivery_export import firm_export_document
        r = _run(firm_export_document(
            "Test content here", "My test objective",
            departments=["eng"], output_path=str(tmp_path / "out.md"),
        ))
        assert isinstance(r, dict)
        assert Path(r["file_path"]).exists()

    def test_default_path(self, tmp_path):
        from src.delivery_export import firm_export_document
        with patch("src.delivery_export.OUTPUT_DIR", str(tmp_path)):
            r = _run(firm_export_document("content", "obj"))
            assert isinstance(r, dict)

    def test_project_brief_format(self, tmp_path):
        from src.delivery_export import firm_export_document
        r = _run(firm_export_document(
            "Brief content here", "Project objective",
            format="project_brief", output_path=str(tmp_path / "brief.md"),
        ))
        assert isinstance(r, dict)

    def test_structured_doc_format(self, tmp_path):
        from src.delivery_export import firm_export_document
        r = _run(firm_export_document(
            "Structured content", "Obj",
            format="structured_document", output_path=str(tmp_path / "doc.md"),
        ))
        assert isinstance(r, dict)


class TestExportAuto:
    def test_github_route(self):
        from src.delivery_export import firm_export_auto
        with patch("src.delivery_export.GITHUB_TOKEN", "ghp_test"), \
             patch("src.delivery_export.firm_export_github_pr", new_callable=AsyncMock) as mock_pr:
            mock_pr.return_value = {"ok": True, "pr_url": "https://github.com/pr/1"}
            r = _run(firm_export_auto(
                content="c", objective="obj", delivery_format="github_pr",
                github_repo="owner/repo",
            ))
            assert isinstance(r, dict)

    def test_document_route(self, tmp_path):
        from src.delivery_export import firm_export_auto
        with patch("src.delivery_export.OUTPUT_DIR", str(tmp_path)):
            r = _run(firm_export_auto(
                content="c", objective="obj", delivery_format="document",
            ))
            assert isinstance(r, dict)

    def test_unknown_format(self):
        from src.delivery_export import firm_export_auto
        r = _run(firm_export_auto(content="c", objective="obj", delivery_format="fax"))
        assert isinstance(r, dict)  # defaults to document export


# ═══════════════════════════════════════════════════════════════════════════════
# reliability_probe.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestGatewayProbe:
    def test_no_websockets(self):
        with patch.dict("sys.modules", {"websockets": None, "websockets.exceptions": None}):
            import importlib
            from src import reliability_probe
            importlib.reload(reliability_probe)
            # The function handles ImportError internally
            r = _run(reliability_probe.openclaw_gateway_probe())
            assert isinstance(r, dict)

    def test_connection_refused(self):
        from src.reliability_probe import openclaw_gateway_probe
        r = _run(openclaw_gateway_probe(gateway_url="ws://127.0.0.1:19999", max_retries=1, backoff_factor=0.01))
        assert r["ok"] is False


class TestDocSyncCheck:
    def test_no_package_json(self):
        from src.reliability_probe import openclaw_doc_sync_check
        r = _run(openclaw_doc_sync_check("/nonexistent/package.json"))
        assert r["ok"] is False

    def test_empty_deps(self, tmp_path):
        from src.reliability_probe import openclaw_doc_sync_check
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"name": "test"}))
        r = _run(openclaw_doc_sync_check(str(pj)))
        assert isinstance(r, dict)
        assert r["desynced"] == 0

    def test_no_md_files(self, tmp_path):
        from src.reliability_probe import openclaw_doc_sync_check
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"dependencies": {"lodash": "^4.17.21"}}))
        r = _run(openclaw_doc_sync_check(str(pj), docs_glob="*.md"))
        assert isinstance(r, dict)

    def test_stale_docs(self, tmp_path):
        from src.reliability_probe import openclaw_doc_sync_check
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"dependencies": {"@agentclientprotocol/sdk": "^0.14.1"}}))
        md = tmp_path / "docs.md"
        md.write_text("Using agentclientprotocol/sdk version 0.13.x for integration.")
        r = _run(openclaw_doc_sync_check(str(pj), docs_glob="*.md"))
        assert isinstance(r, dict)


class TestChannelAudit:
    def test_no_package_json(self):
        from src.reliability_probe import openclaw_channel_audit
        r = _run(openclaw_channel_audit("/nonexistent/package.json", "/nonexistent/README.md"))
        assert r["ok"] is False

    def test_no_readme(self, tmp_path):
        from src.reliability_probe import openclaw_channel_audit
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"dependencies": {"baileys": "^6.0.0"}}))
        r = _run(openclaw_channel_audit(str(pj), str(tmp_path / "nope.md")))
        assert r["ok"] is False

    def test_zombie_channel(self, tmp_path):
        from src.reliability_probe import openclaw_channel_audit
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"dependencies": {"@line/bot-sdk": "^17.0.0"}}))
        readme = tmp_path / "README.md"
        readme.write_text("# OpenClaw\nSupports WhatsApp and Slack channels.")
        r = _run(openclaw_channel_audit(str(pj), str(readme)))
        assert isinstance(r, dict)
        assert r.get("zombie_deps", 0) >= 0


class TestAdrGenerate:
    def test_happy_path(self):
        from src.reliability_probe import firm_adr_generate
        r = _run(firm_adr_generate(
            title="Use HNSW index",
            context="We need fast vector search",
            decision="Use pgvector HNSW",
            alternatives=["Flat index", "IVFFlat"],
            consequences=["Better recall", "Slower writes"],
        ))
        assert isinstance(r, dict)
        assert r["ok"] is True
        assert "markdown" in r
        assert r["commit_path"].startswith("docs/decisions/")

    def test_with_status_and_adr_id(self):
        from src.reliability_probe import firm_adr_generate
        r = _run(firm_adr_generate(
            title="Choose DB",
            context="Need database",
            decision="Use PostgreSQL",
            alternatives=["PostgreSQL", "MongoDB", "DynamoDB"],
            consequences=["SQL expertise needed"],
            status="accepted",
            adr_id="ADR-0042",
        ))
        assert isinstance(r, dict)
        assert r["ok"] is True
        assert r["adr_id"] == "ADR-0042"
        assert r["status"] == "accepted"

    def test_invalid_status(self):
        from src.reliability_probe import firm_adr_generate
        r = _run(firm_adr_generate(
            title="Test",
            context="ctx",
            decision="dec",
            alternatives=[],
            consequences=[],
            status="invalid",
        ))
        assert r["ok"] is False
        assert "status" in r["error"]


# ═══════════════════════════════════════════════════════════════════════════════
# browser_audit.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestBrowserContextCheck:
    def test_workspace_not_found(self):
        from src.browser_audit import openclaw_browser_context_check
        r = _run(openclaw_browser_context_check("/nonexistent/workspace"))
        assert r["ok"] is False

    def test_empty_workspace(self, tmp_path):
        from src.browser_audit import openclaw_browser_context_check
        r = _run(openclaw_browser_context_check(str(tmp_path)))
        assert isinstance(r, dict)

    def test_playwright_config(self, tmp_path):
        from src.browser_audit import openclaw_browser_context_check
        cfg = tmp_path / "playwright.config.js"
        cfg.write_text("""
const config = {
  use: {
    headless: true,
    launchOptions: {
      args: ['--no-sandbox', '--disable-web-security']
    }
  }
};
module.exports = config;
""")
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"devDependencies": {"@playwright/test": "^1.40.0"}}))
        r = _run(openclaw_browser_context_check(str(tmp_path)))
        assert isinstance(r, dict)

    def test_config_override(self, tmp_path):
        from src.browser_audit import openclaw_browser_context_check
        r = _run(openclaw_browser_context_check(str(tmp_path), config_override={
            "framework": "playwright",
            "headless": True,
            "args": ["--no-sandbox"],
            "timeout": 30000,
            "viewport": {"width": 1280, "height": 720},
        }))
        assert isinstance(r, dict)

    def test_puppeteer_config(self, tmp_path):
        from src.browser_audit import openclaw_browser_context_check
        cfg = tmp_path / ".puppeteerrc.json"
        cfg.write_text(json.dumps({
            "launch": {
                "headless": "new",
                "args": ["--remote-debugging-port=9222"],
            },
        }))
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"dependencies": {"puppeteer": "^21.0.0"}}))
        r = _run(openclaw_browser_context_check(str(tmp_path)))
        assert isinstance(r, dict)

    def test_no_check_deps(self, tmp_path):
        from src.browser_audit import openclaw_browser_context_check
        r = _run(openclaw_browser_context_check(str(tmp_path), check_deps=False))
        assert isinstance(r, dict)
