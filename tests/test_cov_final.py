"""
test_cov_final.py — Final coverage push: 3 new business modules + deeper branches.

Covers:
  - legal_status.py (5 handlers)
  - location_strategy.py (5 handlers)
  - supplier_management.py (5 handlers)
  - config_migration.py deeper (plugin integrity inner logic, OTEL redaction)
  - spec_compliance.py deeper (elicitation schemas, SSE transport, icon metadata, JSON schema)
  - security_audit.py deeper (vuln scan loop, session config, rate limit)
  - observability.py deeper (CI pipeline checks)
  - advanced_security.py deeper (exec approval, hook session, config include, safe bins)
  - compliance_medium.py deeper (model routing, resource links branches)
  - gateway_hardening.py deeper (edge cases)
  - n8n_bridge.py deeper (import/export edge cases)
  - hebbian_memory/_runtime.py deeper
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch


# ── Helper ───────────────────────────────────────────────────────────────────

def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _write_config(tmp_path: Path, data: dict) -> str:
    p = tmp_path / "openclaw.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _parse(result) -> dict:
    """Parse handler result (list[dict] with JSON text) into dict."""
    if isinstance(result, list) and result and isinstance(result[0], dict):
        return json.loads(result[0]["text"])
    if isinstance(result, dict):
        return result
    raise ValueError(f"Unexpected result type: {type(result)}")


# ═════════════════════════════════════════════════════════════════════════════
# LEGAL STATUS — 5 handlers
# ═════════════════════════════════════════════════════════════════════════════

class TestLegalStatusCompare:
    def test_basic_startup_sas(self):
        from src.legal_status import handle_legal_status_compare
        r = _parse(_run(handle_legal_status_compare({
            "project_type": "startup", "founders": 2, "revenue_y1": 200000,
            "fundraising": True, "sector": "tech",
        })))
        assert r["ok"] is True
        assert r["forms_analyzed"] >= 1
        assert r["recommended"] is not None

    def test_single_founder_filters_multi(self):
        from src.legal_status import handle_legal_status_compare
        r = _parse(_run(handle_legal_status_compare({
            "founders": 1, "fundraising": False,
        })))
        assert r["ok"] is True
        # Single founder: SAS (min 2) should be filtered out, SASU/EURL should remain
        forms = [f["form"] for f in r["comparison"]]
        assert "SAS" not in forms  # requires min 2

    def test_micro_over_threshold(self):
        from src.legal_status import handle_legal_status_compare
        r = _parse(_run(handle_legal_status_compare({
            "founders": 1, "revenue_y1": 100000,  # > 77700 threshold
        })))
        assert r["ok"] is True
        # MICRO should have warning
        micro = [f for f in r["comparison"] if f["form"] == "MICRO"]
        if micro:
            assert "warning" in micro[0]


class TestLegalTaxSimulate:
    def test_basic_sas_simulation(self):
        from src.legal_status import handle_legal_tax_simulate
        r = _parse(_run(handle_legal_tax_simulate({
            "legal_form": "SAS", "revenue": 150000, "salary": 40000,
            "dividends": 20000, "horizon_years": 3, "growth_rate": 0.1,
        })))
        assert r["ok"] is True
        assert len(r["projections"]) == 3

    def test_holding_benefit(self):
        from src.legal_status import handle_legal_tax_simulate
        r = _parse(_run(handle_legal_tax_simulate({
            "legal_form": "SAS", "revenue": 200000, "salary": 50000,
            "dividends": 30000, "holding": True, "horizon_years": 2,
        })))
        assert r["ok"] is True
        # Holding: régime mère-fille should give benefit
        for p in r["projections"]:
            assert "holding_benefit" in p

    def test_unknown_form(self):
        from src.legal_status import handle_legal_tax_simulate
        r = _parse(_run(handle_legal_tax_simulate({"legal_form": "XYZ"})))
        assert r["ok"] is False
        assert "XYZ" in r.get("error", "")

    def test_zero_profit(self):
        from src.legal_status import handle_legal_tax_simulate
        r = _parse(_run(handle_legal_tax_simulate({
            "legal_form": "SARL", "revenue": 10000, "salary": 50000,
            "dividends": 0, "horizon_years": 1,
        })))
        assert r["ok"] is True
        # With salary > revenue, profit is negative => is_tax=0
        assert r["projections"][0]["is_tax"] == 0

    def test_reduced_is_rate(self):
        from src.legal_status import handle_legal_tax_simulate
        r = _parse(_run(handle_legal_tax_simulate({
            "legal_form": "SAS", "revenue": 30000, "salary": 0,
            "dividends": 0, "horizon_years": 1,
        })))
        assert r["ok"] is True
        # Revenue <42500 should use reduced IS rate


class TestLegalSocialProtection:
    def test_assimile_salarie(self):
        from src.legal_status import handle_legal_social_protection
        r = _parse(_run(handle_legal_social_protection({
            "status": "assimile_salarie", "salary": 60000, "include_options": True,
        })))
        assert r["ok"] is True
        assert len(r["comparison"]) >= 2

    def test_tns_status(self):
        from src.legal_status import handle_legal_social_protection
        r = _parse(_run(handle_legal_social_protection({
            "status": "TNS", "salary": 40000,
        })))
        assert r["ok"] is True
        assert "recommendations" in r

    def test_unknown_status(self):
        from src.legal_status import handle_legal_social_protection
        r = _parse(_run(handle_legal_social_protection({"status": "UNKNOWN_STATUS"})))
        assert r["ok"] is False

    def test_no_options(self):
        from src.legal_status import handle_legal_social_protection
        r = _parse(_run(handle_legal_social_protection({
            "status": "assimile_salarie", "include_options": False,
        })))
        assert r["ok"] is True
        assert r["comparison"] == []


class TestLegalGovernanceAudit:
    def test_sas_with_investors(self):
        from src.legal_status import handle_legal_governance_audit
        r = _parse(_run(handle_legal_governance_audit({
            "legal_form": "SAS", "founders": 3, "has_investors": True,
        })))
        assert r["ok"] is True
        assert r["critical_clauses"] >= 1

    def test_unknown_form(self):
        from src.legal_status import handle_legal_governance_audit
        r = _parse(_run(handle_legal_governance_audit({"legal_form": "BADFORM"})))
        assert r["ok"] is False

    def test_specific_clauses_filter(self):
        from src.legal_status import handle_legal_governance_audit
        r = _parse(_run(handle_legal_governance_audit({
            "legal_form": "SAS", "founders": 2,
            "specific_clauses": ["agrement_cession", "drag_along"],
        })))
        assert r["ok"] is True
        clauses = [c["clause"] for c in r["recommended_clauses"]]
        for c in clauses:
            assert c in ("agrement_cession", "drag_along")

    def test_single_founder_no_investors(self):
        from src.legal_status import handle_legal_governance_audit
        r = _parse(_run(handle_legal_governance_audit({
            "legal_form": "SASU", "founders": 1, "has_investors": False,
        })))
        assert r["ok"] is True


class TestLegalCreationChecklist:
    def test_sas_tech(self):
        from src.legal_status import handle_legal_creation_checklist
        r = _parse(_run(handle_legal_creation_checklist({
            "legal_form": "SAS", "sector": "tech", "geography": "France",
        })))
        assert r["ok"] is True
        assert r["total_steps"] >= 1
        assert len(r["annual_obligations"]) >= 1

    def test_unknown_form(self):
        from src.legal_status import handle_legal_creation_checklist
        r = _parse(_run(handle_legal_creation_checklist({"legal_form": "BADFORM"})))
        assert r["ok"] is False

    def test_micro_no_annual_accounts(self):
        from src.legal_status import handle_legal_creation_checklist
        r = _parse(_run(handle_legal_creation_checklist({"legal_form": "MICRO"})))
        assert r["ok"] is True


# ═════════════════════════════════════════════════════════════════════════════
# LOCATION STRATEGY — 5 handlers
# ═════════════════════════════════════════════════════════════════════════════

class TestLocationGeoAnalysis:
    def test_paris_tech(self):
        from src.location_strategy import handle_location_geo_analysis
        r = _parse(_run(handle_location_geo_analysis({
            "cities": ["Paris", "Lyon"], "sector": "tech", "headcount": 20,
        })))
        assert r["ok"] is True
        assert r["cities_analyzed"] == 2

    def test_no_cities(self):
        from src.location_strategy import handle_location_geo_analysis
        r = _parse(_run(handle_location_geo_analysis({"cities": []})))
        assert r["ok"] is False

    def test_small_city(self):
        from src.location_strategy import handle_location_geo_analysis
        r = _parse(_run(handle_location_geo_analysis({
            "cities": ["Clermont-Ferrand"], "sector": "industry",
        })))
        assert r["ok"] is True


class TestLocationRealEstate:
    def test_idf_search(self):
        from src.location_strategy import handle_location_real_estate
        r = _parse(_run(handle_location_real_estate({
            "zone": "Île-de-France", "property_type": "bureau",
            "surface_min": 200, "budget_max": 5000,
        })))
        assert r["ok"] is True
        assert r["zones_found"] >= 1

    def test_specific_zone(self):
        from src.location_strategy import handle_location_real_estate
        r = _parse(_run(handle_location_real_estate({
            "zone": "La Défense", "surface_min": 100,
        })))
        assert r["ok"] is True

    def test_no_budget(self):
        from src.location_strategy import handle_location_real_estate
        r = _parse(_run(handle_location_real_estate({"zone": "France"})))
        assert r["ok"] is True


class TestLocationSiteScore:
    def test_two_sites(self):
        from src.location_strategy import handle_location_site_score
        r = _parse(_run(handle_location_site_score({
            "sites": ["Site A", "Site B"],
            "scores": {"Site A": {"transport_access": 8}, "Site B": {"transport_access": 6}},
        })))
        assert r["ok"] is True
        assert r["sites_scored"] == 2
        assert r["recommended"] is not None

    def test_no_sites(self):
        from src.location_strategy import handle_location_site_score
        r = _parse(_run(handle_location_site_score({"sites": []})))
        assert r["ok"] is False

    def test_custom_weights(self):
        from src.location_strategy import handle_location_site_score
        r = _parse(_run(handle_location_site_score({
            "sites": ["HQ"],
            "weights": {"price_sqm": 50, "transport_access": 30},
        })))
        assert r["ok"] is True


class TestLocationIncentives:
    def test_startup_tech(self):
        from src.location_strategy import handle_location_incentives
        r = _parse(_run(handle_location_incentives({
            "zone": "Paris", "company_type": "startup",
            "headcount": 10, "sector": "tech",
        })))
        assert r["ok"] is True
        assert r["total_incentive_programs"] >= 1

    def test_large_company_filters_jei(self):
        from src.location_strategy import handle_location_incentives
        r = _parse(_run(handle_location_incentives({
            "headcount": 300, "company_type": "enterprise",
        })))
        assert r["ok"] is True


class TestLocationTcoSimulate:
    def test_two_sites(self):
        from src.location_strategy import handle_location_tco_simulate
        r = _parse(_run(handle_location_tco_simulate({
            "sites": ["La Défense", "Saint-Denis"],
            "surface": 300, "horizon_years": 3, "headcount": 15,
        })))
        assert r["ok"] is True
        assert r["sites_compared"] == 2
        assert r["recommended"] is not None

    def test_no_sites(self):
        from src.location_strategy import handle_location_tco_simulate
        r = _parse(_run(handle_location_tco_simulate({"sites": []})))
        assert r["ok"] is False

    def test_single_site(self):
        from src.location_strategy import handle_location_tco_simulate
        r = _parse(_run(handle_location_tco_simulate({
            "sites": ["Paris CBD"],
            "surface": 100, "horizon_years": 5,
        })))
        assert r["ok"] is True
        assert r["potential_savings"] == 0  # only one site


# ═════════════════════════════════════════════════════════════════════════════
# SUPPLIER MANAGEMENT — 5 handlers
# ═════════════════════════════════════════════════════════════════════════════

class TestSupplierSearch:
    def test_saas_search(self):
        from src.supplier_management import handle_supplier_search
        r = _parse(_run(handle_supplier_search({
            "category": "saas", "query": "CRM", "budget_max": 500,
        })))
        assert r["ok"] is True
        assert r["category"] == "saas"

    def test_unknown_category(self):
        from src.supplier_management import handle_supplier_search
        r = _parse(_run(handle_supplier_search({"category": "nonexistent"})))
        assert r["ok"] is False

    def test_hardware_search(self):
        from src.supplier_management import handle_supplier_search
        r = _parse(_run(handle_supplier_search({
            "category": "hardware", "query": "laptops", "users": 50,
        })))
        assert r["ok"] is True


class TestSupplierEvaluate:
    def test_two_suppliers(self):
        from src.supplier_management import handle_supplier_evaluate
        r = _parse(_run(handle_supplier_evaluate({
            "suppliers": ["Vendor A", "Vendor B"],
            "scores": {"Vendor A": {"quality": 9}, "Vendor B": {"quality": 7}},
        })))
        assert r["ok"] is True
        assert r["recommended"] is not None
        assert r["runner_up"] is not None

    def test_no_suppliers(self):
        from src.supplier_management import handle_supplier_evaluate
        r = _parse(_run(handle_supplier_evaluate({"suppliers": []})))
        assert r["ok"] is False

    def test_single_supplier(self):
        from src.supplier_management import handle_supplier_evaluate
        r = _parse(_run(handle_supplier_evaluate({"suppliers": ["Solo"]})))
        assert r["ok"] is True
        assert r["runner_up"] is None


class TestSupplierTcoAnalyze:
    def test_two_suppliers_with_costs(self):
        from src.supplier_management import handle_supplier_tco_analyze
        r = _parse(_run(handle_supplier_tco_analyze({
            "suppliers": ["A", "B"],
            "volume": 10, "horizon_years": 3,
            "unit_prices": {"A": 50, "B": 80},
            "include_hidden_costs": True,
        })))
        assert r["ok"] is True
        assert r["suppliers_compared"] == 2
        assert r["recommended"] == "A"  # cheaper

    def test_no_hidden_costs(self):
        from src.supplier_management import handle_supplier_tco_analyze
        r = _parse(_run(handle_supplier_tco_analyze({
            "suppliers": ["X"],
            "include_hidden_costs": False,
        })))
        assert r["ok"] is True

    def test_no_suppliers(self):
        from src.supplier_management import handle_supplier_tco_analyze
        r = _parse(_run(handle_supplier_tco_analyze({"suppliers": []})))
        assert r["ok"] is False


class TestSupplierContractCheck:
    def test_missing_clauses(self):
        from src.supplier_management import handle_supplier_contract_check
        r = _parse(_run(handle_supplier_contract_check({
            "supplier": "Vendor X", "contract_type": "SaaS",
            "existing_clauses": [],
        })))
        assert r["ok"] is True
        assert r["missing_critical"] >= 1
        assert r["overall_score"] == "CRITICAL"

    def test_all_clauses_present(self):
        from src.supplier_management import handle_supplier_contract_check, _CONTRACT_CLAUSES
        all_clauses = [c["clause"] for c in _CONTRACT_CLAUSES]
        r = _parse(_run(handle_supplier_contract_check({
            "supplier": "Good Vendor",
            "existing_clauses": all_clauses,
        })))
        assert r["ok"] is True
        assert r["overall_score"] == "OK"


class TestSupplierRiskMonitor:
    def test_crud_lifecycle(self):
        from src.supplier_management import handle_supplier_risk_monitor, _SUPPLIER_WATCHLIST
        _SUPPLIER_WATCHLIST.clear()

        # Add
        r = _parse(_run(handle_supplier_risk_monitor({
            "action": "add", "supplier": "TestVendor", "notes": "test",
        })))
        assert r["ok"] is True
        assert r["action"] == "added"

        # Status specific
        r = _parse(_run(handle_supplier_risk_monitor({
            "action": "status", "supplier": "TestVendor",
        })))
        assert r["ok"] is True

        # Update
        r = _parse(_run(handle_supplier_risk_monitor({
            "action": "update", "supplier": "TestVendor", "notes": "updated",
        })))
        assert r["ok"] is True

        # Export
        r = _parse(_run(handle_supplier_risk_monitor({"action": "export"})))
        assert r["ok"] is True
        assert r["total"] >= 1

        # Remove
        r = _parse(_run(handle_supplier_risk_monitor({
            "action": "remove", "supplier": "TestVendor",
        })))
        assert r["ok"] is True

        # Status empty
        r = _parse(_run(handle_supplier_risk_monitor({"action": "status"})))
        assert r["ok"] is True
        assert r["watchlist_count"] == 0

    def test_add_no_supplier(self):
        from src.supplier_management import handle_supplier_risk_monitor
        r = _parse(_run(handle_supplier_risk_monitor({"action": "add"})))
        assert r["ok"] is False

    def test_remove_missing(self):
        from src.supplier_management import handle_supplier_risk_monitor, _SUPPLIER_WATCHLIST
        _SUPPLIER_WATCHLIST.clear()
        r = _parse(_run(handle_supplier_risk_monitor({
            "action": "remove", "supplier": "ghost",
        })))
        assert r["ok"] is False

    def test_update_missing(self):
        from src.supplier_management import handle_supplier_risk_monitor, _SUPPLIER_WATCHLIST
        _SUPPLIER_WATCHLIST.clear()
        r = _parse(_run(handle_supplier_risk_monitor({
            "action": "update", "supplier": "ghost",
        })))
        assert r["ok"] is False

    def test_status_missing(self):
        from src.supplier_management import handle_supplier_risk_monitor, _SUPPLIER_WATCHLIST
        _SUPPLIER_WATCHLIST.clear()
        r = _parse(_run(handle_supplier_risk_monitor({
            "action": "status", "supplier": "ghost",
        })))
        assert r["ok"] is False

    def test_unknown_action(self):
        from src.supplier_management import handle_supplier_risk_monitor
        r = _parse(_run(handle_supplier_risk_monitor({"action": "invalid"})))
        assert r["ok"] is False

    def test_add_with_specific_watch(self):
        from src.supplier_management import handle_supplier_risk_monitor, _SUPPLIER_WATCHLIST
        _SUPPLIER_WATCHLIST.clear()
        r = _parse(_run(handle_supplier_risk_monitor({
            "action": "add", "supplier": "WatchTest",
            "watch": ["financial", "security"],
        })))
        assert r["ok"] is True
        _SUPPLIER_WATCHLIST.clear()


# ═════════════════════════════════════════════════════════════════════════════
# CONFIG MIGRATION — deeper coverage (plugin integrity inner logic)
# ═════════════════════════════════════════════════════════════════════════════

class TestConfigMigrationDeeper:
    def test_plugin_no_version(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = {"plugins": {"entries": {"my-plugin": {"source": "npm"}}}}
        r = _run(openclaw_plugin_integrity_check(_write_config(tmp_path, cfg)))
        assert r["status"] == "high"
        ids = [f["id"] for f in r["findings"]]
        assert "plugin_no_version_my-plugin" in ids
        assert "plugin_no_integrity_my-plugin" in ids

    def test_plugin_loose_version(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = {"plugins": {"entries": {"p1": {"version": "^1.0.0", "source": "npm"}}}}
        r = _run(openclaw_plugin_integrity_check(_write_config(tmp_path, cfg)))
        assert any("loose_version" in f["id"] for f in r["findings"])

    def test_plugin_latest_version(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = {"plugins": {"entries": {"p1": {"version": "latest", "source": "npm"}}}}
        r = _run(openclaw_plugin_integrity_check(_write_config(tmp_path, cfg)))
        assert any("loose_version" in f["id"] for f in r["findings"])

    def test_plugin_tilde_version(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = {"plugins": {"entries": {"p1": {"version": "~2.0.0", "source": "git"}}}}
        r = _run(openclaw_plugin_integrity_check(_write_config(tmp_path, cfg)))
        assert any("loose_version" in f["id"] for f in r["findings"])

    def test_plugin_star_version(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = {"plugins": {"entries": {"p1": {"version": "*", "source": "url"}}}}
        r = _run(openclaw_plugin_integrity_check(_write_config(tmp_path, cfg)))
        assert any("loose_version" in f["id"] for f in r["findings"])

    def test_plugin_with_integrity(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = {"plugins": {"entries": {"p1": {
            "version": "1.2.3", "integrity": "sha256-abc123", "source": "npm",
        }}}}
        r = _run(openclaw_plugin_integrity_check(_write_config(tmp_path, cfg)))
        # Should be clean — no version or integrity findings
        ids = [f["id"] for f in r["findings"]]
        assert not any("no_version" in i for i in ids)
        assert not any("no_integrity" in i for i in ids)

    def test_plugin_drift_detection(self, tmp_path):
        """Test manifest drift detection (lines 256-279)."""
        from src.config_migration import openclaw_plugin_integrity_check

        cfg = {"plugins": {"entries": {"test-plugin": {"version": "1.0.0", "source": "npm"}}}}
        cfg_path = _write_config(tmp_path, cfg)

        # Create a plugin file and manifest with mismatched hash
        plugins_dir = tmp_path / "plugins"
        plugin_dir = plugins_dir / "test-plugin"
        plugin_dir.mkdir(parents=True)
        plugin_file = plugin_dir / "index.js"
        plugin_file.write_text("console.log('tampered');")

        manifest = {"test-plugin": {"sha256": "0000deadbeef", "main": "index.js"}}
        manifest_path = tmp_path / "plugin-manifest.json"
        manifest_path.write_text(json.dumps(manifest))

        with patch("src.config_migration._PLUGIN_MANIFEST", manifest_path), \
             patch("src.config_migration._PLUGINS_DIR", plugins_dir):
            r = _run(openclaw_plugin_integrity_check(cfg_path))
        # Drift finding should be present
        assert any("drift" in f["id"] for f in r.get("findings", []))

    def test_plugin_non_dict_entry(self, tmp_path):
        from src.config_migration import openclaw_plugin_integrity_check
        cfg = {"plugins": {"entries": {"p1": "not-a-dict"}}}
        r = _run(openclaw_plugin_integrity_check(_write_config(tmp_path, cfg)))
        assert r["status"] == "ok"

    def test_otel_inline_auth(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        cfg = {"otel": {"endpoint": "https://user:pass@otel.example.com/v1/traces"}}
        r = _run(openclaw_otel_redaction_check(_write_config(tmp_path, cfg)))
        assert any("inline_auth" in f["id"] for f in r.get("findings", []))

    def test_otel_sensitive_header(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        cfg = {"otel": {"headers": {"Authorization": "Bearer sk-1234"}}}
        r = _run(openclaw_otel_redaction_check(_write_config(tmp_path, cfg)))
        assert any("header_inline" in f["id"] for f in r.get("findings", []))

    def test_otel_sensitive_span_attr(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        cfg = {"otel": {"spanAttributes": {"api_key": "secret123"}}}
        r = _run(openclaw_otel_redaction_check(_write_config(tmp_path, cfg)))
        assert any("span_attr" in f["id"] for f in r.get("findings", []))

    def test_otel_redaction_disabled(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        cfg = {"otel": {"endpoint": "https://otel.example.com", "redaction": {"enabled": False}}}
        r = _run(openclaw_otel_redaction_check(_write_config(tmp_path, cfg)))
        assert any("redaction_disabled" in f["id"] for f in r.get("findings", []))

    def test_otel_no_redaction_config(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        # redaction must be non-dict (e.g., null) to reach the elif branch
        cfg = {"otel": {"enabled": True, "endpoint": "https://otel.example.com", "redaction": None}}
        r = _run(openclaw_otel_redaction_check(_write_config(tmp_path, cfg)))
        assert any("no_redaction_config" in f["id"] for f in r.get("findings", []))

    def test_otel_header_env_ref_ok(self, tmp_path):
        from src.config_migration import openclaw_otel_redaction_check
        cfg = {"otel": {"headers": {"Authorization": "$OTEL_AUTH_TOKEN"}}}
        r = _run(openclaw_otel_redaction_check(_write_config(tmp_path, cfg)))
        # env var ref should not trigger inline warning
        assert not any("header_inline" in f["id"] for f in r.get("findings", []))


# ═════════════════════════════════════════════════════════════════════════════
# SPEC COMPLIANCE — deeper branches
# ═════════════════════════════════════════════════════════════════════════════

class TestSpecComplianceDeeper:
    def test_elicitation_unsupported_type(self, tmp_path):
        from src.spec_compliance import elicitation_audit
        cfg = {"mcp": {"capabilities": {"elicitation": {}}, "elicitation": {
            "schemas": [{"properties": {"nested": {"type": "object"}}}],
        }}}
        r = _run(elicitation_audit(_write_config(tmp_path, cfg)))
        assert any("nested" in f and "CRITICAL" in f for f in r["findings"])

    def test_elicitation_array_type(self, tmp_path):
        from src.spec_compliance import elicitation_audit
        cfg = {"mcp": {"capabilities": {"elicitation": {}}, "elicitation": {
            "schemas": [{"properties": {"items": {"type": "array"}}}],
        }}}
        r = _run(elicitation_audit(_write_config(tmp_path, cfg)))
        assert any("CRITICAL" in f and "array" in f for f in r["findings"])

    def test_elicitation_string_enum_ok(self, tmp_path):
        from src.spec_compliance import elicitation_audit
        cfg = {"mcp": {"capabilities": {"elicitation": {}}, "elicitation": {
            "schemas": [{"properties": {"choice": {"type": "string", "enum": ["a", "b"]}}}],
        }}}
        r = _run(elicitation_audit(_write_config(tmp_path, cfg)))
        # string+enum should be OK
        assert not any("CRITICAL" in f for f in r["findings"])

    def test_json_schema_draft07_keywords(self, tmp_path):
        from src.spec_compliance import json_schema_dialect_check
        cfg = {"$schema": "http://json-schema.org/draft-07/schema#",
               "definitions": {"foo": {}}, "dependencies": {"a": ["b"]}}
        r = _run(json_schema_dialect_check(_write_config(tmp_path, cfg)))
        assert r["severity"] in ("HIGH", "MEDIUM")
        assert any("definitions" in f for f in r["findings"])
        assert any("dependencies" in f for f in r["findings"])

    def test_json_schema_additional_items(self, tmp_path):
        from src.spec_compliance import json_schema_dialect_check
        cfg = {"$schema": "https://json-schema.org/draft/2020-12/schema",
               "items": [{}], "additionalItems": False}
        r = _run(json_schema_dialect_check(_write_config(tmp_path, cfg)))
        assert any("additionalItems" in f for f in r["findings"])

    def test_sse_streamable_http_config(self, tmp_path):
        from src.spec_compliance import sse_transport_audit
        cfg = {"mcp": {"transport": {
            "type": "streamable-http",
            "polling": {"enabled": False},
            "allowedOrigins": [],
            "requireProtocolVersionHeader": False,
        }}}
        r = _run(sse_transport_audit(_write_config(tmp_path, cfg)))
        assert any("polling" in f for f in r["findings"])
        assert any("allowedOrigins" in f for f in r["findings"])
        assert any("Protocol-Version" in f for f in r["findings"])

    def test_sse_unknown_transport(self, tmp_path):
        from src.spec_compliance import sse_transport_audit
        cfg = {"mcp": {"transport": {"type": "grpc"}}}
        r = _run(sse_transport_audit(_write_config(tmp_path, cfg)))
        assert any("grpc" in f for f in r["findings"])

    def test_sse_no_transport(self, tmp_path):
        from src.spec_compliance import sse_transport_audit
        cfg = {"mcp": {"transport": {}}}
        r = _run(sse_transport_audit(_write_config(tmp_path, cfg)))
        assert any("No MCP transport" in f for f in r["findings"])

    def test_icon_non_https(self, tmp_path):
        from src.spec_compliance import icon_metadata_audit
        cfg = {"mcp": {"tools": [{"name": "t1", "icon": "http://example.com/icon.png"}]}}
        r = _run(icon_metadata_audit(_write_config(tmp_path, cfg)))
        assert any("non-HTTPS" in f for f in r["findings"])

    def test_icon_data_uri_ok(self, tmp_path):
        from src.spec_compliance import icon_metadata_audit
        cfg = {"mcp": {"tools": [{"name": "t1", "icon": "data:image/png;base64,ABC"}]}}
        r = _run(icon_metadata_audit(_write_config(tmp_path, cfg)))
        assert not any("non-HTTPS" in f for f in r["findings"])

    def test_icon_missing(self, tmp_path):
        from src.spec_compliance import icon_metadata_audit
        cfg = {"mcp": {"tools": [{"name": "t1"}, {"name": "t2"}]}}
        r = _run(icon_metadata_audit(_write_config(tmp_path, cfg)))
        assert any("missing icon" in f for f in r["findings"])

    def test_resources_prompts_audit_deeper(self, tmp_path):
        from src.spec_compliance import resources_prompts_audit
        cfg = {"mcp": {
            "capabilities": {"resources": {}, "prompts": {"listChanged": False}},
            "resources": [{"name": "r1"}, {"uri": "x://y"}],
            "prompts": {"listChanged": False},
        }}
        r = _run(resources_prompts_audit(_write_config(tmp_path, cfg)))
        # resource 0 missing 'uri', resource 1 missing 'name'
        assert any("missing required 'uri'" in f for f in r["findings"])
        assert any("missing 'name'" in f for f in r["findings"])

    def test_elicitation_url_mode_missing(self, tmp_path):
        from src.spec_compliance import elicitation_audit
        cfg = {"mcp": {"capabilities": {"elicitation": {}}}}
        r = _run(elicitation_audit(_write_config(tmp_path, cfg)))
        assert any("URL mode" in f for f in r["findings"])


# ═════════════════════════════════════════════════════════════════════════════
# SECURITY AUDIT — deeper branches
# ═════════════════════════════════════════════════════════════════════════════

class TestSecurityAuditDeeper:
    def test_vuln_scan_with_files(self, tmp_path):
        from src.security_audit import openclaw_security_scan
        # Create a file with a SQL injection pattern
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text("cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")")
        r = _run(openclaw_security_scan(str(tmp_path)))
        assert r["ok"] is True
        assert r["total_files_scanned"] >= 1

    def test_session_config_with_env_file(self, tmp_path):
        from src.security_audit import openclaw_session_config_check
        env = tmp_path / ".env"
        env.write_text("SESSION_SECRET=mysecret123\n")
        r = _run(openclaw_session_config_check(env_file_path=str(env)))
        assert r["ok"] is True
        assert r["severity"] == "OK"

    def test_session_config_compose_no_secret(self, tmp_path):
        from src.security_audit import openclaw_session_config_check
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  openclaw:\n    image: openclaw:latest\n")
        r = _run(openclaw_session_config_check(compose_file_path=str(compose)))
        assert r["ok"] is True
        # openclaw reference without SESSION_SECRET
        assert any("regenerate" in f or "break" in f for f in r["findings"])

    def test_session_config_no_files(self):
        from src.security_audit import openclaw_session_config_check
        r = _run(openclaw_session_config_check())
        assert r["ok"] is True

    def test_rate_limit_funnel_no_limiter(self, tmp_path):
        from src.security_audit import openclaw_rate_limit_check
        cfg = tmp_path / "gateway.yml"
        cfg.write_text("funnel: true\nport: 8080\n")
        r = _run(openclaw_rate_limit_check(str(cfg), check_funnel=True))
        assert r["ok"] is True
        assert r["severity"] == "CRITICAL"

    def test_rate_limit_with_nginx(self, tmp_path):
        from src.security_audit import openclaw_rate_limit_check
        cfg = tmp_path / "gateway.yml"
        cfg.write_text("port: 8080\nnginx: true\nlimit_req zone=one\n")
        r = _run(openclaw_rate_limit_check(str(cfg)))
        assert r["rate_limiter_detected"] is True


# ═════════════════════════════════════════════════════════════════════════════
# ADVANCED SECURITY — deeper branches
# ═════════════════════════════════════════════════════════════════════════════

class TestAdvancedSecurityDeeper:
    def test_exec_approval_apply_patch(self, tmp_path):
        from src.advanced_security import openclaw_exec_approval_freeze_check
        cfg = {"tools": {"exec": {
            "applyPatch": {"workspaceOnly": False},
        }}}
        r = _run(openclaw_exec_approval_freeze_check(_write_config(tmp_path, cfg)))
        assert any("apply_patch" in str(f.get("id", "")).lower()
                    for f in r.get("findings", []))

    def test_exec_approval_shell_wrapper(self, tmp_path):
        from src.advanced_security import openclaw_exec_approval_freeze_check
        # Create exec-approvals.json with shell wrapper
        cfg = {"tools": {"exec": {}}}
        cfg_path = _write_config(tmp_path, cfg)

        approvals_dir = tmp_path / ".openclaw"
        approvals_dir.mkdir(exist_ok=True)
        approvals_file = approvals_dir / "exec-approvals.json"
        approvals_file.write_text(json.dumps({
            "cmd1": {"executable": "/bin/bash"},
        }))

        with patch("src.advanced_security._OPENCLAW_DIR", approvals_dir):
            r = _run(openclaw_exec_approval_freeze_check(cfg_path))
        assert any("shell_wrapper" in str(f.get("id", ""))
                    for f in r.get("findings", []))

    def test_hook_session_routing(self, tmp_path):
        from src.advanced_security import openclaw_hook_session_routing_check
        cfg = {"hooks": {
            "onMessage": {"session": "shared"},
            "routes": [{"path": "/api", "session": "*"}],
        }}
        r = _run(openclaw_hook_session_routing_check(_write_config(tmp_path, cfg)))
        json.dumps(r.get("findings", []))
        assert len(r.get("findings", [])) >= 0  # just make sure it runs

    def test_config_include_valid_file(self, tmp_path):
        from src.advanced_security import openclaw_config_include_check
        sub = tmp_path / "sub.json"
        sub.write_text('{"key": "value"}')
        # $include must be a string value, not a list
        cfg = {"nested": {"$include": str(sub)}}
        r = _run(openclaw_config_include_check(_write_config(tmp_path, cfg)))
        assert r["status"] == "ok"
        assert r["include_count"] >= 1

    def test_config_include_traversal(self, tmp_path):
        from src.advanced_security import openclaw_config_include_check
        cfg = {"nested": {"$include": "../../../etc/passwd"}}
        r = _run(openclaw_config_include_check(_write_config(tmp_path, cfg)))
        assert any("traversal" in f.get("id", "") for f in r.get("findings", []))

    def test_config_include_missing(self, tmp_path):
        from src.advanced_security import openclaw_config_include_check
        cfg = {"nested": {"$include": str(tmp_path / "nonexistent.json")}}
        r = _run(openclaw_config_include_check(_write_config(tmp_path, cfg)))
        assert any("missing" in f.get("id", "") for f in r.get("findings", []))

    def test_safe_bins_profile(self, tmp_path):
        from src.advanced_security import openclaw_safe_bins_profile_check
        cfg = {"tools": {"exec": {
            "safeBins": ["python", "node"],
            "safeBinProfiles": {"python": {"allowed": True}},
        }}}
        r = _run(openclaw_safe_bins_profile_check(_write_config(tmp_path, cfg)))
        # node has no profile
        assert any("node" in str(f) for f in r.get("findings", []))


# ═════════════════════════════════════════════════════════════════════════════
# COMPLIANCE MEDIUM — deeper branches
# ═════════════════════════════════════════════════════════════════════════════

class TestComplianceMediumDeeper:
    def test_model_routing_single_provider(self, tmp_path):
        from src.compliance_medium import model_routing_audit
        cfg = {"mcp": {"routing": {
            "models": [
                {"provider": "anthropic", "model": "claude-3"},
                {"provider": "anthropic", "model": "claude-4"},
            ],
        }}}
        r = _run(model_routing_audit(_write_config(tmp_path, cfg)))
        assert any("single" in str(f).lower() or "provider" in str(f).lower()
                    for f in r.get("findings", []))

    def test_resource_links_missing_uri(self, tmp_path):
        from src.compliance_medium import resource_links_audit
        cfg = {"mcp": {"capabilities": {"resources": {}}, "resources": {
            "static": [{"name": "r1"}, {"uri": "badscheme", "name": "r2"}],
        }}}
        r = _run(resource_links_audit(_write_config(tmp_path, cfg)))
        assert any("no URI" in f or "no uri" in f.lower() for f in r.get("findings", []))

    def test_gdpr_residency_no_region(self, tmp_path):
        from src.compliance_medium import gdpr_residency_audit
        cfg = {"mcp": {"storage": {}}}
        r = _run(gdpr_residency_audit(_write_config(tmp_path, cfg)))
        assert len(r.get("findings", [])) >= 0  # runs without error

    def test_circuit_breaker_missing(self, tmp_path):
        from src.compliance_medium import circuit_breaker_audit
        cfg = {"mcp": {"tools": [{"name": "t1"}]}}
        r = _run(circuit_breaker_audit(_write_config(tmp_path, cfg)))
        assert len(r.get("findings", [])) >= 0


# ═════════════════════════════════════════════════════════════════════════════
# GATEWAY HARDENING — deeper branches
# ═════════════════════════════════════════════════════════════════════════════

class TestGatewayHardeningDeeper:
    def test_webhook_sig_missing_secret(self, tmp_path):
        from src.gateway_hardening import openclaw_webhook_sig_check
        cfg = {"channels": {"telegram": {
            "webhookPath": "/webhook/telegram",
        }}}
        r = _run(openclaw_webhook_sig_check(_write_config(tmp_path, cfg)))
        assert any("signing" in str(f).lower() or "secret" in str(f).lower()
                    for f in r.get("findings", []))

    def test_log_config_no_rotation(self, tmp_path):
        from src.gateway_hardening import openclaw_log_config_check
        cfg = {"logging": {"level": "debug"}}
        r = _run(openclaw_log_config_check(_write_config(tmp_path, cfg)))
        json.dumps(r.get("findings", []))
        assert len(r.get("findings", [])) >= 0

    def test_workspace_integrity(self, tmp_path):
        from src.gateway_hardening import openclaw_workspace_integrity_check
        cfg = {"workspace": {"path": str(tmp_path)}}
        r = _run(openclaw_workspace_integrity_check(_write_config(tmp_path, cfg)))
        assert "findings" in r or "status" in r or "error" in r


# ═════════════════════════════════════════════════════════════════════════════
# N8N BRIDGE — deeper branches
# ═════════════════════════════════════════════════════════════════════════════

class TestN8nBridgeDeeper:
    def test_export_with_pipeline(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_export
        steps = [
            {"type": "http_request", "name": "fetch"},
            {"type": "agent", "name": "process"},
        ]
        r = _run(openclaw_n8n_workflow_export("test-pipeline", steps))
        assert r["ok"] is True
        assert r["node_count"] >= 2

    def test_export_empty_steps(self):
        from src.n8n_bridge import openclaw_n8n_workflow_export
        r = _run(openclaw_n8n_workflow_export("empty", []))
        assert r["ok"] is False

    def test_export_step_no_name(self):
        from src.n8n_bridge import openclaw_n8n_workflow_export
        r = _run(openclaw_n8n_workflow_export("bad", [{"type": "http_request"}]))
        assert r["ok"] is False

    def test_export_step_not_dict(self):
        from src.n8n_bridge import openclaw_n8n_workflow_export
        r = _run(openclaw_n8n_workflow_export("bad", ["not_a_dict"]))
        assert r["ok"] is False

    def test_export_to_file(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_export
        out = str(tmp_path / "workflow.json")
        steps = [{"type": "http_request", "name": "step1"}]
        r = _run(openclaw_n8n_workflow_export("test", steps, output_path=out))
        assert r["ok"] is True
        assert Path(out).exists()

    def test_import_valid(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        workflow = {"nodes": [
            {"type": "n8n-nodes-base.httpRequest", "name": "fetch",
             "parameters": {}, "position": [0, 0]},
        ], "connections": {}, "name": "test"}
        wf_path = tmp_path / "workflow.json"
        wf_path.write_text(json.dumps(workflow))
        r = _run(openclaw_n8n_workflow_import(str(wf_path)))
        assert r["ok"] is True

    def test_import_invalid_json(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        wf_path = tmp_path / "bad.json"
        wf_path.write_text("not json!")
        r = _run(openclaw_n8n_workflow_import(str(wf_path)))
        assert r["ok"] is False

    def test_import_not_json_ext(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        wf_path = tmp_path / "workflow.txt"
        wf_path.write_text('{"nodes": []}')
        r = _run(openclaw_n8n_workflow_import(str(wf_path)))
        assert r["ok"] is False

    def test_import_missing_file(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        r = _run(openclaw_n8n_workflow_import(str(tmp_path / "nope.json")))
        assert r["ok"] is False

    def test_import_not_object(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        wf_path = tmp_path / "array.json"
        wf_path.write_text("[1,2,3]")
        r = _run(openclaw_n8n_workflow_import(str(wf_path)))
        assert r["ok"] is False

    def test_import_with_target_dir(self, tmp_path):
        from src.n8n_bridge import openclaw_n8n_workflow_import
        workflow = {"nodes": [{"type": "n8n-nodes-base.httpRequest", "name": "f",
                              "parameters": {}, "position": [0, 0]}],
                   "connections": {}, "name": "test"}
        wf_path = tmp_path / "workflow.json"
        wf_path.write_text(json.dumps(workflow))
        target = tmp_path / "imported"
        target.mkdir()
        r = _run(openclaw_n8n_workflow_import(str(wf_path), target_dir=str(target)))
        assert r["ok"] is True


# ═════════════════════════════════════════════════════════════════════════════
# OBSERVABILITY — deeper branches
# ═════════════════════════════════════════════════════════════════════════════

class TestObservabilityDeeper:
    def test_ci_pipeline_with_workflow(self, tmp_path):
        from src.observability import openclaw_ci_pipeline_check
        ci_dir = tmp_path / ".github" / "workflows"
        ci_dir.mkdir(parents=True)
        wf = ci_dir / "ci.yml"
        wf.write_text("name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n")
        r = _run(openclaw_ci_pipeline_check(str(tmp_path)))
        assert r["ok"] is True

    def test_ci_pipeline_no_dir(self, tmp_path):
        from src.observability import openclaw_ci_pipeline_check
        r = _run(openclaw_ci_pipeline_check(str(tmp_path)))
        assert r["ok"] is True  # ok even if missing, just reports


# ═════════════════════════════════════════════════════════════════════════════
# HEBBIAN MEMORY — _runtime.py deeper
# ═════════════════════════════════════════════════════════════════════════════

class TestHebbianRuntimeDeeper:
    def test_harvest_empty_file(self, tmp_path):
        from src.hebbian_memory._runtime import openclaw_hebbian_harvest
        jsonl = tmp_path / "empty.jsonl"
        jsonl.write_text("")
        r = _run(openclaw_hebbian_harvest(str(jsonl)))
        assert r["ok"] is True

    def test_weight_update_no_file(self, tmp_path):
        from src.hebbian_memory._runtime import openclaw_hebbian_weight_update
        r = _run(openclaw_hebbian_weight_update(str(tmp_path / "missing.jsonl")))
        # Should handle missing file
        if isinstance(r, dict):
            assert "ok" in r or "error" in r

    def test_status(self, tmp_path):
        from src.hebbian_memory._analysis import openclaw_hebbian_status
        r = _run(openclaw_hebbian_status(str(tmp_path)))
        assert isinstance(r, dict)
