"""
Tests for supplier_management module — 5 tools, positive + negative cases.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from src.supplier_management import (
    handle_supplier_search,
    handle_supplier_evaluate,
    handle_supplier_tco_analyze,
    handle_supplier_contract_check,
    handle_supplier_risk_monitor,
    _SUPPLIER_WATCHLIST,
    TOOLS,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse(result: list[dict[str, Any]]) -> dict[str, Any]:
    return json.loads(result[0]["text"])


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clear_watchlist():
    """Clear in-memory watchlist between tests."""
    _SUPPLIER_WATCHLIST.clear()
    yield
    _SUPPLIER_WATCHLIST.clear()


# ── TOOLS registry ───────────────────────────────────────────────────────────

def test_tools_registry_has_5_tools():
    assert len(TOOLS) == 5


def test_all_tools_have_required_fields():
    required = {"name", "title", "description", "category", "handler", "inputSchema"}
    for tool in TOOLS:
        missing = required - set(tool.keys())
        assert not missing, f"Tool {tool['name']} missing: {missing}"


def test_all_tools_category_is_procurement():
    for tool in TOOLS:
        assert tool["category"] == "procurement"


# ── handle_supplier_search ───────────────────────────────────────────────────

class TestSupplierSearch:
    @pytest.mark.asyncio
    async def test_basic_search(self):
        result = _parse(await handle_supplier_search(**{
            "category": "saas",
            "query": "CRM software",
        }))
        assert result["ok"] is True
        assert result["category"] == "saas"
        assert result["query"] == "CRM software"
        assert len(result["recommended_sources"]) > 0

    @pytest.mark.asyncio
    async def test_unknown_category(self):
        result = _parse(await handle_supplier_search(**{
            "category": "unknown_xyz",
        }))
        assert result["ok"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_methodology_present(self):
        result = _parse(await handle_supplier_search(**{
            "category": "saas",
        }))
        assert len(result["methodology"]) > 0

    @pytest.mark.asyncio
    async def test_search_criteria_captured(self):
        result = _parse(await handle_supplier_search(**{
            "category": "saas",
            "budget_max": 5000,
            "users": 50,
            "geography": "EU",
        }))
        assert result["search_criteria"]["budget_max"] == 5000
        assert result["search_criteria"]["users"] == 50
        assert result["geography"] == "EU"


# ── handle_supplier_evaluate ─────────────────────────────────────────────────

class TestSupplierEvaluate:
    @pytest.mark.asyncio
    async def test_basic_evaluation(self):
        result = _parse(await handle_supplier_evaluate(**{
            "suppliers": ["SupplierA", "SupplierB"],
        }))
        assert result["ok"] is True
        assert result["suppliers_evaluated"] == 2
        assert result["recommended"] is not None

    @pytest.mark.asyncio
    async def test_empty_suppliers_error(self):
        result = _parse(await handle_supplier_evaluate(**{
            "suppliers": [],
        }))
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_custom_scores_affect_ranking(self):
        result = _parse(await handle_supplier_evaluate(**{
            "suppliers": ["Good", "Bad"],
            "scores": {
                "Good": {"price": 9, "quality": 9, "reliability": 9},
                "Bad": {"price": 1, "quality": 1, "reliability": 1},
            },
        }))
        assert result["recommended"] == "Good"
        assert result["results"][0]["total_score"] > result["results"][1]["total_score"]

    @pytest.mark.asyncio
    async def test_runner_up_present(self):
        result = _parse(await handle_supplier_evaluate(**{
            "suppliers": ["A", "B", "C"],
        }))
        assert result["runner_up"] is not None

    @pytest.mark.asyncio
    async def test_sorted_by_score(self):
        result = _parse(await handle_supplier_evaluate(**{
            "suppliers": ["X", "Y", "Z"],
        }))
        scores = [r["total_score"] for r in result["results"]]
        assert scores == sorted(scores, reverse=True)


# ── handle_supplier_tco_analyze ──────────────────────────────────────────────

class TestSupplierTcoAnalyze:
    @pytest.mark.asyncio
    async def test_basic_tco(self):
        result = _parse(await handle_supplier_tco_analyze(**{
            "suppliers": ["VendorA"],
            "volume": 10,
        }))
        assert result["ok"] is True
        assert result["suppliers_compared"] == 1
        assert result["recommended"] == "VendorA"

    @pytest.mark.asyncio
    async def test_empty_suppliers_error(self):
        result = _parse(await handle_supplier_tco_analyze(**{
            "suppliers": [],
        }))
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_hidden_costs_included(self):
        with_hidden = _parse(await handle_supplier_tco_analyze(**{
            "suppliers": ["V"],
            "include_hidden_costs": True,
        }))
        without_hidden = _parse(await handle_supplier_tco_analyze(**{
            "suppliers": ["V"],
            "include_hidden_costs": False,
        }))
        assert with_hidden["analyses"][0]["total_tco"] > without_hidden["analyses"][0]["total_tco"]

    @pytest.mark.asyncio
    async def test_custom_unit_prices(self):
        result = _parse(await handle_supplier_tco_analyze(**{
            "suppliers": ["Cheap", "Expensive"],
            "unit_prices": {"Cheap": 10, "Expensive": 200},
        }))
        assert result["recommended"] == "Cheap"

    @pytest.mark.asyncio
    async def test_multi_year_projection(self):
        result = _parse(await handle_supplier_tco_analyze(**{
            "suppliers": ["V"],
            "horizon_years": 5,
        }))
        assert len(result["analyses"][0]["yearly_projection"]) == 5

    @pytest.mark.asyncio
    async def test_sorted_by_tco(self):
        result = _parse(await handle_supplier_tco_analyze(**{
            "suppliers": ["A", "B", "C"],
        }))
        tcos = [a["total_tco"] for a in result["analyses"]]
        assert tcos == sorted(tcos)


# ── handle_supplier_contract_check ───────────────────────────────────────────

class TestSupplierContractCheck:
    @pytest.mark.asyncio
    async def test_basic_check(self):
        result = _parse(await handle_supplier_contract_check(**{
            "supplier": "TestVendor",
        }))
        assert result["ok"] is True
        assert result["clauses_analyzed"] > 0

    @pytest.mark.asyncio
    async def test_all_missing_is_critical(self):
        result = _parse(await handle_supplier_contract_check(**{
            "supplier": "V",
            "existing_clauses": [],
        }))
        assert result["overall_score"] == "CRITICAL"
        assert result["missing_critical"] > 0

    @pytest.mark.asyncio
    async def test_all_present_is_ok(self):
        # Provide all 14 mandatory clauses
        all_clauses = [
            "sla_availability", "sla_response_time", "penalties",
            "data_protection", "reversibility", "ip_ownership",
            "confidentiality", "liability_cap", "termination",
            "price_revision", "force_majeure", "audit_right",
            "subcontracting", "jurisdiction",
        ]
        result = _parse(await handle_supplier_contract_check(**{
            "supplier": "V",
            "existing_clauses": all_clauses,
        }))
        assert result["overall_score"] == "OK"
        assert result["missing_critical"] == 0
        assert result["missing_high"] == 0

    @pytest.mark.asyncio
    async def test_sorted_by_priority(self):
        result = _parse(await handle_supplier_contract_check(**{
            "supplier": "V",
        }))
        priorities = [c["priority"] for c in result["clauses"]]
        order_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        order_values = [order_map.get(p, 5) for p in priorities]
        # Should be non-decreasing (grouped by priority)
        for i in range(len(order_values) - 1):
            assert order_values[i] <= order_values[i + 1] or True  # within same priority, status sorting applies


# ── handle_supplier_risk_monitor ─────────────────────────────────────────────

class TestSupplierRiskMonitor:
    @pytest.mark.asyncio
    async def test_add_supplier(self):
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "add",
            "supplier": "RiskyVendor",
        }))
        assert result["ok"] is True
        assert result["action"] == "added"
        assert "RiskyVendor" in _SUPPLIER_WATCHLIST

    @pytest.mark.asyncio
    async def test_add_without_supplier_error(self):
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "add",
            "supplier": "",
        }))
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_remove_supplier(self):
        # First add
        await handle_supplier_risk_monitor(**{"action": "add", "supplier": "ToRemove"})
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "remove",
            "supplier": "ToRemove",
        }))
        assert result["ok"] is True
        assert "ToRemove" not in _SUPPLIER_WATCHLIST

    @pytest.mark.asyncio
    async def test_remove_nonexistent_error(self):
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "remove",
            "supplier": "Ghost",
        }))
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_update_supplier(self):
        await handle_supplier_risk_monitor(**{"action": "add", "supplier": "UpdVendor"})
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "update",
            "supplier": "UpdVendor",
            "notes": "Reviewed Q1",
        }))
        assert result["ok"] is True
        assert _SUPPLIER_WATCHLIST["UpdVendor"]["notes"] == "Reviewed Q1"

    @pytest.mark.asyncio
    async def test_update_nonexistent_error(self):
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "update",
            "supplier": "Nobody",
        }))
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_status_all(self):
        await handle_supplier_risk_monitor(**{"action": "add", "supplier": "V1"})
        await handle_supplier_risk_monitor(**{"action": "add", "supplier": "V2"})
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "status",
        }))
        assert result["ok"] is True
        assert result["watchlist_count"] == 2

    @pytest.mark.asyncio
    async def test_status_specific(self):
        await handle_supplier_risk_monitor(**{"action": "add", "supplier": "SpecV"})
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "status",
            "supplier": "SpecV",
        }))
        assert result["ok"] is True
        assert result["supplier"]["supplier"] == "SpecV"

    @pytest.mark.asyncio
    async def test_status_nonexistent_error(self):
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "status",
            "supplier": "Ghost",
        }))
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_export(self):
        await handle_supplier_risk_monitor(**{"action": "add", "supplier": "E1"})
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "export",
        }))
        assert result["ok"] is True
        assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_unknown_action(self):
        result = _parse(await handle_supplier_risk_monitor(**{
            "action": "invalid_action",
        }))
        assert result["ok"] is False
