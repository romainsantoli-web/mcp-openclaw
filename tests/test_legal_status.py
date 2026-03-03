"""
Tests for legal_status module — 5 tools, positive + negative cases.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from src.legal_status import (
    handle_legal_status_compare,
    handle_legal_tax_simulate,
    handle_legal_social_protection,
    handle_legal_governance_audit,
    handle_legal_creation_checklist,
    TOOLS,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse(result: list[dict[str, Any]]) -> dict[str, Any]:
    return json.loads(result[0]["text"])


# ── TOOLS registry ───────────────────────────────────────────────────────────

def test_tools_registry_has_5_tools():
    assert len(TOOLS) == 5


def test_all_tools_have_required_fields():
    required = {"name", "title", "description", "category", "handler", "inputSchema"}
    for tool in TOOLS:
        missing = required - set(tool.keys())
        assert not missing, f"Tool {tool['name']} missing: {missing}"


def test_all_tools_category_is_legal_status():
    for tool in TOOLS:
        assert tool["category"] == "legal_status"


# ── handle_legal_status_compare ──────────────────────────────────────────────

class TestLegalStatusCompare:
    @pytest.mark.asyncio
    async def test_basic_compare_single_founder(self):
        result = _parse(await handle_legal_status_compare({
            "founders": 1,
        }))
        assert result["ok"] is True
        assert result["forms_analyzed"] > 0
        assert result["recommended"] is not None

    @pytest.mark.asyncio
    async def test_multi_founder_filters(self):
        result = _parse(await handle_legal_status_compare({
            "founders": 3,
        }))
        assert result["ok"] is True
        # EURL and SASU require exactly 1 associate
        for form in result["comparison"]:
            assert form["form"] not in ("EURL", "SASU")

    @pytest.mark.asyncio
    async def test_fundraising_flag_boosts_sas(self):
        result = _parse(await handle_legal_status_compare({
            "founders": 2,
            "fundraising": True,
        }))
        assert result["ok"] is True
        # SAS generally has HIGH fundraising_flexibility
        sas_entry = next((f for f in result["comparison"] if f["form"] == "SAS"), None)
        if sas_entry:
            assert sas_entry["fundraising_flexibility"] == "HIGH"

    @pytest.mark.asyncio
    async def test_micro_warning_on_high_revenue(self):
        result = _parse(await handle_legal_status_compare({
            "founders": 1,
            "revenue_y1": 100000,
        }))
        assert result["ok"] is True
        micro = next((f for f in result["comparison"] if f["form"] == "MICRO"), None)
        if micro:
            assert "warning" in micro

    @pytest.mark.asyncio
    async def test_returns_timestamp_and_disclaimer(self):
        result = _parse(await handle_legal_status_compare({}))
        assert "timestamp" in result
        assert "disclaimer" in result


# ── handle_legal_tax_simulate ────────────────────────────────────────────────

class TestLegalTaxSimulate:
    @pytest.mark.asyncio
    async def test_basic_simulation(self):
        result = _parse(await handle_legal_tax_simulate({
            "legal_form": "SAS",
            "revenue": 150000,
            "salary": 40000,
        }))
        assert result["ok"] is True
        assert result["legal_form"] == "SAS"
        assert len(result["projections"]) == 3  # default horizon

    @pytest.mark.asyncio
    async def test_custom_horizon(self):
        result = _parse(await handle_legal_tax_simulate({
            "legal_form": "SARL",
            "revenue": 100000,
            "horizon_years": 5,
        }))
        assert result["ok"] is True
        assert len(result["projections"]) == 5

    @pytest.mark.asyncio
    async def test_holding_benefit(self):
        result = _parse(await handle_legal_tax_simulate({
            "legal_form": "SAS",
            "revenue": 200000,
            "salary": 50000,
            "dividends": 30000,
            "holding": True,
        }))
        assert result["ok"] is True
        # With holding, dividends should have reduced tax
        year1 = result["projections"][0]
        assert year1["holding_benefit"] > 0

    @pytest.mark.asyncio
    async def test_unknown_legal_form(self):
        result = _parse(await handle_legal_tax_simulate({
            "legal_form": "XYZ",
        }))
        assert result["ok"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_zero_revenue(self):
        result = _parse(await handle_legal_tax_simulate({
            "legal_form": "SAS",
            "revenue": 0,
        }))
        assert result["ok"] is True


# ── handle_legal_social_protection ───────────────────────────────────────────

class TestLegalSocialProtection:
    @pytest.mark.asyncio
    async def test_assimile_salarie(self):
        result = _parse(await handle_legal_social_protection({
            "status": "assimile_salarie",
            "salary": 60000,
        }))
        assert result["ok"] is True
        assert result["annual_charges"] > 0
        assert result["coverage"]["unemployment"] is False

    @pytest.mark.asyncio
    async def test_tns(self):
        result = _parse(await handle_legal_social_protection({
            "status": "TNS",
            "salary": 60000,
        }))
        assert result["ok"] is True
        assert result["coverage"]["unemployment"] is False

    @pytest.mark.asyncio
    async def test_unknown_status(self):
        result = _parse(await handle_legal_social_protection({
            "status": "invalid_status",
        }))
        assert result["ok"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_comparison_included(self):
        result = _parse(await handle_legal_social_protection({
            "status": "assimile_salarie",
            "include_options": True,
        }))
        assert result["ok"] is True
        assert len(result["comparison"]) > 0

    @pytest.mark.asyncio
    async def test_comparison_excluded(self):
        result = _parse(await handle_legal_social_protection({
            "status": "assimile_salarie",
            "include_options": False,
        }))
        assert result["ok"] is True
        assert result["comparison"] == []

    @pytest.mark.asyncio
    async def test_recommendations_present(self):
        result = _parse(await handle_legal_social_protection({
            "status": "TNS",
        }))
        assert result["ok"] is True
        assert len(result["recommendations"]) > 0


# ── handle_legal_governance_audit ────────────────────────────────────────────

class TestLegalGovernanceAudit:
    @pytest.mark.asyncio
    async def test_basic_audit_sas(self):
        result = _parse(await handle_legal_governance_audit({
            "legal_form": "SAS",
            "founders": 2,
        }))
        assert result["ok"] is True
        assert result["legal_form"] == "SAS"
        assert result["clause_count"] > 0

    @pytest.mark.asyncio
    async def test_with_investors_more_critical(self):
        without = _parse(await handle_legal_governance_audit({
            "legal_form": "SAS",
            "founders": 2,
            "has_investors": False,
        }))
        with_inv = _parse(await handle_legal_governance_audit({
            "legal_form": "SAS",
            "founders": 2,
            "has_investors": True,
        }))
        assert with_inv["critical_clauses"] >= without["critical_clauses"]

    @pytest.mark.asyncio
    async def test_unknown_legal_form(self):
        result = _parse(await handle_legal_governance_audit({
            "legal_form": "INVALID",
        }))
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_specific_clauses_filter(self):
        result = _parse(await handle_legal_governance_audit({
            "legal_form": "SAS",
            "specific_clauses": ["agrement_cession", "drag_along"],
        }))
        assert result["ok"] is True
        clause_names = [c["clause"] for c in result["recommended_clauses"]]
        assert set(clause_names).issubset({"agrement_cession", "drag_along"})

    @pytest.mark.asyncio
    async def test_governance_structure_fields(self):
        result = _parse(await handle_legal_governance_audit({
            "legal_form": "SAS",
            "founders": 3,
        }))
        gs = result["governance_structure"]
        assert gs["president"] is True
        assert gs["directeur_general"] is True  # founders > 1


# ── handle_legal_creation_checklist ──────────────────────────────────────────

class TestLegalCreationChecklist:
    @pytest.mark.asyncio
    async def test_basic_checklist(self):
        result = _parse(await handle_legal_creation_checklist({
            "legal_form": "SAS",
        }))
        assert result["ok"] is True
        assert result["total_steps"] > 0
        assert result["estimated_timeline"] == "4-8 semaines"

    @pytest.mark.asyncio
    async def test_cost_range(self):
        result = _parse(await handle_legal_creation_checklist({
            "legal_form": "SAS",
        }))
        assert "€" in result["estimated_cost"]["min"]
        assert "€" in result["estimated_cost"]["max"]

    @pytest.mark.asyncio
    async def test_annual_obligations(self):
        result = _parse(await handle_legal_creation_checklist({
            "legal_form": "SAS",
        }))
        assert len(result["annual_obligations"]) > 0

    @pytest.mark.asyncio
    async def test_unknown_legal_form(self):
        result = _parse(await handle_legal_creation_checklist({
            "legal_form": "WRONG",
        }))
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_micro_no_annual_accounts(self):
        result = _parse(await handle_legal_creation_checklist({
            "legal_form": "MICRO",
        }))
        assert result["ok"] is True
        # MICRO has annual_accounts: False, so "comptes annuels" should be filtered
        obligation_texts = [o["obligation"].lower() for o in result["annual_obligations"]]
        assert not any("comptes annuels" in t for t in obligation_texts)
