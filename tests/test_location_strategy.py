"""
Tests for location_strategy module — 5 tools, positive + negative cases.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from src.location_strategy import (
    handle_location_geo_analysis,
    handle_location_real_estate,
    handle_location_site_score,
    handle_location_incentives,
    handle_location_tco_simulate,
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


def test_all_tools_category_is_location_strategy():
    for tool in TOOLS:
        assert tool["category"] == "location_strategy"


# ── handle_location_geo_analysis ─────────────────────────────────────────────

class TestGeoAnalysis:
    @pytest.mark.asyncio
    async def test_basic_analysis(self):
        result = _parse(await handle_location_geo_analysis({
            "cities": ["Paris", "Lyon"],
        }))
        assert result["ok"] is True
        assert result["cities_analyzed"] == 2
        assert len(result["analyses"]) == 2

    @pytest.mark.asyncio
    async def test_empty_cities_returns_error(self):
        result = _parse(await handle_location_geo_analysis({
            "cities": [],
        }))
        assert result["ok"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_paris_has_metro(self):
        result = _parse(await handle_location_geo_analysis({
            "cities": ["Paris"],
        }))
        paris = result["analyses"][0]
        assert paris["infrastructure"]["public_transport"] == "metro/tram"
        assert paris["infrastructure"]["tgv_access"] is True

    @pytest.mark.asyncio
    async def test_paris_salary_index_higher(self):
        result = _parse(await handle_location_geo_analysis({
            "cities": ["Paris", "Rennes"],
        }))
        paris = next(a for a in result["analyses"] if a["city"] == "Paris")
        rennes = next(a for a in result["analyses"] if a["city"] == "Rennes")
        assert paris["talent_pool"]["estimated_salary_index"] > rennes["talent_pool"]["estimated_salary_index"]

    @pytest.mark.asyncio
    async def test_tech_sector_high_fit(self):
        result = _parse(await handle_location_geo_analysis({
            "cities": ["Lyon"],
            "sector": "tech",
        }))
        assert result["analyses"][0]["sector_fit"] == "HIGH"

    @pytest.mark.asyncio
    async def test_non_tech_sector_medium_fit(self):
        result = _parse(await handle_location_geo_analysis({
            "cities": ["Lyon"],
            "sector": "manufacturing",
        }))
        assert result["analyses"][0]["sector_fit"] == "MEDIUM"


# ── handle_location_real_estate ──────────────────────────────────────────────

class TestRealEstate:
    @pytest.mark.asyncio
    async def test_basic_search(self):
        result = _parse(await handle_location_real_estate({
            "zone": "Île-de-France",
        }))
        assert result["ok"] is True
        assert result["zones_found"] > 0

    @pytest.mark.asyncio
    async def test_budget_filter(self):
        result = _parse(await handle_location_real_estate({
            "zone": "Île-de-France",
            "budget_max": 100,  # very low
        }))
        assert result["ok"] is True
        # Some zones should be over budget
        over_budget = [z for z in result["results"] if not z["within_budget"]]
        assert len(over_budget) > 0

    @pytest.mark.asyncio
    async def test_sorted_by_price(self):
        result = _parse(await handle_location_real_estate({
            "zone": "Île-de-France",
        }))
        prices = [z["price_sqm_year"]["min"] for z in result["results"]]
        assert prices == sorted(prices)

    @pytest.mark.asyncio
    async def test_surface_in_criteria(self):
        result = _parse(await handle_location_real_estate({
            "zone": "Paris",
            "surface_min": 300,
        }))
        assert result["search_criteria"]["surface_min_sqm"] == 300


# ── handle_location_site_score ───────────────────────────────────────────────

class TestSiteScore:
    @pytest.mark.asyncio
    async def test_basic_scoring(self):
        result = _parse(await handle_location_site_score({
            "sites": ["Site A", "Site B"],
        }))
        assert result["ok"] is True
        assert result["sites_scored"] == 2
        assert result["recommended"] is not None

    @pytest.mark.asyncio
    async def test_empty_sites_error(self):
        result = _parse(await handle_location_site_score({
            "sites": [],
        }))
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_custom_scores_affect_ranking(self):
        result = _parse(await handle_location_site_score({
            "sites": ["Site A", "Site B"],
            "scores": {
                "Site A": {"transport_access": 10, "fiber_connectivity": 10},
                "Site B": {"transport_access": 1, "fiber_connectivity": 1},
            },
        }))
        assert result["recommended"] == "Site A"
        assert result["results"][0]["total_score"] > result["results"][1]["total_score"]

    @pytest.mark.asyncio
    async def test_sorted_by_score_desc(self):
        result = _parse(await handle_location_site_score({
            "sites": ["X", "Y", "Z"],
        }))
        scores = [s["total_score"] for s in result["results"]]
        assert scores == sorted(scores, reverse=True)


# ── handle_location_incentives ───────────────────────────────────────────────

class TestIncentives:
    @pytest.mark.asyncio
    async def test_basic_incentives(self):
        result = _parse(await handle_location_incentives({
            "zone": "Paris",
        }))
        assert result["ok"] is True
        assert result["total_incentive_programs"] > 0

    @pytest.mark.asyncio
    async def test_tax_zones_present(self):
        result = _parse(await handle_location_incentives({
            "zone": "Lyon",
        }))
        assert len(result["tax_zones"]) > 0

    @pytest.mark.asyncio
    async def test_national_aids_present(self):
        result = _parse(await handle_location_incentives({
            "zone": "Nantes",
            "company_type": "startup",
        }))
        assert len(result["national_aids"]) > 0

    @pytest.mark.asyncio
    async def test_large_company_filters_jei(self):
        small = _parse(await handle_location_incentives({
            "headcount": 10,
        }))
        large = _parse(await handle_location_incentives({
            "headcount": 300,
        }))
        # Large company should have fewer aids (JEI filtered)
        assert len(large["national_aids"]) <= len(small["national_aids"])


# ── handle_location_tco_simulate ─────────────────────────────────────────────

class TestTcoSimulate:
    @pytest.mark.asyncio
    async def test_basic_tco(self):
        result = _parse(await handle_location_tco_simulate({
            "sites": ["Paris QCA"],
        }))
        assert result["ok"] is True
        assert result["sites_compared"] == 1

    @pytest.mark.asyncio
    async def test_empty_sites_error(self):
        result = _parse(await handle_location_tco_simulate({
            "sites": [],
        }))
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_multi_year_projections(self):
        result = _parse(await handle_location_tco_simulate({
            "sites": ["Paris QCA"],
            "horizon_years": 5,
        }))
        sim = result["simulations"][0]
        assert len(sim["yearly_projections"]) == 5

    @pytest.mark.asyncio
    async def test_sorted_by_tco(self):
        result = _parse(await handle_location_tco_simulate({
            "sites": ["Paris QCA", "La Défense", "Saint-Denis"],
        }))
        tcos = [s["total_tco"] for s in result["simulations"]]
        assert tcos == sorted(tcos)

    @pytest.mark.asyncio
    async def test_savings_computed(self):
        result = _parse(await handle_location_tco_simulate({
            "sites": ["Paris QCA", "Saint-Denis"],
        }))
        if result["sites_compared"] > 1:
            assert result["potential_savings"] >= 0

    @pytest.mark.asyncio
    async def test_cost_per_employee(self):
        result = _parse(await handle_location_tco_simulate({
            "sites": ["Paris QCA"],
            "headcount": 20,
        }))
        sim = result["simulations"][0]
        assert sim["cost_per_employee_month"] > 0
