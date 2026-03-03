"""
Tests for market_research module — 6 tools, positive + negative cases.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.market_research import (
    openclaw_market_competitive_analysis,
    openclaw_market_sizing,
    openclaw_market_financial_benchmark,
    openclaw_market_web_research,
    openclaw_market_report_generate,
    openclaw_market_research_monitor,
    _MONITOR_WATCHLIST,
    _RESEARCH_CACHE,
    TOOLS,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clear_stores():
    """Clear in-memory stores between tests."""
    _MONITOR_WATCHLIST.clear()
    _RESEARCH_CACHE.clear()
    yield
    _MONITOR_WATCHLIST.clear()
    _RESEARCH_CACHE.clear()


# ── TOOLS registry ───────────────────────────────────────────────────────────

def test_tools_registry_has_6_tools():
    assert len(TOOLS) == 6


def test_all_tools_have_required_fields():
    required = {"name", "title", "description", "category", "handler", "inputSchema"}
    for tool in TOOLS:
        missing = required - set(tool.keys())
        assert not missing, f"Tool {tool['name']} missing: {missing}"


def test_all_tools_category_is_market_research():
    for tool in TOOLS:
        assert tool["category"] == "market_research"


# ── openclaw_market_competitive_analysis ─────────────────────────────────────

class TestCompetitiveAnalysis:
    def test_basic_analysis(self):
        result = openclaw_market_competitive_analysis(
            sector="SaaS project management",
            competitors=["Monday.com", "Asana", "Notion"],
            geography="France",
        )
        assert result["ok"] is True
        assert result["sector"] == "SaaS project management"
        assert result["competitors_count"] == 3
        assert len(result["feature_matrix"]) == 3
        assert result["swot_analysis"] is not None
        assert result["positioning_map"] is not None

    def test_with_our_product(self):
        result = openclaw_market_competitive_analysis(
            sector="CRM",
            competitors=["Salesforce"],
            our_product="MyCRM",
        )
        assert result["ok"] is True
        # Our product row should be first
        assert result["feature_matrix"][0]["competitor"].startswith("✅")

    def test_without_swot_and_positioning(self):
        result = openclaw_market_competitive_analysis(
            sector="EdTech",
            include_swot=False,
            include_positioning=False,
        )
        assert result["ok"] is True
        assert result["swot_analysis"] is None
        assert result["positioning_map"] is None

    def test_custom_criteria(self):
        custom = ["price", "support", "integrations"]
        result = openclaw_market_competitive_analysis(
            sector="Fintech",
            competitors=["Stripe"],
            criteria=custom,
        )
        assert result["criteria"] == custom
        for row in result["feature_matrix"]:
            for c in custom:
                assert c in row

    def test_no_competitors_empty_list(self):
        result = openclaw_market_competitive_analysis(sector="Test")
        assert result["ok"] is True
        assert result["competitors_count"] == 0
        assert result["feature_matrix"] == []

    def test_caches_result(self):
        openclaw_market_competitive_analysis(sector="Cache Test")
        assert "competitive_Cache Test" in _RESEARCH_CACHE


# ── openclaw_market_sizing ───────────────────────────────────────────────────

class TestMarketSizing:
    def test_basic_both_approaches(self):
        result = openclaw_market_sizing(sector="SaaS PM", geography="France")
        assert result["ok"] is True
        assert result["top_down"] is not None
        assert result["bottom_up"] is not None
        assert result["approach"] == "both"

    def test_top_down_only(self):
        result = openclaw_market_sizing(sector="CRM", approach="top_down")
        assert result["top_down"] is not None
        assert result["bottom_up"] is None

    def test_bottom_up_only(self):
        result = openclaw_market_sizing(sector="CRM", approach="bottom_up")
        assert result["top_down"] is None
        assert result["bottom_up"] is not None

    def test_with_known_data(self):
        data = {"tam": "€5B", "cagr": "12%", "total_market": "€50B"}
        result = openclaw_market_sizing(sector="AI", known_data=data)
        assert result["ok"] is True
        assert result["top_down"]["tam"] == "€5B"

    def test_horizon_years(self):
        result = openclaw_market_sizing(sector="IoT", horizon_years=10)
        assert result["horizon_years"] == 10
        projections = result["bottom_up"]["year_projections"]
        assert "year_10" in projections

    def test_caches_result(self):
        openclaw_market_sizing(sector="Cache Sizing")
        assert "sizing_Cache Sizing" in _RESEARCH_CACHE


# ── openclaw_market_financial_benchmark ──────────────────────────────────────

class TestFinancialBenchmark:
    def test_basic_benchmark(self):
        result = openclaw_market_financial_benchmark(sector="SaaS")
        assert result["ok"] is True
        assert len(result["benchmark_table"]) > 0
        assert result["pricing_analysis"] is not None

    def test_specific_metrics(self):
        result = openclaw_market_financial_benchmark(
            sector="SaaS",
            metrics=["CAC", "LTV", "churn"],
        )
        assert len(result["benchmark_table"]) == 3
        metric_names = [r["metric"] for r in result["benchmark_table"]]
        assert "CAC" in metric_names

    def test_with_our_data(self):
        our = {"CAC": "€150", "LTV": "€1200", "churn": "3%"}
        result = openclaw_market_financial_benchmark(
            sector="SaaS",
            metrics=["CAC", "LTV", "churn"],
            our_data=our,
        )
        for row in result["benchmark_table"]:
            if row["metric"] == "CAC":
                assert row["our_value"] == "€150"
                assert row["confidence"] == "HIGH"

    def test_with_competitors(self):
        result = openclaw_market_financial_benchmark(
            sector="SaaS",
            competitors=["Stripe", "Square"],
        )
        assert "Stripe" in result["competitor_profiles"]
        assert "Square" in result["competitor_profiles"]

    def test_without_pricing(self):
        result = openclaw_market_financial_benchmark(
            sector="SaaS",
            include_pricing=False,
        )
        assert result["pricing_analysis"] is None

    def test_health_indicators_without_data(self):
        result = openclaw_market_financial_benchmark(sector="Test")
        assert result["health_indicators"]["key_ratios"]["ltv_cac"]["our_value"] == "[N/A]"


# ── openclaw_market_web_research ─────────────────────────────────────────────

class TestWebResearch:
    def test_basic_search(self):
        result = openclaw_market_web_research(query="SaaS market France 2026")
        assert result["ok"] is True
        assert result["query"] == "SaaS market France 2026"
        assert result["sources_planned"] == 3  # default sources

    def test_specific_sources(self):
        result = openclaw_market_web_research(
            query="Test",
            sources=["crunchbase", "g2", "linkedin", "github"],
        )
        assert result["sources_planned"] == 4

    def test_with_competitor(self):
        result = openclaw_market_web_research(
            query="competitive analysis",
            competitor="Monday.com",
        )
        assert result["competitor"] == "Monday.com"
        # Suggested queries should include competitor-specific ones
        assert any("Monday.com" in q for q in result["search_queries_suggested"])

    def test_without_competitor_no_competitor_queries(self):
        result = openclaw_market_web_research(query="general market")
        # No None values in suggestions
        assert all(q is not None for q in result["search_queries_suggested"])

    def test_caches_result(self):
        openclaw_market_web_research(query="Cache web test")
        assert any("research_" in k for k in _RESEARCH_CACHE)


# ── openclaw_market_report_generate ──────────────────────────────────────────

class TestReportGenerate:
    def test_basic_report(self, tmp_path):
        out = str(tmp_path / "report.md")
        result = openclaw_market_report_generate(
            title="Test Market Report",
            output_path=out,
        )
        assert result["ok"] is True
        assert result["sections_count"] == 9  # all default sections
        assert Path(out).exists()
        content = Path(out).read_text(encoding="utf-8")
        assert "📊 Test Market Report" in content
        assert "Executive Summary" in content
        assert "⚠️" in content  # AI disclaimer

    def test_specific_sections(self, tmp_path):
        out = str(tmp_path / "partial.md")
        result = openclaw_market_report_generate(
            title="Partial Report",
            sections=["executive_summary", "recommendations"],
            output_path=out,
        )
        assert result["sections_count"] == 2
        content = Path(out).read_text(encoding="utf-8")
        assert "Executive Summary" in content
        assert "Recommandations" in content
        # Should NOT contain other sections
        assert "Paysage Concurrentiel" not in content

    def test_auto_output_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MARKET_RESEARCH_OUTPUT_DIR", str(tmp_path))
        # Re-import to pick up env
        from src import market_research
        old_dir = market_research.OUTPUT_DIR
        market_research.OUTPUT_DIR = str(tmp_path)
        try:
            result = openclaw_market_report_generate(title="Auto Path Report")
            assert result["ok"] is True
            assert result["output_path"] is not None
            assert Path(result["output_path"]).exists()
        finally:
            market_research.OUTPUT_DIR = old_dir

    def test_report_with_toc(self, tmp_path):
        out = str(tmp_path / "toc.md")
        result = openclaw_market_report_generate(
            title="TOC Report",
            output_path=out,
            include_toc=True,
        )
        content = Path(out).read_text(encoding="utf-8")
        assert "Table des matières" in content

    def test_report_without_toc(self, tmp_path):
        out = str(tmp_path / "notoc.md")
        result = openclaw_market_report_generate(
            title="No TOC Report",
            output_path=out,
            include_toc=False,
        )
        content = Path(out).read_text(encoding="utf-8")
        assert "Table des matières" not in content

    def test_path_traversal_blocked(self):
        result = openclaw_market_report_generate(
            title="Hack",
            output_path="/tmp/../../../etc/evil.md",
        )
        assert result["ok"] is False
        assert "traversal" in result["error"].lower()

    def test_report_has_cross_department_usage(self, tmp_path):
        out = str(tmp_path / "cross.md")
        result = openclaw_market_report_generate(title="Cross Dept", output_path=out)
        assert "CEO" in result["cross_department_usage"]
        assert "CFO" in result["cross_department_usage"]
        assert "CTO" in result["cross_department_usage"]


# ── openclaw_market_research_monitor ─────────────────────────────────────────

class TestResearchMonitor:
    def test_add_competitor(self):
        result = openclaw_market_research_monitor(
            action="add",
            competitor="Monday.com",
            watch=["pricing", "features"],
        )
        assert result["ok"] is True
        assert result["watchlist_size"] == 1
        assert "Monday.com" in _MONITOR_WATCHLIST

    def test_add_without_competitor_fails(self):
        result = openclaw_market_research_monitor(action="add")
        assert result["ok"] is False

    def test_remove_competitor(self):
        _MONITOR_WATCHLIST["Test"] = {
            "added_at": "now", "watch_items": [], "events": [], "last_checked": "now"
        }
        result = openclaw_market_research_monitor(action="remove", competitor="Test")
        assert result["ok"] is True
        assert "Test" not in _MONITOR_WATCHLIST

    def test_remove_nonexistent_fails(self):
        result = openclaw_market_research_monitor(action="remove", competitor="Ghost")
        assert result["ok"] is False

    def test_update_event(self):
        _MONITOR_WATCHLIST["Comp"] = {
            "added_at": "now", "watch_items": ["pricing"], "events": [], "last_checked": "now"
        }
        result = openclaw_market_research_monitor(
            action="update",
            competitor="Comp",
            notes="New pricing page launched",
        )
        assert result["ok"] is True
        assert result["total_events"] == 1

    def test_update_nonexistent_fails(self):
        result = openclaw_market_research_monitor(
            action="update", competitor="Ghost", notes="test"
        )
        assert result["ok"] is False

    def test_status_empty(self):
        result = openclaw_market_research_monitor(action="status")
        assert result["ok"] is True
        assert result["watchlist_size"] == 0

    def test_status_with_data(self):
        _MONITOR_WATCHLIST["A"] = {
            "added_at": "now", "watch_items": ["pricing"], "events": [{"ts": "now"}], "last_checked": "now"
        }
        result = openclaw_market_research_monitor(action="status")
        assert result["ok"] is True
        assert result["watchlist_size"] == 1

    def test_export(self):
        _MONITOR_WATCHLIST["Export"] = {
            "added_at": "now", "watch_items": ["all"], "events": [], "last_checked": "now"
        }
        result = openclaw_market_research_monitor(action="export")
        assert result["ok"] is True
        assert "Export" in result["data"]

    def test_invalid_action(self):
        result = openclaw_market_research_monitor(action="invalid")
        assert result["ok"] is False

    def test_full_workflow(self):
        """End-to-end: add → update → status → export → remove."""
        # Add
        r1 = openclaw_market_research_monitor(
            action="add", competitor="FlowCo", watch=["pricing", "features"]
        )
        assert r1["ok"]
        # Update
        r2 = openclaw_market_research_monitor(
            action="update", competitor="FlowCo", notes="Raised Series B"
        )
        assert r2["ok"]
        # Status
        r3 = openclaw_market_research_monitor(action="status")
        assert r3["watchlist_size"] == 1
        assert r3["watchlist"][0]["events_count"] == 1
        # Export
        r4 = openclaw_market_research_monitor(action="export")
        assert r4["data"]["FlowCo"]["events_count"] == 1
        # Remove
        r5 = openclaw_market_research_monitor(action="remove", competitor="FlowCo")
        assert r5["ok"]
        assert r5["watchlist_size"] == 0


# ── Pydantic model validation ───────────────────────────────────────────────

class TestPydanticModels:
    def test_competitive_analysis_valid(self):
        from src.models import MarketCompetitiveAnalysisInput
        m = MarketCompetitiveAnalysisInput(sector="Test")
        assert m.sector == "Test"

    def test_competitive_analysis_empty_sector_fails(self):
        from src.models import MarketCompetitiveAnalysisInput
        with pytest.raises(Exception):
            MarketCompetitiveAnalysisInput(sector="")

    def test_sizing_valid(self):
        from src.models import MarketSizingInput
        m = MarketSizingInput(sector="Test", approach="top_down")
        assert m.approach == "top_down"

    def test_sizing_invalid_approach(self):
        from src.models import MarketSizingInput
        with pytest.raises(Exception):
            MarketSizingInput(sector="Test", approach="invalid")

    def test_report_generate_path_traversal(self):
        from src.models import MarketReportGenerateInput
        with pytest.raises(Exception):
            MarketReportGenerateInput(title="Test", output_path="/tmp/../evil")

    def test_report_generate_invalid_language(self):
        from src.models import MarketReportGenerateInput
        with pytest.raises(Exception):
            MarketReportGenerateInput(title="Test", language="de")

    def test_monitor_invalid_action(self):
        from src.models import MarketResearchMonitorInput
        with pytest.raises(Exception):
            MarketResearchMonitorInput(action="destroy")

    def test_web_research_valid(self):
        from src.models import MarketWebResearchInput
        m = MarketWebResearchInput(query="test query")
        assert m.query == "test query"

    def test_web_research_empty_query_fails(self):
        from src.models import MarketWebResearchInput
        with pytest.raises(Exception):
            MarketWebResearchInput(query="")

    def test_financial_benchmark_valid(self):
        from src.models import MarketFinancialBenchmarkInput
        m = MarketFinancialBenchmarkInput(sector="SaaS")
        assert m.include_pricing is True

    def test_sizing_horizon_limits(self):
        from src.models import MarketSizingInput
        with pytest.raises(Exception):
            MarketSizingInput(sector="Test", horizon_years=0)
        with pytest.raises(Exception):
            MarketSizingInput(sector="Test", horizon_years=25)
