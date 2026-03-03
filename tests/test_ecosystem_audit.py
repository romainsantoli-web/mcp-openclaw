"""
Unit tests for src/ecosystem_audit.py — ecosystem differentiation.
"""

from __future__ import annotations


from src.ecosystem_audit import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 7

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "firm_mcp_firewall_check",
            "firm_rag_pipeline_check",
            "firm_sandbox_exec_check",
            "firm_context_health_check",
            "firm_provenance_tracker",
            "firm_cost_analytics",
            "firm_token_budget_optimizer",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
