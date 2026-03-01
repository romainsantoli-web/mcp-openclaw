"""
Unit tests for src/ecosystem_audit.py — ecosystem differentiation.
"""

from __future__ import annotations

import pytest

from src.ecosystem_audit import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 7

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "openclaw_mcp_firewall_check",
            "openclaw_rag_pipeline_check",
            "openclaw_sandbox_exec_check",
            "openclaw_context_health_check",
            "openclaw_provenance_tracker",
            "openclaw_cost_analytics",
            "openclaw_token_budget_optimizer",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
