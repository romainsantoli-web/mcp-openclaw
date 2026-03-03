"""
Unit tests for src/compliance_medium.py — medium-priority compliance tools.
"""

from __future__ import annotations


from src.compliance_medium import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 6

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "firm_tool_deprecation_audit",
            "firm_circuit_breaker_audit",
            "firm_gdpr_residency_audit",
            "firm_agent_identity_audit",
            "firm_model_routing_audit",
            "firm_resource_links_audit",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
