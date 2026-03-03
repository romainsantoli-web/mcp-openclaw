"""
Unit tests for src/security_audit.py — Firm security scanning tools.
"""

from __future__ import annotations


from src.security_audit import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 4

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "firm_security_scan",
            "firm_sandbox_audit",
            "firm_session_config_check",
            "firm_rate_limit_check",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])

    def test_all_have_input_schema(self):
        for tool in TOOLS:
            assert "inputSchema" in tool
            assert tool["inputSchema"]["type"] == "object"
