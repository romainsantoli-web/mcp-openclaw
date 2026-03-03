"""
Unit tests for src/gateway_hardening.py — Gateway auth and credentials.
"""

from __future__ import annotations


from src.gateway_hardening import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 5

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "firm_gateway_auth_check",
            "firm_credentials_check",
            "firm_webhook_sig_check",
            "firm_log_config_check",
            "firm_workspace_integrity_check",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
