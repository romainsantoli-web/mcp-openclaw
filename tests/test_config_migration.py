"""
Unit tests for src/config_migration.py — config migration tools.
"""

from __future__ import annotations


from src.config_migration import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 5

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "openclaw_shell_env_check",
            "openclaw_plugin_integrity_check",
            "openclaw_token_separation_check",
            "openclaw_otel_redaction_check",
            "openclaw_rpc_rate_limit_check",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
