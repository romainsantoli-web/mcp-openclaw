"""
Unit tests for src/runtime_audit.py — runtime config scanning.
"""

from __future__ import annotations



from src.runtime_audit import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 7

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "openclaw_node_version_check",
            "openclaw_secrets_workflow_check",
            "openclaw_http_headers_check",
            "openclaw_nodes_commands_check",
            "openclaw_trusted_proxy_check",
            "openclaw_session_disk_budget_check",
            "openclaw_dm_allowlist_check",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
