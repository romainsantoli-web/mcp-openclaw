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
            "firm_node_version_check",
            "firm_secrets_workflow_check",
            "firm_http_headers_check",
            "firm_nodes_commands_check",
            "firm_trusted_proxy_check",
            "firm_session_disk_budget_check",
            "firm_dm_allowlist_check",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
