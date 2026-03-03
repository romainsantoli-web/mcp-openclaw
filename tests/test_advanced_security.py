"""
Unit tests for src/advanced_security.py — advanced security scanning.
"""

from __future__ import annotations


from src.advanced_security import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 8

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "firm_secrets_lifecycle_check",
            "firm_channel_auth_canon_check",
            "firm_exec_approval_freeze_check",
            "firm_hook_session_routing_check",
            "firm_config_include_check",
            "firm_config_prototype_check",
            "firm_safe_bins_profile_check",
            "firm_group_policy_default_check",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
