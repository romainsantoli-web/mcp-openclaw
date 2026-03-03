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
            "openclaw_secrets_lifecycle_check",
            "openclaw_channel_auth_canon_check",
            "openclaw_exec_approval_freeze_check",
            "openclaw_hook_session_routing_check",
            "openclaw_config_include_check",
            "openclaw_config_prototype_check",
            "openclaw_safe_bins_profile_check",
            "openclaw_group_policy_default_check",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
