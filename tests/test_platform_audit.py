"""
Unit tests for src/platform_audit.py — platform alignment 2026.2.
"""

from __future__ import annotations


from src.platform_audit import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 9

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "firm_secrets_v2_audit",
            "firm_agent_routing_check",
            "firm_voice_security_check",
            "firm_trust_model_check",
            "firm_autoupdate_check",
            "firm_plugin_sdk_check",
            "firm_content_boundary_check",
            "firm_sqlite_vec_check",
            "firm_adaptive_thinking_check",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
