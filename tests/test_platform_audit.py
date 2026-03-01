"""
Unit tests for src/platform_audit.py — platform alignment 2026.2.
"""

from __future__ import annotations

import pytest

from src.platform_audit import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 8

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "openclaw_secrets_v2_audit",
            "openclaw_agent_routing_check",
            "openclaw_voice_security_check",
            "openclaw_trust_model_check",
            "openclaw_autoupdate_check",
            "openclaw_plugin_sdk_check",
            "openclaw_content_boundary_check",
            "openclaw_sqlite_vec_check",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
