"""
Unit tests for src/gateway_hardening.py — Gateway auth and credentials.
"""

from __future__ import annotations

import pytest

from src.gateway_hardening import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 5

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "openclaw_gateway_auth_check",
            "openclaw_credentials_check",
            "openclaw_webhook_sig_check",
            "openclaw_log_config_check",
            "openclaw_workspace_integrity_check",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
