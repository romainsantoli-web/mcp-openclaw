"""
Unit tests for src/auth_compliance.py — OAuth/OIDC compliance.
"""

from __future__ import annotations

import pytest

from src.auth_compliance import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 2

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {"openclaw_oauth_oidc_audit", "openclaw_token_scope_check"}
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
