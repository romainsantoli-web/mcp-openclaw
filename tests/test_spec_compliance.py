"""
Unit tests for src/spec_compliance.py — MCP 2025-11-25 spec compliance.
"""

from __future__ import annotations

import pytest

from src.spec_compliance import TOOLS


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 7

    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        expected = {
            "openclaw_elicitation_audit",
            "openclaw_tasks_audit",
            "openclaw_resources_prompts_audit",
            "openclaw_audio_content_audit",
            "openclaw_json_schema_dialect_check",
            "openclaw_sse_transport_audit",
            "openclaw_icon_metadata_audit",
        }
        assert names == expected

    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
