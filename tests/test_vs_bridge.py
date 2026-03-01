"""Unit tests for src/vs_bridge.py."""
from src.vs_bridge import TOOLS

class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 4
    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
    def test_tool_names(self):
        names = {t["name"] for t in TOOLS}
        assert "vs_context_push" in names
        assert "vs_context_pull" in names
        assert "vs_session_link" in names
        assert "vs_session_status" in names
