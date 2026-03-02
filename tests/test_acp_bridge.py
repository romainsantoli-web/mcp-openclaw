"""Unit tests for src/acp_bridge.py."""
from src.acp_bridge import TOOLS

class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 7
    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
