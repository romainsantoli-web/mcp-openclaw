"""Unit tests for src/n8n_bridge.py."""
from src.n8n_bridge import TOOLS

class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 2
    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
