"""Unit tests for src/browser_audit.py."""
from src.browser_audit import TOOLS

class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 1
    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
