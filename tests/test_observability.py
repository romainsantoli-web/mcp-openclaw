"""Unit tests for src/observability.py."""
from src.observability import TOOLS

class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 2
    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
