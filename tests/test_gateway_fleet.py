"""Unit tests for src/gateway_fleet.py."""
from src.gateway_fleet import TOOLS

class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 6
    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
