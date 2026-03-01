"""Unit tests for src/reliability_probe.py."""
from src.reliability_probe import TOOLS

class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 4
    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
