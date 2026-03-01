"""Unit tests for src/agent_orchestration.py."""
from src.agent_orchestration import TOOLS

class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 2
    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
