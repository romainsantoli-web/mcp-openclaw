"""Unit tests for src/i18n_audit.py."""
from src.i18n_audit import TOOLS

class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 1
    def test_all_have_handler(self):
        for tool in TOOLS:
            assert callable(tool["handler"])
