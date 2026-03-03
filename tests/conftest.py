"""
Shared fixtures for firm-mcp-server test suite.

Provides:
  - tmp_config: temporary YAML/JSON config files
  - soul_dir: temporary SOUL.md directory structure
  - mock_config: factory for fake Firm config dicts
  - sample_agent_card: valid A2A Agent Card dict
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def tmp_config(tmp_path: Path):
    """Create a temporary config file and return its path.

    Usage:
        def test_something(tmp_config):
            cfg_path = tmp_config({"gateway": {"auth": {"mode": "password"}}})
    """

    def _make(data: dict[str, Any], name: str = "config.json") -> str:
        p = tmp_path / name
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(p)

    return _make


@pytest.fixture
def soul_dir(tmp_path: Path):
    """Create a temporary directory with SOUL.md files.

    Usage:
        def test_discovery(soul_dir):
            d = soul_dir({"ceo": "---\\nname: CEO\\n---\\n# Skills\\n## Strategy"})
    """

    def _make(souls: dict[str, str]) -> str:
        for name, content in souls.items():
            soul_path = tmp_path / name
            soul_path.mkdir(parents=True, exist_ok=True)
            (soul_path / "SOUL.md").write_text(
                textwrap.dedent(content), encoding="utf-8"
            )
        return str(tmp_path)

    return _make


@pytest.fixture
def mock_config():
    """Factory for fake Firm config dicts."""

    def _make(**overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "gateway": {
                "auth": {"mode": "password"},
                "controlUi": {"dangerouslyDisableDeviceAuth": False},
                "bind": "0.0.0.0",
                "port": 3000,
            },
            "agents": {
                "defaults": {"model": "claude-3-opus", "env": {}},
            },
            "tools": {
                "exec": {"allowCommands": ["git", "ls"], "env": {}},
            },
            "hooks": {"env": {}},
            "nodes": {"allowCommands": ["git", "curl"]},
            "sessions": {"diskBudgetMb": 500},
        }
        base.update(overrides)
        return base

    return _make


@pytest.fixture
def sample_agent_card() -> dict[str, Any]:
    """Return a valid A2A RC v1.0 Agent Card."""
    return {
        "name": "Test Agent",
        "description": "A test A2A agent",
        "url": "https://agents.example.com/test",
        "version": "1.0.0",
        "skills": [
            {
                "id": "test-skill",
                "name": "Test Skill",
                "description": "A test skill",
                "tags": ["test"],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain"],
            }
        ],
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
    }


@pytest.fixture(autouse=True)
def _isolate_a2a_stores():
    """Clear A2A in-memory stores between tests."""
    from src.a2a_bridge import _TASKS, _PUSH_CONFIGS, _SUBSCRIPTIONS

    _TASKS.clear()
    _PUSH_CONFIGS.clear()
    _SUBSCRIPTIONS.clear()
    yield
    _TASKS.clear()
    _PUSH_CONFIGS.clear()
    _SUBSCRIPTIONS.clear()
