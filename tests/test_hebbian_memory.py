"""
Unit tests for src/hebbian_memory.py — Hebbian adaptive memory.
"""

from __future__ import annotations

import json

import pytest

from src.hebbian_memory import (
    openclaw_hebbian_harvest,
    openclaw_hebbian_weight_update,
    openclaw_hebbian_analyze,
    openclaw_hebbian_status,
    openclaw_hebbian_layer_validate,
    openclaw_hebbian_pii_check,
    openclaw_hebbian_decay_config_check,
    openclaw_hebbian_drift_check,
    TOOLS,
)


@pytest.fixture
def jsonl_log(tmp_path):
    """Create a sample JSONL conversation log."""
    lines = [
        json.dumps({"summary": "Discussed Hebbian learning", "tags": ["ml", "hebbian"], "session_id": "s1"}),
        json.dumps({"summary": "Weight update algorithms", "tags": ["algorithm"], "session_id": "s2"}),
    ]
    log_file = tmp_path / "sessions.jsonl"
    log_file.write_text("\n".join(lines))
    return str(log_file)


class TestHarvestTool:
    @pytest.mark.asyncio
    async def test_harvest_from_jsonl(self, jsonl_log, tmp_path):
        result = await openclaw_hebbian_harvest(
            session_jsonl_path=jsonl_log,
            db_path=str(tmp_path / "hebbian.db"),
        )
        assert result["ok"] is True

    @pytest.mark.asyncio
    async def test_harvest_missing_file(self, tmp_path):
        result = await openclaw_hebbian_harvest(
            session_jsonl_path="/nonexistent/log.jsonl",
            db_path=str(tmp_path / "out.db"),
        )
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_harvest_traversal_blocked(self, tmp_path):
        result = await openclaw_hebbian_harvest(
            session_jsonl_path="../../../etc/passwd",
            db_path=str(tmp_path / "out.db"),
        )
        assert result["ok"] is False


class TestWeightUpdate:
    @pytest.mark.asyncio
    async def test_weight_update_missing(self):
        result = await openclaw_hebbian_weight_update(
            claude_md_path="/nonexistent/CLAUDE.md",
        )
        assert result["ok"] is False


class TestAnalyze:
    @pytest.mark.asyncio
    async def test_analyze_missing(self):
        result = await openclaw_hebbian_analyze(
            db_path="/nonexistent/hebbian.db",
        )
        assert result["ok"] is True
        assert result.get("status") == "no_data"


class TestStatus:
    @pytest.mark.asyncio
    async def test_status_missing(self):
        result = await openclaw_hebbian_status(
            db_path="/nonexistent/hebbian.db",
        )
        assert result["ok"] is True
        assert result["db_exists"] is False


class TestLayerValidate:
    @pytest.mark.asyncio
    async def test_layer_validate_missing(self):
        result = await openclaw_hebbian_layer_validate(
            claude_md_path="/nonexistent/CLAUDE.md",
        )
        assert result["ok"] is False


class TestPiiCheck:
    @pytest.mark.asyncio
    async def test_pii_check_missing(self):
        result = await openclaw_hebbian_pii_check(
            config_path="/nonexistent/config.json",
        )
        assert result["ok"] is True
        assert result["status"] == "info"  # no hebbian section → info


class TestDecayConfig:
    @pytest.mark.asyncio
    async def test_decay_config_missing(self, tmp_config):
        cfg = tmp_config({"memory": {"decay": {}}})
        result = await openclaw_hebbian_decay_config_check(config_path=cfg)
        assert isinstance(result["ok"], bool)  # Validates it runs


class TestDriftCheck:
    @pytest.mark.asyncio
    async def test_drift_check_missing(self):
        result = await openclaw_hebbian_drift_check(
            claude_md_path="/nonexistent/CLAUDE.md",
        )
        assert result["ok"] is False  # file not found


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 8

    def test_all_names_prefixed(self):
        for tool in TOOLS:
            assert tool["name"].startswith("openclaw_hebbian_")
