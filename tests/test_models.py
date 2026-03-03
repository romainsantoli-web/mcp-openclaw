"""
Unit tests for src/models.py — Pydantic validation models.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models import (
    TOOL_MODELS,
    A2aCardGenerateInput,
    A2aCardValidateInput,
    A2aTaskSendInput,
    A2aCancelTaskInput,
    A2aSubscribeTaskInput,
    A2aPushConfigInput,
    A2aDiscoveryInput,
)


class TestToolModelsRegistry:
    def test_all_tools_in_registry(self):
        assert len(TOOL_MODELS) >= 115, f"Expected at least 115, got {len(TOOL_MODELS)}"

    def test_new_a2a_tools_in_registry(self):
        assert "firm_a2a_cancel_task" in TOOL_MODELS
        assert "firm_a2a_subscribe_task" in TOOL_MODELS

    def test_all_values_are_pydantic_models(self):
        from pydantic import BaseModel
        for name, model_cls in TOOL_MODELS.items():
            assert issubclass(model_cls, BaseModel), f"{name} is not a BaseModel subclass"


class TestA2aCardGenerateInput:
    def test_valid_input(self):
        m = A2aCardGenerateInput(soul_path="./souls/ceo/SOUL.md", base_url="https://example.com")
        assert m.soul_path == "./souls/ceo/SOUL.md"
        assert m.sign is False

    def test_traversal_blocked_soul_path(self):
        with pytest.raises(ValidationError, match="traversal"):
            A2aCardGenerateInput(soul_path="../../../etc/passwd", base_url="https://example.com")

    def test_traversal_blocked_output_path(self):
        with pytest.raises(ValidationError, match="traversal"):
            A2aCardGenerateInput(soul_path="./ok.md", base_url="https://example.com", output_path="/tmp/../../../etc/shadow")

    def test_base_url_too_short(self):
        with pytest.raises(ValidationError):
            A2aCardGenerateInput(soul_path="./s.md", base_url="h")

    def test_sign_and_key(self):
        m = A2aCardGenerateInput(soul_path="./s.md", base_url="https://x.com", sign=True, signing_key="sk-123")
        assert m.sign is True


class TestA2aCardValidateInput:
    def test_at_least_one_required(self):
        with pytest.raises(ValidationError):
            A2aCardValidateInput()

    def test_card_json_ok(self):
        m = A2aCardValidateInput(card_json={"name": "X"})
        assert m.card_json is not None

    def test_card_path_traversal(self):
        with pytest.raises(ValidationError, match="traversal"):
            A2aCardValidateInput(card_path="../../etc/passwd")


class TestA2aTaskSendInput:
    def test_valid(self):
        m = A2aTaskSendInput(agent_url="https://example.com/agent", message="Hello")
        assert m.blocking is False

    def test_empty_message_rejected(self):
        with pytest.raises(ValidationError):
            A2aTaskSendInput(agent_url="https://example.com/agent", message="")


class TestA2aCancelTaskInput:
    def test_valid(self):
        m = A2aCancelTaskInput(task_id="abc-123")
        assert m.task_id == "abc-123"

    def test_empty_id_rejected(self):
        with pytest.raises(ValidationError):
            A2aCancelTaskInput(task_id="")


class TestA2aSubscribeTaskInput:
    def test_valid(self):
        m = A2aSubscribeTaskInput(task_id="abc-123")
        assert m.callback_url is None

    def test_with_callback(self):
        m = A2aSubscribeTaskInput(task_id="abc-123", callback_url="https://hooks.example.com/cb")
        assert m.callback_url is not None

    def test_empty_id_rejected(self):
        with pytest.raises(ValidationError):
            A2aSubscribeTaskInput(task_id="")


class TestA2aPushConfigInput:
    def test_valid_list(self):
        m = A2aPushConfigInput(task_id="t-1", action="list")
        assert m.action == "list"

    def test_invalid_action(self):
        with pytest.raises(ValidationError):
            A2aPushConfigInput(task_id="t-1", action="invalid")


class TestA2aDiscoveryInput:
    def test_valid(self):
        m = A2aDiscoveryInput(souls_dir="./souls")
        assert m.check_reachability is False

    def test_traversal_blocked(self):
        with pytest.raises(ValidationError, match="traversal"):
            A2aDiscoveryInput(souls_dir="../../etc")
