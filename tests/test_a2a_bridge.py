"""
Unit tests for src/a2a_bridge.py — A2A Protocol RC v1.0 bridge.

Tests: card generation, validation, task lifecycle, cancel, subscribe, push config, discovery.
"""

from __future__ import annotations

import json

import pytest

from src.a2a_bridge import (
    A2A_SPEC_VERSION,
    _generate_card_from_soul,
    _sign_agent_card,
    _text_part,
    _file_part,
    _data_part,
    _validate_agent_card,
    firm_a2a_card_generate,
    firm_a2a_card_validate,
    firm_a2a_task_send,
    firm_a2a_task_status,
    firm_a2a_cancel_task,
    firm_a2a_subscribe_task,
    firm_a2a_push_config,
    firm_a2a_discovery,
    TOOLS,
)


class TestPartHelpers:
    def test_text_part(self):
        p = _text_part("hello")
        assert p == {"type": "TextPart", "text": "hello"}

    def test_file_part(self):
        p = _file_part("https://example.com/f.pdf", "application/pdf")
        assert p["type"] == "FilePart"
        assert p["file"]["uri"] == "https://example.com/f.pdf"
        assert p["file"]["mimeType"] == "application/pdf"

    def test_data_part(self):
        p = _data_part({"key": "val"})
        assert p == {"type": "DataPart", "data": {"key": "val"}}

    def test_no_kind_discriminator(self):
        """RC v1.0: parts should NOT have a 'kind' field."""
        for part in [_text_part("x"), _file_part("u"), _data_part({})]:
            assert "kind" not in part


class TestCardGeneration:
    def test_generate_from_soul(self, tmp_path):
        soul = tmp_path / "SOUL.md"
        soul.write_text("---\nname: TestBot\ndescription: A test agent\n---\n# Skills\n## Analysis\n## Reporting\n")
        card = _generate_card_from_soul(str(soul), "https://example.com/bot")
        assert card["name"] == "TestBot"
        assert card["url"] == "https://example.com/bot"
        assert len(card["skills"]) == 2
        assert card["defaultInputModes"] == ["text/plain", "application/json"]

    def test_generate_with_extensions(self, tmp_path):
        soul = tmp_path / "SOUL.md"
        soul.write_text("---\nname: ExtBot\n---\n# Skills\n## Default\n")
        exts = [{"uri": "https://example.com/ext/custom", "required": True}]
        card = _generate_card_from_soul(str(soul), "https://example.com", extensions=exts)
        assert card["extensions"] == exts

    def test_generate_with_security_schemes(self, tmp_path):
        soul = tmp_path / "SOUL.md"
        soul.write_text("---\nname: SecBot\n---\n# Skills\n## Default\n")
        schemes = {"bearer": {"type": "http", "scheme": "bearer"}}
        card = _generate_card_from_soul(str(soul), "https://example.com", security_schemes=schemes)
        assert "securitySchemes" in card
        assert card["security"] == [{"bearer": []}]

    def test_generate_missing_file(self):
        with pytest.raises(FileNotFoundError):
            _generate_card_from_soul("/nonexistent/SOUL.md", "https://example.com")

    def test_sign_agent_card(self, sample_agent_card):
        signed = _sign_agent_card(sample_agent_card, "sk-test-secret-key-123")
        assert signed["signature"]["algorithm"] == "RS256"
        assert signed["signature"]["signed"] is True
        assert "key_hint" in signed["signature"]
        assert "jcs_canonical_hash" in signed
        assert len(signed["jcs_canonical_hash"]) == 64  # SHA-256 hex


class TestCardValidation:
    def test_valid_card(self, sample_agent_card):
        issues = _validate_agent_card(sample_agent_card)
        critical = [i for i in issues if i["severity"] == "CRITICAL"]
        assert len(critical) == 0

    def test_missing_required_fields(self):
        issues = _validate_agent_card({})
        critical = [i for i in issues if i["severity"] == "CRITICAL"]
        assert len(critical) >= 3  # name, url, skills, version

    def test_invalid_url_scheme(self):
        card = {"name": "X", "url": "ftp://bad.com", "version": "1.0.0", "skills": []}
        issues = _validate_agent_card(card)
        url_issues = [i for i in issues if i["field"] == "url"]
        assert any(i["severity"] == "HIGH" for i in url_issues)

    def test_duplicate_skill_ids(self):
        card = {
            "name": "X", "url": "https://ok.com", "version": "1.0",
            "skills": [{"id": "dup", "name": "A"}, {"id": "dup", "name": "B"}],
        }
        issues = _validate_agent_card(card)
        dup_issues = [i for i in issues if "Duplicate" in i.get("message", "")]
        assert len(dup_issues) == 1

    def test_invalid_security_scheme_type(self):
        card = {
            "name": "X", "url": "https://ok.com", "version": "1.0", "skills": [],
            "securitySchemes": {"bad": {"type": "unknown"}},
        }
        issues = _validate_agent_card(card)
        scheme_issues = [i for i in issues if "security" in i.get("field", "").lower()]
        assert len(scheme_issues) >= 1

    def test_unknown_capability_warning(self):
        card = {
            "name": "X", "url": "https://ok.com", "version": "1.0", "skills": [],
            "capabilities": {"unknownCap": True},
        }
        issues = _validate_agent_card(card)
        cap_issues = [i for i in issues if i["severity"] == "INFO" and "capability" in i.get("message", "").lower()]
        assert len(cap_issues) == 1


class TestCardGenerateTool:
    def test_card_generate_ok(self, tmp_path):
        soul = tmp_path / "SOUL.md"
        soul.write_text("---\nname: ToolBot\n---\n# Skills\n## Default\n")
        result = firm_a2a_card_generate(str(soul), "https://example.com")
        assert result["ok"] is True
        assert result["a2a_spec_version"] == A2A_SPEC_VERSION

    def test_card_generate_with_sign(self, tmp_path):
        soul = tmp_path / "SOUL.md"
        soul.write_text("---\nname: SignBot\n---\n# Skills\n## Default\n")
        result = firm_a2a_card_generate(str(soul), "https://example.com", sign=True, signing_key="sk-123")
        assert "signature" in result
        assert result["signature"]["signed"] is True

    def test_card_generate_missing_file(self):
        result = firm_a2a_card_generate("/nonexistent/SOUL.md", "https://example.com")
        assert result["ok"] is False
        assert "error" in result

    def test_card_generate_writes_output(self, tmp_path):
        soul = tmp_path / "SOUL.md"
        soul.write_text("---\nname: OutBot\n---\n# Skills\n## Default\n")
        out = tmp_path / "card.json"
        result = firm_a2a_card_generate(str(soul), "https://example.com", output_path=str(out))
        assert result["ok"] is True
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["name"] == "OutBot"


class TestCardValidateTool:
    def test_validate_valid_card(self, sample_agent_card):
        result = firm_a2a_card_validate(card_json=sample_agent_card)
        assert result["ok"] is True
        assert result["a2a_spec_version"] == A2A_SPEC_VERSION

    def test_validate_from_file(self, tmp_path, sample_agent_card):
        card_file = tmp_path / "card.json"
        card_file.write_text(json.dumps(sample_agent_card))
        result = firm_a2a_card_validate(card_path=str(card_file))
        assert result["ok"] is True

    def test_validate_missing_file(self):
        result = firm_a2a_card_validate(card_path="/nonexistent.json")
        assert result["ok"] is False

    def test_validate_no_input(self):
        result = firm_a2a_card_validate()
        assert result["ok"] is False


class TestTaskLifecycle:
    @pytest.mark.asyncio
    async def test_task_send_ok(self):
        result = await firm_a2a_task_send("https://remote.example.com/agent", "Hello")
        assert result["ok"] is True
        assert result["a2a_method"] == "SendMessage"
        assert "task_id" in result

    @pytest.mark.asyncio
    async def test_task_send_ssrf_localhost(self):
        result = await firm_a2a_task_send("http://localhost:8080/agent", "Evil")
        assert result["ok"] is False
        assert "ssrf" in result.get("error", "").lower() or "blocked" in result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_task_send_invalid_scheme(self):
        result = await firm_a2a_task_send("ftp://bad.com/agent", "Test")
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_task_send_blocking(self):
        result = await firm_a2a_task_send("https://remote.example.com/agent", "Hello", blocking=True)
        assert result["ok"] is True
        assert result["status"]["state"] == "completed"

    @pytest.mark.asyncio
    async def test_task_status_get(self):
        send_result = await firm_a2a_task_send("https://remote.example.com/agent", "Test")
        task_id = send_result["task_id"]
        status_result = await firm_a2a_task_status(task_id=task_id)
        assert status_result["ok"] is True
        assert status_result["a2a_method"] == "GetTask"
        assert status_result["task_id"] == task_id

    @pytest.mark.asyncio
    async def test_task_status_not_found(self):
        result = await firm_a2a_task_status(task_id="nonexistent-id")
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_task_list(self):
        await firm_a2a_task_send("https://remote.example.com/a", "T1")
        await firm_a2a_task_send("https://remote.example.com/b", "T2")
        result = await firm_a2a_task_status()
        assert result["ok"] is True
        assert result["a2a_method"] == "ListTasks"
        assert result["total"] == 2

    @pytest.mark.asyncio
    async def test_task_status_with_history(self):
        send_result = await firm_a2a_task_send("https://remote.example.com/agent", "Test")
        result = await firm_a2a_task_status(task_id=send_result["task_id"], include_history=True)
        assert "history" in result
        assert len(result["history"]) >= 1


class TestCancelTask:
    @pytest.mark.asyncio
    async def test_cancel_working_task(self):
        send = await firm_a2a_task_send("https://remote.example.com/agent", "Long task")
        result = await firm_a2a_cancel_task(send["task_id"])
        assert result["ok"] is True
        assert result["a2a_method"] == "CancelTask"
        assert result["status"]["state"] == "canceled"

    @pytest.mark.asyncio
    async def test_cancel_completed_task_fails(self):
        send = await firm_a2a_task_send("https://remote.example.com/agent", "Quick", blocking=True)
        result = await firm_a2a_cancel_task(send["task_id"])
        assert result["ok"] is False
        assert "terminal" in result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_cancel_nonexistent(self):
        result = await firm_a2a_cancel_task("no-such-task")
        assert result["ok"] is False


class TestSubscribeTask:
    @pytest.mark.asyncio
    async def test_subscribe_ok(self):
        send = await firm_a2a_task_send("https://remote.example.com/agent", "Test")
        result = await firm_a2a_subscribe_task(send["task_id"])
        assert result["ok"] is True
        assert result["a2a_method"] == "SubscribeToTask"
        assert result["streaming"] is True
        assert len(result["initial_events"]) >= 1

    @pytest.mark.asyncio
    async def test_subscribe_completed_with_artifacts(self):
        send = await firm_a2a_task_send("https://remote.example.com/agent", "Done", blocking=True)
        result = await firm_a2a_subscribe_task(send["task_id"])
        assert result["ok"] is True
        artifact_events = [e for e in result["initial_events"] if e["type"] == "TaskArtifactUpdateEvent"]
        assert len(artifact_events) >= 1

    @pytest.mark.asyncio
    async def test_subscribe_nonexistent(self):
        result = await firm_a2a_subscribe_task("no-task")
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_subscribe_ssrf_callback(self):
        send = await firm_a2a_task_send("https://remote.example.com/agent", "Test")
        result = await firm_a2a_subscribe_task(send["task_id"], callback_url="http://127.0.0.1:9999/hook")
        assert result["ok"] is False


class TestPushConfig:
    @pytest.mark.asyncio
    async def test_push_create_and_list(self):
        send = await firm_a2a_task_send("https://remote.example.com/agent", "Test")
        tid = send["task_id"]
        create = firm_a2a_push_config(tid, action="create", webhook_url="https://hooks.example.com/cb")
        assert create["ok"] is True
        lst = firm_a2a_push_config(tid, action="list")
        assert lst["total"] == 1

    @pytest.mark.asyncio
    async def test_push_get_and_delete(self):
        send = await firm_a2a_task_send("https://remote.example.com/agent", "Test")
        tid = send["task_id"]
        create = firm_a2a_push_config(tid, action="create", webhook_url="https://hooks.example.com/cb")
        cfg_id = create["config"]["id"]
        get = firm_a2a_push_config(tid, action="get", config_id=cfg_id)
        assert get["ok"] is True
        delete = firm_a2a_push_config(tid, action="delete", config_id=cfg_id)
        assert delete["ok"] is True
        lst = firm_a2a_push_config(tid, action="list")
        assert lst["total"] == 0

    def test_push_ssrf_blocked(self):
        from src.a2a_bridge import _TASKS
        _TASKS["fake"] = {"id": "fake", "status": {"state": "working"}}
        result = firm_a2a_push_config("fake", action="create", webhook_url="http://localhost/hook")
        assert result["ok"] is False

    def test_push_nonexistent_task(self):
        result = firm_a2a_push_config("nope", action="list")
        assert result["ok"] is False


class TestDiscovery:
    @pytest.mark.asyncio
    async def test_discovery_local_souls(self, soul_dir):
        d = soul_dir({"ceo": "---\nname: CEO\n---\n# Skills\n## Strategy\n## Leadership\n"})
        result = await firm_a2a_discovery(souls_dir=d)
        assert result["ok"] is True
        assert result["total"] == 1
        assert result["agents"][0]["name"] == "CEO"

    @pytest.mark.asyncio
    async def test_discovery_remote_urls(self):
        result = await firm_a2a_discovery(urls=["https://agents.example.com/bot1"])
        assert result["ok"] is True
        assert result["total"] == 1
        assert result["agents"][0]["source"] == "remote"

    @pytest.mark.asyncio
    async def test_discovery_invalid_dir(self):
        result = await firm_a2a_discovery(souls_dir="/nonexistent")
        assert result["ok"] is False


class TestToolsRegistry:
    def test_tools_count(self):
        assert len(TOOLS) == 8

    def test_all_tools_have_required_fields(self):
        for tool in TOOLS:
            assert "name" in tool
            assert "handler" in tool
            assert "inputSchema" in tool
            assert tool["name"].startswith("firm_a2a_")

    def test_spec_version(self):
        assert A2A_SPEC_VERSION == "1.0.0-rc"
