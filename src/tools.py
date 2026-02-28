from __future__ import annotations

import importlib
from typing import Any

from .config import Settings
from .firm_repo import (
    FirmRepoError,
    list_agents,
    list_prompts,
    load_prompt,
    repo_status,
    sync_repo,
    validate_layout,
)
from .health import gateway_health
from .memory_adapter import MemoryAdapter
from .openclaw_ws_client import OpenClawError, OpenClawWsClient


def _discover_departments(settings: Settings) -> list[str]:
    agents_dir = settings.firm_repo_path / ".github" / "agents"
    if not agents_dir.exists():
        return []

    departments: list[str] = []
    for file_path in sorted(agents_dir.glob("department-*.agent.md")):
        name = file_path.stem.replace("department-", "").replace(".agent", "")
        departments.append(name)
    return departments


def _load_agent(settings: Settings, agent_name: str) -> dict[str, Any]:
    file_path = (
        settings.firm_repo_path / ".github" / "agents" / f"{agent_name}.agent.md"
    )
    if not file_path.exists():
        return {"ok": False, "error": f"Agent introuvable: {agent_name}"}

    return {
        "ok": True,
        "agent": agent_name,
        "content": file_path.read_text(encoding="utf-8"),
    }


def _build_orchestration_payload(
    objective: str,
    prompt_content: str,
    selected_departments: list[str],
    department_agents: dict[str, str],
    memory_context: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "objective": objective,
        "prompt": {
            "name": "firm-delivery.prompt.md",
            "content": prompt_content,
        },
        "departments": selected_departments,
        "agents": department_agents,
        "memory_context": memory_context,
    }


def build_server(settings: Settings) -> Any:
    fastmcp_module = importlib.import_module("mcp.server.fastmcp")
    mcp = fastmcp_module.FastMCP(
        "mcp-openclaw-wrapper",
        host=settings.mcp_host,
        port=settings.mcp_port,
    )
    ws_client = OpenClawWsClient(settings)
    memory = MemoryAdapter()

    if settings.firm_repo_auto_sync:
        try:
            sync_repo(settings)
        except FirmRepoError:
            pass

    @mcp.tool()
    def firm_repo_status() -> dict[str, Any]:
        return repo_status(settings)

    @mcp.tool()
    def firm_repo_sync() -> dict[str, Any]:
        try:
            return sync_repo(settings)
        except FirmRepoError as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def firm_list_departments() -> dict[str, Any]:
        return {"departments": _discover_departments(settings)}

    @mcp.tool()
    def firm_list_agents() -> dict[str, Any]:
        try:
            return {"agents": list_agents(settings)}
        except FirmRepoError as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def firm_list_prompts() -> dict[str, Any]:
        try:
            return {"prompts": list_prompts(settings)}
        except FirmRepoError as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def firm_load_agent(agent_name: str) -> dict[str, Any]:
        return _load_agent(settings, agent_name)

    @mcp.tool()
    def firm_load_prompt(prompt_name: str) -> dict[str, Any]:
        try:
            return load_prompt(settings, prompt_name)
        except FirmRepoError as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def firm_validate_layout() -> dict[str, Any]:
        try:
            return validate_layout(settings)
        except FirmRepoError as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    async def firm_run_delivery_workflow(
        objective: str,
        departments: list[str] | None = None,
        prompt_name: str = "firm-delivery.prompt.md",
        memory_key: str = "delivery/latest",
        push_to_openclaw: bool = False,
        openclaw_method: str = "agent.run",
    ) -> dict[str, Any]:
        try:
            prompts = list_prompts(settings)
        except FirmRepoError as exc:
            return {"ok": False, "error": str(exc)}

        if prompt_name not in prompts:
            return {
                "ok": False,
                "error": f"Prompt non trouvé: {prompt_name}",
                "available_prompts": prompts,
            }

        prompt_data = load_prompt(settings, prompt_name)
        if not prompt_data.get("ok"):
            return prompt_data

        available_departments = _discover_departments(settings)
        selected_departments = departments or available_departments
        unknown_departments = [
            item for item in selected_departments if item not in available_departments
        ]
        if unknown_departments:
            return {
                "ok": False,
                "error": "Départements inconnus demandés",
                "unknown_departments": unknown_departments,
                "available_departments": available_departments,
            }

        department_agents: dict[str, str] = {}
        for department in selected_departments:
            agent_name = f"department-{department}"
            agent_data = _load_agent(settings, agent_name)
            if not agent_data.get("ok"):
                return {
                    "ok": False,
                    "error": f"Impossible de charger l'agent pour {department}",
                    "details": agent_data,
                }
            department_agents[department] = agent_data["content"]

        memory_context = memory.retrieve(memory_key)
        orchestration_payload = _build_orchestration_payload(
            objective=objective,
            prompt_content=prompt_data["content"],
            selected_departments=selected_departments,
            department_agents=department_agents,
            memory_context=memory_context,
        )

        openclaw_result: dict[str, Any] | None = None
        if push_to_openclaw:
            try:
                response = await ws_client.request(openclaw_method, orchestration_payload)
            except OpenClawError as exc:
                openclaw_result = {"ok": False, "error": str(exc)}
            else:
                if response.error:
                    openclaw_result = {
                        "ok": False,
                        "request_id": response.request_id,
                        "error": response.error,
                    }
                else:
                    openclaw_result = {
                        "ok": True,
                        "request_id": response.request_id,
                        "result": response.result,
                    }

        memory_write = None
        if not settings.read_only_mode:
            memory_write = memory.write_back(
                key=memory_key,
                value={
                    "objective": objective,
                    "departments": selected_departments,
                    "push_to_openclaw": push_to_openclaw,
                    "openclaw_ok": openclaw_result.get("ok")
                    if openclaw_result is not None
                    else None,
                },
            )

        return {
            "ok": True,
            "objective": objective,
            "selected_departments": selected_departments,
            "available_departments": available_departments,
            "prompt": prompt_name,
            "memory_key": memory_key,
            "memory_context_items": len(memory_context),
            "memory_write": memory_write,
            "orchestration_payload": orchestration_payload,
            "openclaw_result": openclaw_result,
            "notes": [
                "Aucun appel OpenClaw n'est fait si push_to_openclaw=false.",
                "La mémoire locale n'est écrite que si READ_ONLY_MODE=false.",
            ],
        }

    @mcp.tool()
    def memory_retrieve(key: str) -> dict[str, Any]:
        return {"key": key, "events": memory.retrieve(key)}

    @mcp.tool()
    def memory_write_back(key: str, value: dict[str, Any]) -> dict[str, Any]:
        if settings.read_only_mode:
            return {"ok": False, "error": "Mode lecture seule actif"}
        return memory.write_back(key, value)

    @mcp.tool()
    async def openclaw_health() -> dict[str, Any]:
        return await gateway_health(ws_client)

    @mcp.tool()
    async def openclaw_invoke(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            response = await ws_client.request(method, params or {})
        except OpenClawError as exc:
            return {"ok": False, "error": str(exc)}

        if response.error is not None:
            return {"ok": False, "request_id": response.request_id, "error": response.error}

        return {"ok": True, "request_id": response.request_id, "result": response.result}

    return mcp
