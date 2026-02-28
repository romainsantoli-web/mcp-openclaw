from __future__ import annotations

import importlib
import time
from typing import Any

from .audit import AuditLogger, AuditSettings
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
from .memory_sqlite import SQLiteMemoryStore
from .openclaw_dispatcher import OpenClawDispatcher
from .model_router import (
    build_agent_copilot_access_plan,
    list_profiles,
    list_subtask_profiles,
    route_task,
)
from .policy_engine import PolicyEngine, PolicyError
from .telemetry import TelemetryCollector
from .openclaw_ws_client import OpenClawError, OpenClawWsClient
from .workflow_runtime import RuntimeSettings, WorkflowRuntime


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
    routing_metadata: dict[str, Any],
    agent_copilot_access: dict[str, Any],
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
        "routing": routing_metadata,
        "agent_copilot_access": agent_copilot_access,
    }


def build_server(settings: Settings) -> Any:
    fastmcp_module = importlib.import_module("mcp.server.fastmcp")
    mcp = fastmcp_module.FastMCP(
        "mcp-openclaw-wrapper",
        host=settings.mcp_host,
        port=settings.mcp_port,
    )
    ws_client = OpenClawWsClient(settings)
    dispatcher = OpenClawDispatcher(settings=settings, ws_client=ws_client)
    policy = PolicyEngine(
        secure_production_mode=settings.secure_production_mode,
        blocked_tools=settings.policy_blocked_tools,
        allow_write_tools=settings.policy_allow_write_tools,
        allow_network_tools=settings.policy_allow_network_tools,
    )
    audit = AuditLogger(
        AuditSettings(
            enabled=settings.audit_enabled,
            file_path=settings.audit_file_path,
        )
    )
    if settings.memory_backend == "sqlite":
        memory: Any = SQLiteMemoryStore(settings.memory_sqlite_path)
    else:
        memory = MemoryAdapter()
    telemetry = TelemetryCollector(enabled=settings.telemetry_enabled)
    workflow_runtime = WorkflowRuntime(
        RuntimeSettings(
            max_attempts=settings.workflow_max_attempts,
            idempotency_enabled=settings.workflow_idempotency_enabled,
            store_path=settings.workflow_store_path,
        )
    )

    def _guard(tool_name: str, category: str) -> dict[str, Any] | None:
        try:
            policy.guard(tool_name, category)
        except PolicyError as exc:
            return {"ok": False, "error": str(exc)}
        return None

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
        blocked = _guard("firm_repo_sync", "network")
        if blocked is not None:
            return blocked
        try:
            result = sync_repo(settings)
            audit.log("firm_repo_sync", {"ok": True, "result": result})
            return result
        except FirmRepoError as exc:
            audit.log("firm_repo_sync", {"ok": False, "error": str(exc)})
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
    def openclaw_dispatch_diagnostics() -> dict[str, Any]:
        return {
            "gateway_url": settings.openclaw_gateway_url,
            "webhook_url": settings.openclaw_webhook_url,
            "dispatch_mode": settings.openclaw_dispatch_mode,
            "allowlist_policy": settings.openclaw_allowlist_policy,
            "allowed_methods": list(settings.openclaw_allowed_methods),
            "read_only_mode": settings.read_only_mode,
            "routing_mode": settings.routing_mode,
            "routing_default_task_family": settings.routing_default_task_family,
            "routing_default_quality_tier": settings.routing_default_quality_tier,
            "routing_default_profile": settings.routing_default_profile,
            "routing_allowed_profiles": list(settings.routing_allowed_profiles),
            "routing_enable_copilot_hints": settings.routing_enable_copilot_hints,
            "routing_enable_agent_copilot_access": settings.routing_enable_agent_copilot_access,
            "secure_production_mode": settings.secure_production_mode,
        }

    @mcp.tool()
    def enterprise_diagnostics() -> dict[str, Any]:
        memory_diag: dict[str, Any]
        if hasattr(memory, "diagnostics"):
            memory_diag = memory.diagnostics()
        else:
            memory_diag = {"backend": "memory", "events_count": "unknown"}
        return {
            "policy": policy.diagnostics(),
            "audit": audit.diagnostics(),
            "memory": memory_diag,
            "telemetry": telemetry.snapshot(),
            "workflow_runtime": workflow_runtime.diagnostics(),
            "secure_production_mode": settings.secure_production_mode,
        }

    @mcp.tool()
    def observability_snapshot() -> dict[str, Any]:
        return {
            "ok": True,
            "telemetry": telemetry.snapshot(),
            "runtime": workflow_runtime.diagnostics(),
        }

    @mcp.tool()
    def ops_recent_runs(limit: int = 20) -> dict[str, Any]:
        return {
            "ok": True,
            "runs": workflow_runtime.list_recent_runs(limit=max(1, limit)),
        }

    @mcp.tool()
    def routing_profiles_list() -> dict[str, Any]:
        return {
            "profiles": list_profiles(),
            "subtask_profiles": list_subtask_profiles(),
            "default_profile": settings.routing_default_profile,
            "allowed_profiles": list(settings.routing_allowed_profiles),
        }

    @mcp.tool()
    def routing_agent_plan(
        departments: list[str],
        quality_tier: str | None = None,
        model_override: str | None = None,
    ) -> dict[str, Any]:
        effective_quality_tier = (
            quality_tier or settings.routing_default_quality_tier
        ).strip().lower()
        return {
            "ok": True,
            "agent_copilot_access": build_agent_copilot_access_plan(
                settings=settings,
                departments=departments,
                quality_tier=effective_quality_tier,
                model_override=model_override,
            ),
        }

    @mcp.tool()
    def routing_preview(
        objective: str,
        task_family: str | None = None,
        quality_tier: str | None = None,
        subtask_type: str | None = None,
        latency_budget_ms: int | None = None,
        model_override: str | None = None,
    ) -> dict[str, Any]:
        decision = route_task(
            settings=settings,
            objective=objective,
            task_family=task_family,
            quality_tier=quality_tier,
            subtask_type=subtask_type,
            latency_budget_ms=latency_budget_ms,
            model_override=model_override,
        )
        return {"ok": True, "routing": decision}

    @mcp.tool()
    def routing_explain(
        objective: str,
        task_family: str | None = None,
        quality_tier: str | None = None,
        subtask_type: str | None = None,
        latency_budget_ms: int | None = None,
        model_override: str | None = None,
    ) -> dict[str, Any]:
        decision = route_task(
            settings=settings,
            objective=objective,
            task_family=task_family,
            quality_tier=quality_tier,
            subtask_type=subtask_type,
            latency_budget_ms=latency_budget_ms,
            model_override=model_override,
        )
        return {
            "ok": True,
            "explanation": {
                "model_profile": decision["model_profile"],
                "task_family": decision["task_family"],
                "quality_tier": decision["quality_tier"],
                "rationale": decision["rationale"],
            },
        }

    async def _execute_delivery_workflow(
        objective: str,
        departments: list[str] | None,
        prompt_name: str,
        memory_key: str,
        push_to_openclaw: bool,
        openclaw_method: str,
        task_family: str | None,
        quality_tier: str | None,
        subtask_type: str | None,
        latency_budget_ms: int | None,
        model_override: str | None,
        idempotency_key: str | None,
        max_attempts: int | None,
    ) -> dict[str, Any]:
        async def _run_once() -> dict[str, Any]:
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
            routing_metadata = route_task(
                settings=settings,
                objective=objective,
                task_family=task_family,
                quality_tier=quality_tier,
                subtask_type=subtask_type,
                latency_budget_ms=latency_budget_ms,
                model_override=model_override,
            )
            effective_quality_tier = (
                quality_tier or settings.routing_default_quality_tier
            ).strip().lower()
            agent_copilot_access = build_agent_copilot_access_plan(
                settings=settings,
                departments=selected_departments,
                quality_tier=effective_quality_tier,
                model_override=model_override,
            )

            effective_method = openclaw_method
            if not effective_method:
                effective_method = routing_metadata.get("default_method", "agent.run")

            orchestration_payload = _build_orchestration_payload(
                objective=objective,
                prompt_content=prompt_data["content"],
                selected_departments=selected_departments,
                department_agents=department_agents,
                memory_context=memory_context,
                routing_metadata=routing_metadata,
                agent_copilot_access=agent_copilot_access,
            )

            openclaw_result: dict[str, Any] | None = None
            if push_to_openclaw:
                blocked = _guard("firm_run_delivery_workflow.dispatch", "network")
                if blocked is not None:
                    return blocked
                dispatch = await dispatcher.dispatch(
                    method=effective_method,
                    payload=orchestration_payload,
                )
                openclaw_result = {
                    "ok": dispatch.ok,
                    "channel": dispatch.channel,
                    "request_id": dispatch.request_id,
                    "result": dispatch.result,
                    "error": dispatch.error,
                    "attempts": dispatch.attempts,
                }
                audit.log(
                    "openclaw_dispatch",
                    {
                        "objective": objective,
                        "method": effective_method,
                        "ok": openclaw_result.get("ok"),
                        "channel": openclaw_result.get("channel"),
                        "request_id": openclaw_result.get("request_id"),
                    },
                )

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
                        "model_profile": routing_metadata.get("model_profile"),
                        "task_family": routing_metadata.get("task_family"),
                        "subtask_type": routing_metadata.get("subtask_type"),
                        "agent_copilot_access_count": len(agent_copilot_access),
                    },
                )

            audit.log(
                "firm_run_delivery_workflow",
                {
                    "objective": objective,
                    "departments": selected_departments,
                    "push_to_openclaw": push_to_openclaw,
                    "task_family": routing_metadata.get("task_family"),
                    "model_profile": routing_metadata.get("model_profile"),
                    "ok": True,
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
                "routing": routing_metadata,
                "agent_copilot_access": agent_copilot_access,
                "effective_openclaw_method": effective_method,
                "orchestration_payload": orchestration_payload,
                "openclaw_result": openclaw_result,
                "notes": [
                    "Aucun appel OpenClaw n'est fait si push_to_openclaw=false.",
                    "La mémoire locale n'est écrite que si READ_ONLY_MODE=false.",
                ],
            }

        start = time.monotonic()
        run_envelope = await workflow_runtime.execute(
            workflow_name="firm_delivery_workflow",
            run_callable=_run_once,
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
            metadata={
                "objective": objective,
                "push_to_openclaw": push_to_openclaw,
                "task_family": task_family,
                "subtask_type": subtask_type,
            },
        )
        duration_ms = (time.monotonic() - start) * 1000
        telemetry.inc("workflow.total")
        if run_envelope.get("ok"):
            telemetry.inc("workflow.success")
        else:
            telemetry.inc("workflow.failure")
        telemetry.observe_ms("workflow.duration_ms", duration_ms)

        final_result = run_envelope.get("result", {})
        if isinstance(final_result, dict):
            final_result["runtime"] = {
                "run_id": run_envelope.get("run_id"),
                "attempts_count": run_envelope.get("attempts_count"),
                "max_attempts": run_envelope.get("max_attempts"),
                "duration_ms": run_envelope.get("duration_ms"),
                "idempotent_replay": run_envelope.get("idempotent_replay", False),
                "attempts": run_envelope.get("attempts", []),
            }
            return final_result

        return {
            "ok": False,
            "error": "workflow_runtime_result_invalid",
            "runtime": run_envelope,
        }

    @mcp.tool()
    async def firm_run_delivery_workflow(
        objective: str,
        departments: list[str] | None = None,
        prompt_name: str = "firm-delivery.prompt.md",
        memory_key: str = "delivery/latest",
        push_to_openclaw: bool = False,
        openclaw_method: str = "agent.run",
        task_family: str | None = None,
        quality_tier: str | None = None,
        subtask_type: str | None = None,
        latency_budget_ms: int | None = None,
        model_override: str | None = None,
        idempotency_key: str | None = None,
        max_attempts: int | None = None,
    ) -> dict[str, Any]:
        return await _execute_delivery_workflow(
            objective=objective,
            departments=departments,
            prompt_name=prompt_name,
            memory_key=memory_key,
            push_to_openclaw=push_to_openclaw,
            openclaw_method=openclaw_method,
            task_family=task_family,
            quality_tier=quality_tier,
            subtask_type=subtask_type,
            latency_budget_ms=latency_budget_ms,
            model_override=model_override,
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
        )

    @mcp.tool()
    async def firm_run_delivery_and_dispatch(
        objective: str,
        departments: list[str] | None = None,
        prompt_name: str = "firm-delivery.prompt.md",
        memory_key: str = "delivery/latest",
        openclaw_method: str = "agent.run",
        require_openclaw_success: bool = False,
        task_family: str | None = None,
        quality_tier: str | None = None,
        subtask_type: str | None = None,
        latency_budget_ms: int | None = None,
        model_override: str | None = None,
        idempotency_key: str | None = None,
        max_attempts: int | None = None,
    ) -> dict[str, Any]:
        result = await _execute_delivery_workflow(
            objective=objective,
            departments=departments,
            prompt_name=prompt_name,
            memory_key=memory_key,
            push_to_openclaw=True,
            openclaw_method=openclaw_method,
            task_family=task_family,
            quality_tier=quality_tier,
            subtask_type=subtask_type,
            latency_budget_ms=latency_budget_ms,
            model_override=model_override,
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
        )

        if not result.get("ok"):
            return result

        openclaw_result = result.get("openclaw_result") or {
            "ok": False,
            "error": "Aucune réponse OpenClaw",
        }
        dispatch_ok = bool(openclaw_result.get("ok"))
        if require_openclaw_success and not dispatch_ok:
            return {
                "ok": False,
                "error": "Dispatch OpenClaw échoué",
                "objective": objective,
                "openclaw_result": openclaw_result,
            }

        return {
            "ok": True,
            "objective": objective,
            "dispatch_ok": dispatch_ok,
            "departments_count": len(result.get("selected_departments", [])),
            "memory_key": memory_key,
            "openclaw_request_id": openclaw_result.get("request_id"),
            "openclaw_error": openclaw_result.get("error"),
            "openclaw_result": openclaw_result.get("result"),
            "openclaw_attempts": openclaw_result.get("attempts", []),
            "summary": {
                "selected_departments": result.get("selected_departments", []),
                "prompt": result.get("prompt"),
                "memory_context_items": result.get("memory_context_items", 0),
                "model_profile": (result.get("routing") or {}).get("model_profile"),
                "task_family": (result.get("routing") or {}).get("task_family"),
                "subtask_type": (result.get("routing") or {}).get("subtask_type"),
                "agent_copilot_access_count": len(result.get("agent_copilot_access") or {}),
            },
        }

    @mcp.tool()
    def memory_retrieve(key: str) -> dict[str, Any]:
        return {"key": key, "events": memory.retrieve(key)}

    @mcp.tool()
    def memory_write_back(key: str, value: dict[str, Any]) -> dict[str, Any]:
        blocked = _guard("memory_write_back", "write")
        if blocked is not None:
            return blocked
        if settings.read_only_mode:
            return {"ok": False, "error": "Mode lecture seule actif"}
        result = memory.write_back(key, value)
        audit.log("memory_write_back", {"key": key, "ok": True})
        return result

    @mcp.tool()
    async def openclaw_health() -> dict[str, Any]:
        blocked = _guard("openclaw_health", "network")
        if blocked is not None:
            return blocked
        return await gateway_health(ws_client)

    @mcp.tool()
    async def openclaw_invoke(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        blocked = _guard("openclaw_invoke", "network")
        if blocked is not None:
            return blocked
        invoke_start = time.monotonic()
        try:
            response = await ws_client.request(method, params or {})
        except OpenClawError as exc:
            telemetry.inc("openclaw_invoke.failure")
            telemetry.observe_ms("openclaw_invoke.duration_ms", (time.monotonic() - invoke_start) * 1000)
            audit.log("openclaw_invoke", {"method": method, "ok": False, "error": str(exc)})
            return {"ok": False, "error": str(exc)}

        if response.error is not None:
            audit.log(
                "openclaw_invoke",
                {
                    "method": method,
                    "ok": False,
                    "request_id": response.request_id,
                    "error": response.error,
                },
            )
            telemetry.inc("openclaw_invoke.failure")
            telemetry.observe_ms("openclaw_invoke.duration_ms", (time.monotonic() - invoke_start) * 1000)
            return {"ok": False, "request_id": response.request_id, "error": response.error}

        audit.log(
            "openclaw_invoke",
            {
                "method": method,
                "ok": True,
                "request_id": response.request_id,
            },
        )
        telemetry.inc("openclaw_invoke.success")
        telemetry.observe_ms("openclaw_invoke.duration_ms", (time.monotonic() - invoke_start) * 1000)
        return {"ok": True, "request_id": response.request_id, "result": response.result}

    return mcp
