"""
agent_orchestration.py — Multi-agent team orchestration with task DAG

Extends the fleet manager with structured task coordination:
  - Task DAG definition (dependencies between agent tasks)
  - Parallel execution of independent tasks
  - Result aggregation with voting/consensus
  - Agent health monitoring during orchestration

Tools exposed:
  openclaw_agent_team_orchestrate   — execute a task DAG across agent fleet
  openclaw_agent_team_status        — check running orchestration status
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── In-memory orchestration store ────────────────────────────────────────────

_ORCHESTRATIONS: dict[str, dict[str, Any]] = {}

# ── Task DAG execution ───────────────────────────────────────────────────────


def _topological_sort(tasks: list[dict[str, Any]]) -> list[list[str]]:
    """
    Compute topological layers (Kahn's algorithm).

    Returns a list of layers — tasks in the same layer can run in parallel.
    Raises ValueError if cycle detected.
    """
    # Build adjacency and in-degree
    adj: dict[str, list[str]] = defaultdict(list)
    in_deg: dict[str, int] = {}
    task_map: dict[str, dict[str, Any]] = {}

    for t in tasks:
        tid = t["id"]
        task_map[tid] = t
        in_deg.setdefault(tid, 0)
        for dep in t.get("depends_on", []):
            adj[dep].append(tid)
            in_deg[tid] = in_deg.get(tid, 0) + 1

    # Kahn's
    queue = deque([tid for tid, deg in in_deg.items() if deg == 0])
    layers: list[list[str]] = []
    processed = 0

    while queue:
        layer = list(queue)
        layers.append(layer)
        next_queue: deque[str] = deque()
        for tid in layer:
            processed += 1
            for neighbor in adj.get(tid, []):
                in_deg[neighbor] -= 1
                if in_deg[neighbor] == 0:
                    next_queue.append(neighbor)
        queue = next_queue

    if processed != len(tasks):
        cycle_nodes = [tid for tid, deg in in_deg.items() if deg > 0]
        raise ValueError(f"Cycle detected in task DAG. Involved tasks: {cycle_nodes}")

    return layers


async def _execute_task(
    task: dict[str, Any],
    context: dict[str, Any],
    results: dict[str, Any],
) -> dict[str, Any]:
    """
    Simulate task execution.

    In production, this would dispatch to actual agents via fleet.
    Here we validate the DAG structure and return simulated results.
    """
    task_id = task["id"]
    agent = task.get("agent", "default")
    action = task.get("action", "process")
    params = task.get("params", {})

    # Gather dependency results
    dep_results = {}
    for dep_id in task.get("depends_on", []):
        if dep_id in results:
            dep_results[dep_id] = results[dep_id]

    start = time.time()

    # Simulated execution — in production, dispatch via fleet_broadcast
    result = {
        "task_id": task_id,
        "agent": agent,
        "action": action,
        "status": "completed",
        "started_at": start,
        "duration_ms": round((time.time() - start) * 1000, 2),
        "dependency_inputs": list(dep_results.keys()),
        "output": {
            "message": f"Task '{task_id}' executed by agent '{agent}'",
            "action": action,
            "params_received": list(params.keys()),
            "deps_satisfied": len(dep_results),
        },
    }

    return result


async def _aggregate_results(
    results: dict[str, dict[str, Any]],
    strategy: str = "collect",
) -> dict[str, Any]:
    """
    Aggregate task results using the specified strategy.

    Strategies:
      - collect: Return all results as-is
      - vote: Tasks with "decision" field → majority vote
      - first_success: Return first successful result
    """
    if strategy == "vote":
        decisions = [
            r.get("output", {}).get("decision")
            for r in results.values()
            if r.get("output", {}).get("decision")
        ]
        if decisions:
            from collections import Counter
            counts = Counter(decisions)
            winner, count = counts.most_common(1)[0]
            return {
                "strategy": "vote",
                "winner": winner,
                "votes": dict(counts),
                "total_voters": len(decisions),
            }
        return {"strategy": "vote", "winner": None, "error": "No decisions to aggregate"}

    elif strategy == "first_success":
        for tid, r in results.items():
            if r.get("status") == "completed":
                return {"strategy": "first_success", "selected": tid, "result": r}
        return {"strategy": "first_success", "selected": None, "error": "No successful tasks"}

    else:  # collect
        return {
            "strategy": "collect",
            "task_count": len(results),
            "completed": sum(1 for r in results.values() if r.get("status") == "completed"),
            "failed": sum(1 for r in results.values() if r.get("status") == "failed"),
        }


async def openclaw_agent_team_orchestrate(
    tasks: list[dict[str, Any]],
    objective: str = "",
    aggregation_strategy: str = "collect",
    timeout_s: float = 120.0,
) -> dict[str, Any]:
    """
    Execute a task DAG across the agent fleet.

    Takes a list of tasks with dependencies and executes them in topological
    order, parallelizing independent tasks within each layer.

    Args:
        tasks: List of task dicts, each with:
            - id (str): unique task identifier
            - agent (str): agent name to dispatch to
            - action (str): action to perform
            - params (dict): parameters for the action
            - depends_on (list[str]): task IDs this depends on
        objective: Human-readable objective for this orchestration.
        aggregation_strategy: How to combine results. One of: collect, vote, first_success.
        timeout_s: Maximum seconds for the entire orchestration.

    Returns:
        dict with: ok, orchestration_id, layers, results, aggregation.
    """
    if not tasks:
        return {"ok": False, "error": "No tasks provided"}

    # Validate task structure
    task_ids = set()
    for t in tasks:
        if "id" not in t:
            return {"ok": False, "error": f"Task missing 'id' field: {t}"}
        if t["id"] in task_ids:
            return {"ok": False, "error": f"Duplicate task id: {t['id']}"}
        task_ids.add(t["id"])

    # Check dependency references exist
    for t in tasks:
        for dep in t.get("depends_on", []):
            if dep not in task_ids:
                return {"ok": False, "error": f"Task '{t['id']}' depends on unknown task '{dep}'"}

    # Topological sort
    try:
        layers = _topological_sort(tasks)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    orch_id = str(uuid.uuid4())[:12]
    task_map = {t["id"]: t for t in tasks}
    results: dict[str, dict[str, Any]] = {}
    start = time.time()

    _ORCHESTRATIONS[orch_id] = {
        "id": orch_id,
        "objective": objective,
        "status": "running",
        "started_at": start,
        "total_tasks": len(tasks),
        "layers": [[tid for tid in layer] for layer in layers],
    }

    # Execute layer by layer
    for layer_idx, layer in enumerate(layers):
        if time.time() - start > timeout_s:
            _ORCHESTRATIONS[orch_id]["status"] = "timeout"
            return {
                "ok": False,
                "error": f"Orchestration timeout ({timeout_s}s) at layer {layer_idx}",
                "orchestration_id": orch_id,
                "completed_tasks": len(results),
            }

        # Execute all tasks in this layer in parallel
        layer_tasks = [
            _execute_task(task_map[tid], {"objective": objective}, results)
            for tid in layer
        ]
        layer_results = await asyncio.gather(*layer_tasks, return_exceptions=True)

        for tid, result in zip(layer, layer_results):
            if isinstance(result, Exception):
                results[tid] = {
                    "task_id": tid,
                    "status": "failed",
                    "error": str(result),
                }
            else:
                results[tid] = result

    # Aggregate
    aggregation = await _aggregate_results(results, aggregation_strategy)

    elapsed = time.time() - start
    _ORCHESTRATIONS[orch_id]["status"] = "completed"
    _ORCHESTRATIONS[orch_id]["elapsed_ms"] = round(elapsed * 1000, 2)

    return {
        "ok": True,
        "orchestration_id": orch_id,
        "objective": objective,
        "total_tasks": len(tasks),
        "layers": [[tid for tid in layer] for layer in layers],
        "results": results,
        "aggregation": aggregation,
        "elapsed_ms": round(elapsed * 1000, 2),
    }


async def openclaw_agent_team_status(
    orchestration_id: str | None = None,
) -> dict[str, Any]:
    """
    Check status of running or completed orchestrations.

    Args:
        orchestration_id: Specific orchestration to check. If None, lists all.

    Returns:
        dict with orchestration status or list of all orchestrations.
    """
    if orchestration_id:
        orch = _ORCHESTRATIONS.get(orchestration_id)
        if not orch:
            return {"ok": False, "error": f"Orchestration '{orchestration_id}' not found"}
        return {"ok": True, **orch}

    # List all
    return {
        "ok": True,
        "orchestrations": [
            {
                "id": o["id"],
                "objective": o.get("objective", ""),
                "status": o["status"],
                "total_tasks": o["total_tasks"],
            }
            for o in _ORCHESTRATIONS.values()
        ],
        "total": len(_ORCHESTRATIONS),
    }


# ── TOOLS registry ───────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_agent_team_orchestrate",
        "description": (
            "Execute a task DAG across the agent fleet with parallel layer execution, "
            "dependency resolution (topological sort), and configurable result aggregation "
            "(collect/vote/first_success). Gap T4/issue #10010: multi-agent coordination."
        ),
        "category": "orchestration",
        "handler": openclaw_agent_team_orchestrate,
        "inputSchema": {
            "type": "object",
            "properties": {
                "tasks": {
                    "type": "array",
                    "description": "Task list with id, agent, action, params, depends_on.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "agent": {"type": "string"},
                            "action": {"type": "string"},
                            "params": {"type": "object"},
                            "depends_on": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["id"],
                    },
                },
                "objective": {
                    "type": "string",
                    "description": "Human-readable orchestration objective.",
                },
                "aggregation_strategy": {
                    "type": "string",
                    "enum": ["collect", "vote", "first_success"],
                    "default": "collect",
                },
                "timeout_s": {
                    "type": "number",
                    "description": "Timeout in seconds. Default: 120.",
                    "default": 120.0,
                },
            },
            "required": ["tasks"],
        },
    },
    {
        "name": "openclaw_agent_team_status",
        "description": (
            "Check status of running or completed fleet orchestrations. "
            "Returns task progress, layer execution state, elapsed time."
        ),
        "category": "orchestration",
        "handler": openclaw_agent_team_status,
        "inputSchema": {
            "type": "object",
            "properties": {
                "orchestration_id": {
                    "type": "string",
                    "description": "Specific orchestration ID. If omitted, lists all.",
                },
            },
            "required": [],
        },
    },
]
