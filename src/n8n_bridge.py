"""
n8n_bridge.py — OpenClaw ↔ n8n workflow automation bridge

Tools:
  openclaw_n8n_workflow_export   — export an agent pipeline as an n8n-compatible workflow JSON
  openclaw_n8n_workflow_import   — validate & import an n8n workflow JSON into the workspace

Gap T8: Workflow Automation is the #1 trending MCP category (50k+ stars).
Bridges the gap between OpenClaw agent orchestration and n8n's visual workflow engine.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_N8N_SCHEMA_VERSION = "1.0"

# Known n8n node types we can map from OpenClaw concepts
_OPENCLAW_TO_N8N_NODE_MAP: dict[str, str] = {
    "http_request": "n8n-nodes-base.httpRequest",
    "webhook": "n8n-nodes-base.webhook",
    "code": "n8n-nodes-base.code",
    "if": "n8n-nodes-base.if",
    "switch": "n8n-nodes-base.switch",
    "merge": "n8n-nodes-base.merge",
    "set": "n8n-nodes-base.set",
    "function": "n8n-nodes-base.function",
    "cron": "n8n-nodes-base.scheduleTrigger",
    "email": "n8n-nodes-base.emailSend",
    "slack": "n8n-nodes-base.slack",
    "github": "n8n-nodes-base.github",
    "postgres": "n8n-nodes-base.postgres",
    "redis": "n8n-nodes-base.redis",
    "openai": "@n8n/n8n-nodes-langchain.openAi",
    "agent": "@n8n/n8n-nodes-langchain.agent",
    "tool": "@n8n/n8n-nodes-langchain.toolWorkflow",
    "memory": "@n8n/n8n-nodes-langchain.memoryBufferWindow",
    "vector_store": "@n8n/n8n-nodes-langchain.vectorStoreInMemory",
}

# Required fields in a valid n8n workflow
_N8N_REQUIRED_FIELDS = {"name", "nodes", "connections"}

# Max workflow size for safety (10 MB)
_MAX_WORKFLOW_SIZE = 10 * 1024 * 1024


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_n8n_node(
    node_id: str,
    node_type: str,
    name: str,
    parameters: dict[str, Any] | None = None,
    position: tuple[int, int] = (0, 0),
) -> dict[str, Any]:
    """Create a single n8n workflow node."""
    n8n_type = _OPENCLAW_TO_N8N_NODE_MAP.get(node_type, f"n8n-nodes-base.{node_type}")
    return {
        "id": node_id,
        "name": name,
        "type": n8n_type,
        "typeVersion": 1,
        "position": list(position),
        "parameters": parameters or {},
    }


def _validate_n8n_workflow(data: dict[str, Any]) -> list[str]:
    """Validate an n8n workflow JSON structure. Returns list of issues."""
    issues: list[str] = []

    for field in _N8N_REQUIRED_FIELDS:
        if field not in data:
            issues.append(f"Missing required field: '{field}'")

    nodes = data.get("nodes", [])
    if not isinstance(nodes, list):
        issues.append("'nodes' must be a list")
        return issues

    node_ids: set[str] = set()
    node_names: set[str] = set()

    for i, node in enumerate(nodes):
        if not isinstance(node, dict):
            issues.append(f"Node {i}: must be a dict")
            continue

        # Check required node fields
        for req in ("type", "name", "position"):
            if req not in node:
                issues.append(f"Node {i} ({node.get('name', '?')}): missing '{req}'")

        # Check for duplicate IDs
        nid = node.get("id")
        if nid:
            if nid in node_ids:
                issues.append(f"Node {i}: duplicate id '{nid}'")
            node_ids.add(nid)

        # Check for duplicate names
        nname = node.get("name")
        if nname:
            if nname in node_names:
                issues.append(f"Node {i}: duplicate name '{nname}'")
            node_names.add(nname)

        # Validate position
        pos = node.get("position")
        if pos is not None and (not isinstance(pos, (list, tuple)) or len(pos) != 2):
            issues.append(f"Node {i} ({nname}): 'position' must be [x, y]")

    # Validate connections reference existing nodes
    connections = data.get("connections", {})
    if isinstance(connections, dict):
        for source_name, targets in connections.items():
            if source_name not in node_names:
                issues.append(f"Connection source '{source_name}' not found in nodes")

    return issues


def _export_pipeline_to_n8n(
    pipeline_name: str,
    steps: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Convert an OpenClaw-style pipeline definition to n8n workflow JSON.

    Each step should have: name, type, and optionally parameters, depends_on.
    """
    nodes: list[dict[str, Any]] = []
    connections: dict[str, Any] = {}

    # Layout: arrange nodes in a grid, 300px apart
    for i, step in enumerate(steps):
        col = i % 4
        row = i // 4
        x_pos = 250 + col * 300
        y_pos = 300 + row * 200

        node_id = step.get("id", str(uuid.uuid4()))
        node = _make_n8n_node(
            node_id=node_id,
            node_type=step.get("type", "code"),
            name=step.get("name", f"Step {i + 1}"),
            parameters=step.get("parameters"),
            position=(x_pos, y_pos),
        )
        nodes.append(node)

    # Build connections from depends_on
    step_name_map = {s.get("name", f"Step {i + 1}"): i for i, s in enumerate(steps)}

    for i, step in enumerate(steps):
        deps = step.get("depends_on", [])
        if isinstance(deps, str):
            deps = [deps]
        for dep_name in deps:
            if dep_name in step_name_map:
                source_name = dep_name
                target_name = step.get("name", f"Step {i + 1}")
                if source_name not in connections:
                    connections[source_name] = {"main": [[]]}
                connections[source_name]["main"][0].append({
                    "node": target_name,
                    "type": "main",
                    "index": 0,
                })

    workflow = {
        "name": pipeline_name,
        "nodes": nodes,
        "connections": connections,
        "active": False,
        "settings": {
            "executionOrder": "v1",
        },
        "meta": {
            "templateCredsSetupCompleted": False,
            "openclaw_exported": True,
            "openclaw_export_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "schema_version": _N8N_SCHEMA_VERSION,
        },
    }

    return workflow


# ── Tool: openclaw_n8n_workflow_export ────────────────────────────────────────

async def openclaw_n8n_workflow_export(
    pipeline_name: str,
    steps: list[dict[str, Any]],
    output_path: str | None = None,
) -> dict[str, Any]:
    """
    Export an OpenClaw agent pipeline as an n8n-compatible workflow JSON.

    Takes a pipeline definition (list of steps with name, type, parameters,
    and optional depends_on) and converts it to an n8n workflow format that
    can be imported into n8n via its UI or REST API.

    Args:
        pipeline_name: Name for the n8n workflow.
        steps: List of pipeline steps. Each step: {name, type, parameters?, depends_on?}.
        output_path: Optional file path to write the workflow JSON. If None, returns inline.

    Returns:
        dict with keys: ok, workflow (the n8n JSON), output_path (if written), node_count.
    """
    if not steps:
        return {"ok": False, "error": "Pipeline must have at least one step"}

    # Validate steps
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            return {"ok": False, "error": f"Step {i} must be a dict"}
        if "name" not in step:
            return {"ok": False, "error": f"Step {i} missing 'name'"}

    workflow = _export_pipeline_to_n8n(pipeline_name, steps)

    result: dict[str, Any] = {
        "ok": True,
        "node_count": len(workflow["nodes"]),
        "connection_count": sum(
            len(targets.get("main", [[]])[0])
            for targets in workflow["connections"].values()
        ),
    }

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(workflow, indent=2, ensure_ascii=False), encoding="utf-8")
        result["output_path"] = str(out)
        logger.info("Exported n8n workflow '%s' → %s (%d nodes)", pipeline_name, out, len(workflow["nodes"]))
    else:
        result["workflow"] = workflow

    return result


# ── Tool: openclaw_n8n_workflow_import ────────────────────────────────────────

async def openclaw_n8n_workflow_import(
    workflow_path: str,
    target_dir: str | None = None,
    strict: bool = True,
) -> dict[str, Any]:
    """
    Validate and import an n8n workflow JSON file.

    Reads an n8n workflow export, validates its structure (nodes, connections,
    required fields), and optionally copies it to the workspace target directory.

    Args:
        workflow_path: Path to the n8n workflow JSON file.
        target_dir: Optional directory to copy the validated workflow into.
        strict: If True, reject workflows with validation issues. Default: True.

    Returns:
        dict with keys: ok, name, node_count, issues[], imported_path?.
    """
    wf_path = Path(workflow_path)

    if not wf_path.exists():
        return {"ok": False, "error": f"Workflow file not found: {workflow_path}"}

    if not wf_path.suffix.lower() == ".json":
        return {"ok": False, "error": f"Expected .json file, got '{wf_path.suffix}'"}

    # Size check
    size = wf_path.stat().st_size
    if size > _MAX_WORKFLOW_SIZE:
        return {"ok": False, "error": f"Workflow too large: {size:,} bytes (max {_MAX_WORKFLOW_SIZE:,})"}

    try:
        raw = wf_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"Invalid JSON: {e}"}
    except OSError as e:
        return {"ok": False, "error": f"Read error: {e}"}

    if not isinstance(data, dict):
        return {"ok": False, "error": "Workflow root must be a JSON object"}

    issues = _validate_n8n_workflow(data)

    if strict and issues:
        return {
            "ok": False,
            "error": "Workflow validation failed",
            "issues": issues,
        }

    nodes = data.get("nodes", [])
    node_types = set()
    for node in nodes:
        if isinstance(node, dict):
            node_types.add(node.get("type", "unknown"))

    result: dict[str, Any] = {
        "ok": True,
        "name": data.get("name", "unnamed"),
        "node_count": len(nodes),
        "node_types": sorted(node_types),
        "issues": issues,
    }

    # Check for credential references (security flag)
    raw_str = json.dumps(data)
    cred_refs = re.findall(r'"credentials"\s*:\s*\{[^}]+\}', raw_str)
    if cred_refs:
        result["credential_references"] = len(cred_refs)
        result["warnings"] = result.get("warnings", [])
        result["warnings"].append(
            f"Workflow contains {len(cred_refs)} credential reference(s) — "
            "ensure secrets are not hardcoded"
        )

    # Import to target directory
    if target_dir:
        target = Path(target_dir)
        target.mkdir(parents=True, exist_ok=True)
        dest = target / wf_path.name
        dest.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        result["imported_path"] = str(dest)
        logger.info("Imported n8n workflow '%s' → %s", data.get("name"), dest)

    return result


# ── TOOLS registry ───────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_n8n_workflow_export",
        "title": "Export to n8n Workflow",
        "description": (
            "Export an OpenClaw agent pipeline as an n8n-compatible workflow JSON. "
            "Converts pipeline steps (name, type, parameters, depends_on) to n8n format "
            "with proper node layout and connections. Gap T8: workflow automation bridge."
        ),
        "category": "workflow_automation",
        "handler": openclaw_n8n_workflow_export,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "pipeline_name": {
                    "type": "string",
                    "description": "Name for the n8n workflow.",
                },
                "steps": {
                    "type": "array",
                    "description": "List of pipeline steps. Each: {name, type, parameters?, depends_on?}.",
                    "items": {"type": "object"},
                },
                "output_path": {
                    "type": "string",
                    "description": "Optional file path to write the workflow JSON.",
                },
            },
            "required": ["pipeline_name", "steps"],
        },
    },
    {
        "name": "openclaw_n8n_workflow_import",
        "title": "Import n8n Workflow",
        "description": (
            "Validate and import an n8n workflow JSON file. Checks structure (nodes, "
            "connections, required fields), detects credential references, and optionally "
            "copies to workspace. Gap T8: workflow automation bridge."
        ),
        "category": "workflow_automation",
        "handler": openclaw_n8n_workflow_import,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "workflow_path": {
                    "type": "string",
                    "description": "Path to the n8n workflow JSON file.",
                },
                "target_dir": {
                    "type": "string",
                    "description": "Optional directory to copy the validated workflow into.",
                },
                "strict": {
                    "type": "boolean",
                    "description": "Reject workflows with validation issues. Default: true.",
                    "default": True,
                },
            },
            "required": ["workflow_path"],
        },
    },
]
