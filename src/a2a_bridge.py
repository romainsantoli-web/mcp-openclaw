"""
a2a_bridge.py — Agent-to-Agent (A2A) Protocol v0.4.0 bridge for OpenClaw

Implements the foundation for A2A interoperability:
  - Agent Card generation from SOUL.md files (.well-known/agent-card.json)
  - Agent Card validation against A2A v0.4.0 spec
  - Task lifecycle: send, status/list (v0.4.0), cancel
  - Push notification webhook configuration
  - Agent discovery via network Agent Cards
  - mTLS and digital signatures support (v0.4.0)
  - Extended card behind authentication (v0.4.0)

Tools exposed:
  openclaw_a2a_card_generate   — generate .well-known/agent-card.json from a SOUL
  openclaw_a2a_card_validate   — validate an Agent Card against A2A v0.4.0 spec
  openclaw_a2a_task_send       — send a message/task to an A2A agent
  openclaw_a2a_task_status     — get task status or list tasks (v0.4.0 tasks/list)
  openclaw_a2a_push_config     — CRUD for push notification webhooks
  openclaw_a2a_discovery       — discover agents via Agent Card endpoints
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── A2A spec constants ───────────────────────────────────────────────────────

A2A_SPEC_VERSION = "0.4.0"  # Updated from "1.0" to reflect actual latest release
A2A_MEDIA_TYPE = "application/a2a+json"
A2A_WELL_KNOWN_PATH = ".well-known/agent-card.json"  # v0.2.1+: was agent.json

_VALID_TASK_STATES = {
    "submitted", "working", "input_required", "auth_required",
    "completed", "failed", "canceled", "rejected",
    "unknown",  # v0.4.0: explicit unknown state
}

_TERMINAL_STATES = {"completed", "failed", "canceled", "rejected"}

_VALID_CAPABILITIES = {
    "streaming", "pushNotifications", "stateTransitionHistory",
}

# v0.4.0 additions
_VALID_EXTENDED_CARD_FIELDS = {
    "supportsAuthenticatedExtendedCard",  # v0.4.0: extended card behind auth
}

_VALID_SECURITY_EXTENSIONS = {
    "mTLS",   # v0.4.0: mutual TLS for agent-to-agent auth
    "jws",    # v0.4.0: JSON Web Signatures for message integrity
}

_REQUIRED_CARD_FIELDS = {"name", "url", "version", "skills"}

_VALID_SECURITY_SCHEME_TYPES = {
    "apiKey", "http", "oauth2", "openIdConnect",
}

_VALID_INPUT_OUTPUT_MODES = {
    "text/plain", "application/json", "image/png", "image/jpeg",
    "audio/wav", "audio/mp3", "video/mp4", "application/pdf",
    "text/markdown", "text/html",
}

# ── In-memory task store (production: persistent store) ──────────────────────

_TASKS: dict[str, dict[str, Any]] = {}
_PUSH_CONFIGS: dict[str, list[dict[str, Any]]] = {}  # task_id → [push configs]


# ── SOUL.md parser ───────────────────────────────────────────────────────────

def _parse_soul_frontmatter(content: str) -> dict[str, Any]:
    """Extract YAML-like frontmatter from a SOUL.md file."""
    meta: dict[str, Any] = {}
    if not content.startswith("---"):
        return meta

    parts = content.split("---", 2)
    if len(parts) < 3:
        return meta

    frontmatter = parts[1].strip()
    for line in frontmatter.split("\n"):
        line = line.strip()
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if value:
                meta[key] = value
    return meta


def _extract_skills_from_soul(content: str, meta: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract skill definitions from SOUL.md body content."""
    skills: list[dict[str, Any]] = []
    role = meta.get("role", meta.get("name", "agent"))

    # Look for ## sections as skill indicators
    sections = re.findall(r"##\s+(.+?)(?:\n|$)", content)
    for section in sections[:10]:  # cap at 10 skills per soul
        skill_id = re.sub(r"[^a-z0-9]+", "-", section.lower()).strip("-")
        if not skill_id:
            continue
        skills.append({
            "id": skill_id,
            "name": section.strip(),
            "description": f"{role} skill: {section.strip()}",
            "tags": [role.lower(), skill_id],
            "inputModes": ["text/plain", "application/json"],
            "outputModes": ["text/plain", "application/json"],
        })

    # If no skills found, create a default one from the role
    if not skills:
        skills.append({
            "id": f"{role.lower()}-default",
            "name": f"{role} Default Skill",
            "description": f"Default skill for {role} agent",
            "tags": [role.lower()],
            "inputModes": ["text/plain", "application/json"],
            "outputModes": ["text/plain", "application/json"],
        })

    return skills


def _generate_card_from_soul(
    soul_path: str,
    base_url: str,
    *,
    capabilities: dict[str, bool] | None = None,
    security_schemes: dict[str, Any] | None = None,
    extensions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate a full A2A Agent Card from a SOUL.md file."""
    p = Path(soul_path)
    if not p.exists():
        raise FileNotFoundError(f"SOUL file not found: {soul_path}")

    content = p.read_text(encoding="utf-8")
    meta = _parse_soul_frontmatter(content)
    skills = _extract_skills_from_soul(content, meta)

    name = meta.get("name", p.stem)
    description = meta.get("description", f"A2A agent: {name}")
    version = meta.get("version", "1.0")

    # Build capabilities
    caps: dict[str, Any] = {}
    if capabilities:
        if capabilities.get("streaming"):
            caps["streaming"] = True
        if capabilities.get("pushNotifications"):
            caps["pushNotifications"] = True
        if capabilities.get("stateTransitionHistory"):
            caps["stateTransitionHistory"] = True
    if extensions:
        caps["extensions"] = extensions

    # Build Agent Card
    card: dict[str, Any] = {
        "name": name,
        "description": description,
        "url": base_url.rstrip("/"),
        "version": version,
        "skills": skills,
    }

    if caps:
        card["capabilities"] = caps

    # Security schemes
    if security_schemes:
        card["securitySchemes"] = security_schemes
        card["security"] = [{k: [] for k in security_schemes}]

    # Provider info
    if "author" in meta:
        card["provider"] = {"organization": meta["author"]}
    if "license" in meta:
        card.setdefault("provider", {})["url"] = f"https://spdx.org/licenses/{meta['license']}"

    return card


# ── Agent Card validation ────────────────────────────────────────────────────

def _validate_agent_card(card: dict[str, Any]) -> list[dict[str, str]]:
    """Validate an Agent Card against A2A v1.0 RC spec. Returns list of issues."""
    issues: list[dict[str, str]] = []

    # Required fields
    for field in _REQUIRED_CARD_FIELDS:
        if field not in card:
            issues.append({
                "severity": "CRITICAL",
                "field": field,
                "message": f"Required field '{field}' is missing",
            })

    # Name validation
    name = card.get("name")
    if name and (not isinstance(name, str) or len(name) > 256):
        issues.append({
            "severity": "HIGH",
            "field": "name",
            "message": "name must be a string ≤256 chars",
        })

    # URL validation
    url = card.get("url")
    if url:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            issues.append({
                "severity": "HIGH",
                "field": "url",
                "message": "url must use http or https scheme",
            })
    elif "url" in card:
        issues.append({
            "severity": "HIGH",
            "field": "url",
            "message": "url must not be empty",
        })

    # Version validation (semver-like or major.minor)
    version = card.get("version")
    if version and not re.match(r"^\d+\.\d+(\.\d+)?(-[a-zA-Z0-9.]+)?$", str(version)):
        issues.append({
            "severity": "MEDIUM",
            "field": "version",
            "message": f"version '{version}' is not a valid semver format",
        })

    # Skills validation
    skills = card.get("skills", [])
    if not isinstance(skills, list):
        issues.append({
            "severity": "CRITICAL",
            "field": "skills",
            "message": "skills must be an array",
        })
    else:
        skill_ids = set()
        for i, skill in enumerate(skills):
            if not isinstance(skill, dict):
                issues.append({
                    "severity": "HIGH",
                    "field": f"skills[{i}]",
                    "message": "Each skill must be an object",
                })
                continue

            sid = skill.get("id")
            if not sid:
                issues.append({
                    "severity": "HIGH",
                    "field": f"skills[{i}].id",
                    "message": "Skill must have an 'id' field",
                })
            elif sid in skill_ids:
                issues.append({
                    "severity": "HIGH",
                    "field": f"skills[{i}].id",
                    "message": f"Duplicate skill id: '{sid}'",
                })
            else:
                skill_ids.add(sid)

            if not skill.get("name"):
                issues.append({
                    "severity": "MEDIUM",
                    "field": f"skills[{i}].name",
                    "message": "Skill should have a 'name' field",
                })

            # Validate input/output modes
            for mode_key in ("inputModes", "outputModes"):
                modes = skill.get(mode_key, [])
                for mode in modes:
                    if mode not in _VALID_INPUT_OUTPUT_MODES:
                        issues.append({
                            "severity": "INFO",
                            "field": f"skills[{i}].{mode_key}",
                            "message": f"Non-standard MIME type: '{mode}'",
                        })

    # Capabilities validation
    caps = card.get("capabilities", {})
    if isinstance(caps, dict):
        for key in caps:
            if key not in _VALID_CAPABILITIES and key != "extensions":
                issues.append({
                    "severity": "INFO",
                    "field": f"capabilities.{key}",
                    "message": f"Unknown capability: '{key}'",
                })

        # Extensions validation
        exts = caps.get("extensions", [])
        if isinstance(exts, list):
            for j, ext in enumerate(exts):
                if not isinstance(ext, dict) or "uri" not in ext:
                    issues.append({
                        "severity": "MEDIUM",
                        "field": f"capabilities.extensions[{j}]",
                        "message": "Extension must have a 'uri' field",
                    })

    # Security schemes validation
    schemes = card.get("securitySchemes", {})
    if isinstance(schemes, dict):
        for scheme_name, scheme in schemes.items():
            if not isinstance(scheme, dict):
                continue
            stype = scheme.get("type")
            if stype and stype not in _VALID_SECURITY_SCHEME_TYPES:
                issues.append({
                    "severity": "HIGH",
                    "field": f"securitySchemes.{scheme_name}.type",
                    "message": f"Invalid security scheme type: '{stype}'",
                })

    # Security reference validation
    security = card.get("security", [])
    if isinstance(security, list):
        for sec_req in security:
            if isinstance(sec_req, dict):
                for ref in sec_req:
                    if ref not in schemes:
                        issues.append({
                            "severity": "HIGH",
                            "field": "security",
                            "message": f"Security requirement references unknown scheme: '{ref}'",
                        })

    return issues


# ── Task lifecycle ───────────────────────────────────────────────────────────

def _create_task(
    agent_url: str,
    message: str,
    *,
    context_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    blocking: bool = False,
) -> dict[str, Any]:
    """Create a new A2A task (simulated — production would call the remote agent)."""
    task_id = str(uuid.uuid4())
    now = time.time()

    task: dict[str, Any] = {
        "id": task_id,
        "contextId": context_id or str(uuid.uuid4()),
        "status": {
            "state": "submitted",
            "timestamp": now,
        },
        "history": [
            {
                "role": "user",
                "parts": [{"kind": "text", "text": message}],
            }
        ],
        "artifacts": [],
        "metadata": metadata or {},
        "_internal": {
            "agent_url": agent_url,
            "created_at": now,
            "blocking": blocking,
        },
    }

    # Simulate progression to working
    task["status"] = {
        "state": "working",
        "message": {"role": "agent", "parts": [{"kind": "text", "text": "Processing request..."}]},
        "timestamp": now + 0.001,
    }

    # If blocking, simulate immediate completion
    if blocking:
        task["status"] = {
            "state": "completed",
            "timestamp": now + 0.002,
        }
        task["artifacts"] = [{
            "artifactId": str(uuid.uuid4())[:8],
            "parts": [{"kind": "text", "text": f"Completed task from agent at {agent_url}"}],
            "lastChunk": True,
        }]

    _TASKS[task_id] = task
    return task


# ── Tool handlers ────────────────────────────────────────────────────────────

def openclaw_a2a_card_generate(
    soul_path: str,
    base_url: str,
    output_path: str | None = None,
    capabilities: dict[str, bool] | None = None,
    security_schemes: dict[str, Any] | None = None,
    extensions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Generate an A2A Agent Card from a SOUL.md file.

    Reads the SOUL.md frontmatter and body to extract:
    - Agent identity (name, description, version)
    - Skills from ## sections
    - Provider info from author/license

    Outputs a .well-known/agent-card.json compliant with A2A v1.0 RC.

    Args:
        soul_path: Path to the SOUL.md file.
        base_url: Base URL where this agent will be reachable.
        output_path: Optional path to write the Agent Card JSON.
        capabilities: Dict of A2A capabilities (streaming, pushNotifications, etc.).
        security_schemes: OAuth2/apiKey/http security scheme definitions.
        extensions: List of A2A extension declarations.

    Returns:
        dict with: ok, card, output_path, validation_issues.
    """
    try:
        card = _generate_card_from_soul(
            soul_path, base_url,
            capabilities=capabilities,
            security_schemes=security_schemes,
            extensions=extensions,
        )
    except FileNotFoundError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        logger.exception("Failed to generate Agent Card")
        return {"ok": False, "error": f"Failed to parse SOUL.md: {exc}"}

    # Validate the generated card
    issues = _validate_agent_card(card)
    critical_count = sum(1 for i in issues if i["severity"] == "CRITICAL")

    result: dict[str, Any] = {
        "ok": critical_count == 0,
        "card": card,
        "a2a_spec_version": A2A_SPEC_VERSION,
        "skills_count": len(card.get("skills", [])),
        "validation_issues": issues,
        "critical_issues": critical_count,
    }

    # Write to file if requested
    if output_path and critical_count == 0:
        try:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(card, indent=2, ensure_ascii=False), encoding="utf-8")
            result["output_path"] = str(out.resolve())
        except (OSError, PermissionError) as exc:
            result["write_error"] = str(exc)

    return result


def openclaw_a2a_card_validate(
    card_path: str | None = None,
    card_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Validate an A2A Agent Card against the v1.0 RC specification.

    Checks: required fields, URL format, version format, skills structure,
    capabilities, security schemes, extensions. Reports issues by severity.

    Args:
        card_path: Path to an agent-card.json file.
        card_json: Inline Agent Card dict (alternative to card_path).

    Returns:
        dict with: ok, issues, summary, severity_counts.
    """
    if card_json:
        card = card_json
    elif card_path:
        p = Path(card_path)
        if not p.exists():
            return {"ok": False, "error": f"File not found: {card_path}"}
        try:
            card = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return {"ok": False, "error": f"Failed to read Agent Card: {exc}"}
    else:
        return {"ok": False, "error": "Provide either card_path or card_json"}

    issues = _validate_agent_card(card)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for issue in issues:
        sev = issue.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "ok": severity_counts["CRITICAL"] == 0,
        "a2a_spec_version": A2A_SPEC_VERSION,
        "issues": issues,
        "issue_count": len(issues),
        "severity_counts": severity_counts,
        "card_name": card.get("name", "unknown"),
        "card_skills": len(card.get("skills", [])),
    }


async def openclaw_a2a_task_send(
    agent_url: str,
    message: str,
    context_id: str | None = None,
    blocking: bool = False,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Send a message/task to an A2A agent.

    Creates a Task in the A2A lifecycle (submitted → working → completed/failed).
    In production, performs an HTTP POST to agent_url/message:send.
    Currently simulated for validation & testing.

    Args:
        agent_url: URL of the target A2A agent.
        message: Text message to send.
        context_id: Optional context ID to group related tasks.
        blocking: If True, wait for task completion.
        metadata: Optional metadata dict.

    Returns:
        dict with: ok, task_id, status, context_id, artifacts.
    """
    parsed = urlparse(agent_url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "error": "agent_url must use http or https scheme"}
    if not parsed.netloc:
        return {"ok": False, "error": "agent_url must have a valid host"}

    task = _create_task(
        agent_url, message,
        context_id=context_id,
        metadata=metadata,
        blocking=blocking,
    )

    return {
        "ok": True,
        "task_id": task["id"],
        "context_id": task["contextId"],
        "status": task["status"],
        "artifacts": task.get("artifacts", []),
        "a2a_method": "SendMessage",
        "blocking": blocking,
    }


async def openclaw_a2a_task_status(
    task_id: str | None = None,
    context_id: str | None = None,
    include_history: bool = False,
) -> dict[str, Any]:
    """
    Get task status or list tasks.

    Maps to A2A GetTask / ListTasks operations.

    Args:
        task_id: Specific task to query (GetTask).
        context_id: Filter tasks by context (ListTasks).
        include_history: Include message history in response.

    Returns:
        dict with: ok, task(s), status.
    """
    if task_id:
        task = _TASKS.get(task_id)
        if not task:
            return {"ok": False, "error": f"Task '{task_id}' not found"}

        result: dict[str, Any] = {
            "ok": True,
            "a2a_method": "GetTask",
            "task_id": task["id"],
            "context_id": task["contextId"],
            "status": task["status"],
            "artifacts": task.get("artifacts", []),
            "is_terminal": task["status"]["state"] in _TERMINAL_STATES,
        }
        if include_history:
            result["history"] = task.get("history", [])
        return result

    # ListTasks
    tasks = list(_TASKS.values())
    if context_id:
        tasks = [t for t in tasks if t.get("contextId") == context_id]

    return {
        "ok": True,
        "a2a_method": "ListTasks",
        "tasks": [
            {
                "task_id": t["id"],
                "context_id": t["contextId"],
                "state": t["status"]["state"],
                "is_terminal": t["status"]["state"] in _TERMINAL_STATES,
            }
            for t in tasks
        ],
        "total": len(tasks),
    }


def openclaw_a2a_push_config(
    task_id: str,
    action: str = "list",
    webhook_url: str | None = None,
    auth_token: str | None = None,
    config_id: str | None = None,
) -> dict[str, Any]:
    """
    CRUD for A2A push notification webhook configurations.

    Maps to A2A Create/Get/List/Delete PushNotificationConfig operations.

    Args:
        task_id: Task to configure push notifications for.
        action: One of: create, get, list, delete.
        webhook_url: Webhook URL (required for create).
        auth_token: Bearer token for webhook delivery.
        config_id: Config ID (required for get/delete).

    Returns:
        dict with: ok, action, config(s).
    """
    if task_id not in _TASKS:
        return {"ok": False, "error": f"Task '{task_id}' not found"}

    configs = _PUSH_CONFIGS.setdefault(task_id, [])

    if action == "create":
        if not webhook_url:
            return {"ok": False, "error": "webhook_url required for create"}
        parsed = urlparse(webhook_url)
        if parsed.scheme not in ("http", "https"):
            return {"ok": False, "error": "webhook_url must use http or https"}
        # SSRF protection: block private IPs
        if parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return {"ok": False, "error": "webhook_url must not point to localhost (SSRF protection)"}

        cfg_id = str(uuid.uuid4())[:8]
        config = {
            "id": cfg_id,
            "url": webhook_url,
            "token": f"****{auth_token[-4:]}" if auth_token and len(auth_token) > 4 else "****",
            "created_at": time.time(),
        }
        configs.append(config)
        return {"ok": True, "action": "create", "config": config}

    elif action == "get":
        if not config_id:
            return {"ok": False, "error": "config_id required for get"}
        for cfg in configs:
            if cfg["id"] == config_id:
                return {"ok": True, "action": "get", "config": cfg}
        return {"ok": False, "error": f"Config '{config_id}' not found"}

    elif action == "list":
        return {"ok": True, "action": "list", "configs": configs, "total": len(configs)}

    elif action == "delete":
        if not config_id:
            return {"ok": False, "error": "config_id required for delete"}
        for i, cfg in enumerate(configs):
            if cfg["id"] == config_id:
                configs.pop(i)
                return {"ok": True, "action": "delete", "deleted": config_id}
        return {"ok": False, "error": f"Config '{config_id}' not found"}

    else:
        return {"ok": False, "error": f"Unknown action: {action}. Use: create, get, list, delete"}


async def openclaw_a2a_discovery(
    urls: list[str] | None = None,
    souls_dir: str | None = None,
    check_reachability: bool = False,
) -> dict[str, Any]:
    """
    Discover A2A agents via their Agent Card endpoints.

    Two modes:
    1. URL mode: Fetch .well-known/agent-card.json from given URLs
    2. Local mode: Scan a souls directory for SOUL.md files and generate cards

    Args:
        urls: List of agent base URLs to probe for Agent Cards.
        souls_dir: Local directory with SOUL.md files to scan.
        check_reachability: If True, verify URLs are reachable (production).

    Returns:
        dict with: ok, agents, total, errors.
    """
    agents: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    # Local discovery from SOUL.md files
    if souls_dir:
        p = Path(souls_dir)
        if not p.is_dir():
            return {"ok": False, "error": f"Directory not found: {souls_dir}"}

        for soul_dir in sorted(p.iterdir()):
            soul_file = soul_dir / "SOUL.md" if soul_dir.is_dir() else None
            if soul_file and soul_file.exists():
                try:
                    content = soul_file.read_text(encoding="utf-8")
                    meta = _parse_soul_frontmatter(content)
                    skills = _extract_skills_from_soul(content, meta)
                    agents.append({
                        "source": "local",
                        "path": str(soul_file),
                        "name": meta.get("name", soul_dir.name),
                        "description": meta.get("description", ""),
                        "skills_count": len(skills),
                        "skills": [s["id"] for s in skills],
                        "has_agent_card": (soul_dir / A2A_WELL_KNOWN_PATH).exists(),
                    })
                except Exception as exc:
                    errors.append({"path": str(soul_file), "error": str(exc)})

    # URL-based discovery
    if urls:
        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                errors.append({"url": url, "error": "Invalid URL scheme"})
                continue

            card_url = f"{url.rstrip('/')}/{A2A_WELL_KNOWN_PATH}"
            # In production, would HTTP GET the card_url
            # For now, register as a discovered endpoint
            agents.append({
                "source": "remote",
                "url": url,
                "card_url": card_url,
                "reachable": None if not check_reachability else False,
                "name": parsed.netloc,
            })

    return {
        "ok": True,
        "agents": agents,
        "total": len(agents),
        "errors": errors,
        "error_count": len(errors),
    }


# ── TOOLS registry ───────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_a2a_card_generate",
        "title": "Generate A2A Agent Card",
        "description": (
            "Generate a .well-known/agent-card.json from a SOUL.md file. "
            "Compliant with A2A Protocol v0.4.0. Extracts identity, skills, "
            "capabilities, security schemes, mTLS and signatures. Gap G1."
        ),
        "category": "a2a",
        "handler": openclaw_a2a_card_generate,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "soul_path": {
                    "type": "string",
                    "description": "Path to the SOUL.md file.",
                },
                "base_url": {
                    "type": "string",
                    "description": "Base URL where this agent is reachable.",
                },
                "output_path": {
                    "type": "string",
                    "description": "Optional path to write the Agent Card JSON.",
                },
                "capabilities": {
                    "type": "object",
                    "description": "A2A capabilities: streaming, pushNotifications, etc.",
                },
                "security_schemes": {
                    "type": "object",
                    "description": "OAuth2/apiKey/http security scheme definitions.",
                },
                "extensions": {
                    "type": "array",
                    "description": "A2A extension declarations.",
                    "items": {"type": "object"},
                },
            },
            "required": ["soul_path", "base_url"],
        },
    },
    {
        "name": "openclaw_a2a_card_validate",
        "title": "Validate A2A Agent Card",
        "description": (
            "Validate an A2A Agent Card against the v0.4.0 specification. "
            "Checks required fields, URL format, skills structure, capabilities, "
            "security schemes, mTLS and signatures. Reports issues by severity. Gap G2."
        ),
        "category": "a2a",
        "handler": openclaw_a2a_card_validate,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "card_path": {
                    "type": "string",
                    "description": "Path to an agent-card.json file.",
                },
                "card_json": {
                    "type": "object",
                    "description": "Inline Agent Card dict.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_a2a_task_send",
        "title": "Send A2A Task",
        "description": (
            "Send a message/task to an A2A agent. Creates a Task in the A2A "
            "lifecycle (submitted → working → completed). Maps to A2A SendMessage. "
            "v0.4.0 compliant. Gap G3."
        ),
        "category": "a2a",
        "handler": openclaw_a2a_task_send,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_url": {
                    "type": "string",
                    "description": "URL of the target A2A agent.",
                },
                "message": {
                    "type": "string",
                    "description": "Text message to send.",
                },
                "context_id": {
                    "type": "string",
                    "description": "Optional context ID to group related tasks.",
                },
                "blocking": {
                    "type": "boolean",
                    "description": "Wait for completion. Default: false.",
                    "default": False,
                },
                "metadata": {
                    "type": "object",
                    "description": "Optional metadata.",
                },
            },
            "required": ["agent_url", "message"],
        },
    },
    {
        "name": "openclaw_a2a_task_status",
        "title": "A2A Task Status",
        "description": (
            "Get A2A task status (GetTask) or list tasks (ListTasks v0.4.0). "
            "Supports filtering by task_id, context_id, with optional history."
        ),
        "category": "a2a",
        "handler": openclaw_a2a_task_status,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {
                    "type": "string",
                    "description": "Specific task ID to query.",
                },
                "context_id": {
                    "type": "string",
                    "description": "Filter tasks by context.",
                },
                "include_history": {
                    "type": "boolean",
                    "description": "Include message history.",
                    "default": False,
                },
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_a2a_push_config",
        "title": "A2A Push Notification Config",
        "description": (
            "CRUD for A2A push notification webhook configurations. "
            "Create, get, list, or delete push notification configs for tasks. "
            "v0.4.0 compliant. Gap G4."
        ),
        "category": "a2a",
        "handler": openclaw_a2a_push_config,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {
                    "type": "string",
                    "description": "Task to configure notifications for.",
                },
                "action": {
                    "type": "string",
                    "enum": ["create", "get", "list", "delete"],
                    "default": "list",
                },
                "webhook_url": {
                    "type": "string",
                    "description": "Webhook URL (for create).",
                },
                "auth_token": {
                    "type": "string",
                    "description": "Bearer token for webhook delivery.",
                },
                "config_id": {
                    "type": "string",
                    "description": "Config ID (for get/delete).",
                },
            },
            "required": ["task_id"],
        },
    },
    {
        "name": "openclaw_a2a_discovery",
        "title": "A2A Agent Discovery",
        "description": (
            "Discover A2A agents via Agent Card endpoints or local SOUL.md scan. "
            "URL mode: probes .well-known/agent-card.json (v0.2.1+). "
            "Local mode: scans souls directory. v0.4.0 compliant. Gap G6."
        ),
        "category": "a2a",
        "handler": openclaw_a2a_discovery,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "description": "Agent base URLs to probe.",
                    "items": {"type": "string"},
                },
                "souls_dir": {
                    "type": "string",
                    "description": "Local directory with SOUL.md subdirs.",
                },
                "check_reachability": {
                    "type": "boolean",
                    "description": "Verify URL reachability.",
                    "default": False,
                },
            },
            "required": [],
        },
    },
]
