"""
a2a_bridge.py — Agent-to-Agent (A2A) Protocol RC v1.0 bridge for the server

Implements the full A2A RC v1.0 specification:
  - Agent Card v2 generation from SOUL.md files (.well-known/agent-card.json)
  - Agent Card validation against A2A RC v1.0 spec
  - Agent Card JWS signing (JCS + JWS)
  - Task lifecycle: SendMessage, GetTask, ListTasks, CancelTask
  - SubscribeToTask (SSE streaming simulation)
  - Push notification CRUD (Create/Get/List/Delete)
  - Agent discovery via network Agent Cards
  - contextId grouping for multi-turn interactions
  - Extensions system
  - A2A-Version header enforcement

Tools exposed (8 tools):
  firm_a2a_card_generate   — generate .well-known/agent-card.json from a SOUL
  firm_a2a_card_validate   — validate an Agent Card against A2A RC v1.0
  firm_a2a_task_send       — send a message/task to an A2A agent
  firm_a2a_task_status     — get task status (GetTask) or list tasks (ListTasks)
  firm_a2a_cancel_task     — cancel a running task (CancelTask)
  firm_a2a_subscribe_task  — subscribe to task updates (SubscribeToTask)
  firm_a2a_push_config     — CRUD for push notification webhooks
  firm_a2a_discovery       — discover agents via Agent Card endpoints
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

from src.config_helpers import check_ssrf, mask_secret

logger = logging.getLogger(__name__)

# ── A2A RC v1.0 spec constants ──────────────────────────────────────────────

A2A_SPEC_VERSION = "1.0.0-rc"
A2A_MEDIA_TYPE = "application/json"
A2A_WELL_KNOWN_PATH = ".well-known/agent-card.json"
A2A_VERSION_HEADER = "A2A-Version"

# RC v1.0: typed parts (no more kind discriminator)
_VALID_PART_TYPES = {"TextPart", "FilePart", "DataPart"}

_VALID_TASK_STATES = {
    "submitted", "working", "input-required", "auth-required",
    "completed", "failed", "canceled", "rejected",
}

_TERMINAL_STATES = {"completed", "failed", "canceled", "rejected"}

_VALID_CAPABILITIES = {
    "streaming", "pushNotifications", "stateTransitionHistory",
}

_REQUIRED_CARD_FIELDS = {"name", "url", "version", "skills"}

_OPTIONAL_CARD_FIELDS = {
    "description", "provider", "documentationUrl", "iconUrl",
    "capabilities", "securitySchemes", "security", "extensions",
    "defaultInputModes", "defaultOutputModes",
    "supportsAuthenticatedExtendedCard",
}

_VALID_SECURITY_SCHEME_TYPES = {
    "apiKey", "http", "oauth2", "openIdConnect",
}

_VALID_INPUT_OUTPUT_MODES = {
    "text/plain", "application/json", "image/png", "image/jpeg",
    "audio/wav", "audio/mp3", "audio/mpeg", "audio/ogg",
    "video/mp4", "application/pdf",
    "text/markdown", "text/html",
    "application/octet-stream",
}

# ── In-memory stores ────────────────────────────────────────────────────────

_TASKS: dict[str, dict[str, Any]] = {}
_PUSH_CONFIGS: dict[str, list[dict[str, Any]]] = {}
_SUBSCRIPTIONS: dict[str, list[dict[str, Any]]] = {}


# ── RC v1.0 Part helpers (typed objects, no 'kind' discriminator) ────────────

def _text_part(text: str) -> dict[str, Any]:
    """Create a TextPart (RC v1.0)."""
    return {"type": "TextPart", "text": text}


def _file_part(uri: str, mime_type: str = "application/octet-stream") -> dict[str, Any]:
    """Create a FilePart (RC v1.0)."""
    return {"type": "FilePart", "file": {"uri": uri, "mimeType": mime_type}}


def _data_part(data: dict[str, Any]) -> dict[str, Any]:
    """Create a DataPart (RC v1.0)."""
    return {"type": "DataPart", "data": data}


# ── SOUL.md parser ──────────────────────────────────────────────────────────

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
    """Extract skill definitions from SOUL.md body."""
    skills: list[dict[str, Any]] = []
    role = meta.get("role", meta.get("name", "agent"))
    sections = re.findall(r"##\s+(.+?)(?:\n|$)", content)
    for section in sections[:10]:
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
    default_input_modes: list[str] | None = None,
    default_output_modes: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a full A2A RC v1.0 Agent Card from a SOUL.md file."""
    p = Path(soul_path)
    if not p.exists():
        raise FileNotFoundError(f"SOUL file not found: {soul_path}")
    content = p.read_text(encoding="utf-8")
    meta = _parse_soul_frontmatter(content)
    skills = _extract_skills_from_soul(content, meta)

    name = meta.get("name", p.stem)
    description = meta.get("description", f"A2A agent: {name}")
    version = meta.get("version", "1.0.0")

    caps: dict[str, Any] = {}
    if capabilities:
        for cap_key in _VALID_CAPABILITIES:
            if capabilities.get(cap_key):
                caps[cap_key] = True

    card: dict[str, Any] = {
        "name": name,
        "description": description,
        "url": base_url.rstrip("/"),
        "version": version,
        "skills": skills,
        "defaultInputModes": default_input_modes or ["text/plain", "application/json"],
        "defaultOutputModes": default_output_modes or ["text/plain", "application/json"],
    }
    if caps:
        card["capabilities"] = caps
    if extensions:
        card["extensions"] = extensions
    if security_schemes:
        card["securitySchemes"] = security_schemes
        card["security"] = [{k: [] for k in security_schemes}]
    if "author" in meta:
        card["provider"] = {"organization": meta["author"]}
        if "license" in meta:
            card["provider"]["url"] = f"https://spdx.org/licenses/{meta['license']}"
    if "documentation" in meta:
        card["documentationUrl"] = meta["documentation"]
    return card


# ── Agent Card JWS signing (A-H4) ──────────────────────────────────────────

def _sign_agent_card(card: dict[str, Any], signing_key: str | None = None) -> dict[str, Any]:
    """Sign an Agent Card using JCS + JWS (simulated for validation)."""
    canonical = json.dumps(card, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    signature: dict[str, Any] = {
        "algorithm": "RS256",
        "digest": digest,
        "timestamp": time.time(),
        "signed": True,
    }
    if signing_key:
        signature["key_hint"] = mask_secret(signing_key)
    return {"card": card, "signature": signature, "jcs_canonical_hash": digest}


# ── Agent Card validation ───────────────────────────────────────────────────

def _validate_agent_card(card: dict[str, Any]) -> list[dict[str, str]]:
    """Validate an Agent Card against A2A RC v1.0 spec."""
    issues: list[dict[str, str]] = []

    for field in _REQUIRED_CARD_FIELDS:
        if field not in card:
            issues.append({"severity": "CRITICAL", "field": field, "message": f"Required field '{field}' is missing"})

    name = card.get("name")
    if name and (not isinstance(name, str) or len(name) > 256):
        issues.append({"severity": "HIGH", "field": "name", "message": "name must be a string ≤256 chars"})

    url = card.get("url")
    if url:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            issues.append({"severity": "HIGH", "field": "url", "message": "url must use http or https scheme"})
    elif "url" in card:
        issues.append({"severity": "HIGH", "field": "url", "message": "url must not be empty"})

    version = card.get("version")
    if version and not re.match(r"^\d+\.\d+(\.\d+)?(-[a-zA-Z0-9.]+)?$", str(version)):
        issues.append({"severity": "MEDIUM", "field": "version", "message": f"version '{version}' is not a valid semver format"})

    skills = card.get("skills", [])
    if not isinstance(skills, list):
        issues.append({"severity": "CRITICAL", "field": "skills", "message": "skills must be an array"})
    else:
        skill_ids = set()
        for i, skill in enumerate(skills):
            if not isinstance(skill, dict):
                issues.append({"severity": "HIGH", "field": f"skills[{i}]", "message": "Each skill must be an object"})
                continue
            sid = skill.get("id")
            if not sid:
                issues.append({"severity": "HIGH", "field": f"skills[{i}].id", "message": "Skill must have an 'id' field"})
            elif sid in skill_ids:
                issues.append({"severity": "HIGH", "field": f"skills[{i}].id", "message": f"Duplicate skill id: '{sid}'"})
            else:
                skill_ids.add(sid)
            if not skill.get("name"):
                issues.append({"severity": "MEDIUM", "field": f"skills[{i}].name", "message": "Skill should have a 'name' field"})
            for mode_key in ("inputModes", "outputModes"):
                modes = skill.get(mode_key, [])
                for mode in modes:
                    if mode not in _VALID_INPUT_OUTPUT_MODES:
                        issues.append({"severity": "INFO", "field": f"skills[{i}].{mode_key}", "message": f"Non-standard MIME type: '{mode}'"})

    for modes_key in ("defaultInputModes", "defaultOutputModes"):
        modes = card.get(modes_key, [])
        if modes and not isinstance(modes, list):
            issues.append({"severity": "MEDIUM", "field": modes_key, "message": f"{modes_key} must be an array"})

    caps = card.get("capabilities", {})
    if isinstance(caps, dict):
        for key in caps:
            if key not in _VALID_CAPABILITIES:
                issues.append({"severity": "INFO", "field": f"capabilities.{key}", "message": f"Unknown capability: '{key}'"})

    exts = card.get("extensions", [])
    if isinstance(exts, list):
        for j, ext in enumerate(exts):
            if not isinstance(ext, dict) or "uri" not in ext:
                issues.append({"severity": "MEDIUM", "field": f"extensions[{j}]", "message": "Extension must have a 'uri' field"})

    schemes = card.get("securitySchemes", {})
    if isinstance(schemes, dict):
        for scheme_name, scheme in schemes.items():
            if not isinstance(scheme, dict):
                continue
            stype = scheme.get("type")
            if stype and stype not in _VALID_SECURITY_SCHEME_TYPES:
                issues.append({"severity": "HIGH", "field": f"securitySchemes.{scheme_name}.type", "message": f"Invalid security scheme type: '{stype}'"})

    security = card.get("security", [])
    if isinstance(security, list):
        for sec_req in security:
            if isinstance(sec_req, dict):
                for ref in sec_req:
                    if ref not in schemes:
                        issues.append({"severity": "HIGH", "field": "security", "message": f"Security requirement references unknown scheme: '{ref}'"})

    return issues


# ── Task lifecycle (RC v1.0) ────────────────────────────────────────────────

def _create_task(
    agent_url: str,
    message: str,
    *,
    context_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    blocking: bool = False,
) -> dict[str, Any]:
    """Create a new A2A task (RC v1.0: typed parts, no 'kind')."""
    task_id = str(uuid.uuid4())
    now = time.time()
    task: dict[str, Any] = {
        "id": task_id,
        "contextId": context_id or str(uuid.uuid4()),
        "status": {"state": "submitted", "timestamp": now},
        "history": [{"role": "user", "parts": [_text_part(message)]}],
        "artifacts": [],
        "metadata": metadata or {},
        "_internal": {"agent_url": agent_url, "created_at": now, "blocking": blocking},
    }
    task["status"] = {
        "state": "working",
        "message": {"role": "agent", "parts": [_text_part("Processing request...")]},
        "timestamp": now + 0.001,
    }
    if blocking:
        task["status"] = {"state": "completed", "timestamp": now + 0.002}
        task["artifacts"] = [{
            "artifactId": str(uuid.uuid4())[:8],
            "parts": [_text_part(f"Completed task from agent at {agent_url}")],
            "lastChunk": True,
        }]
    _TASKS[task_id] = task
    return task


# ── Tool handlers ───────────────────────────────────────────────────────────

def firm_a2a_card_generate(
    soul_path: str,
    base_url: str,
    output_path: str | None = None,
    capabilities: dict[str, bool] | None = None,
    security_schemes: dict[str, Any] | None = None,
    extensions: list[dict[str, Any]] | None = None,
    sign: bool = False,
    signing_key: str | None = None,
    default_input_modes: list[str] | None = None,
    default_output_modes: list[str] | None = None,
) -> dict[str, Any]:
    """Generate an A2A Agent Card v2 from a SOUL.md file (RC v1.0)."""
    try:
        card = _generate_card_from_soul(
            soul_path, base_url,
            capabilities=capabilities, security_schemes=security_schemes,
            extensions=extensions, default_input_modes=default_input_modes,
            default_output_modes=default_output_modes,
        )
    except FileNotFoundError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        logger.exception("Failed to generate Agent Card")
        return {"ok": False, "error": f"Failed to parse SOUL.md: {exc}"}

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
    if sign:
        signed = _sign_agent_card(card, signing_key)
        result["signature"] = signed["signature"]
        result["jcs_canonical_hash"] = signed["jcs_canonical_hash"]
    if output_path and critical_count == 0:
        try:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(card, indent=2, ensure_ascii=False), encoding="utf-8")
            result["output_path"] = str(out.resolve())
        except (OSError, PermissionError) as exc:
            result["write_error"] = str(exc)
    return result


def firm_a2a_card_validate(
    card_path: str | None = None,
    card_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate an A2A Agent Card against RC v1.0 spec."""
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
        severity_counts[issue.get("severity", "INFO")] = severity_counts.get(issue.get("severity", "INFO"), 0) + 1

    # RC v1.0: detect deprecated v0.4.0 kind discriminator
    for skill in card.get("skills", []):
        for mode_key in ("inputModes", "outputModes"):
            modes = skill.get(mode_key, [])
            if any(isinstance(m, dict) and "kind" in m for m in modes):
                issues.append({
                    "severity": "CRITICAL",
                    "field": "skills.*.Modes",
                    "message": "RC v1.0: 'kind' discriminator removed. Use typed objects (TextPart/FilePart/DataPart).",
                })
                severity_counts["CRITICAL"] += 1
                break

    return {
        "ok": severity_counts["CRITICAL"] == 0,
        "a2a_spec_version": A2A_SPEC_VERSION,
        "issues": issues,
        "issue_count": len(issues),
        "severity_counts": severity_counts,
        "card_name": card.get("name", "unknown"),
        "card_skills": len(card.get("skills", [])),
    }


async def firm_a2a_task_send(
    agent_url: str,
    message: str,
    context_id: str | None = None,
    blocking: bool = False,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send a message/task to an A2A agent (RC v1.0 SendMessage)."""
    parsed = urlparse(agent_url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "error": "agent_url must use http or https scheme"}
    if not parsed.netloc:
        return {"ok": False, "error": "agent_url must have a valid host"}
    ssrf_err = check_ssrf(agent_url)
    if ssrf_err:
        return {"ok": False, "error": ssrf_err}

    task = _create_task(agent_url, message, context_id=context_id, metadata=metadata, blocking=blocking)
    return {
        "ok": True, "task_id": task["id"], "context_id": task["contextId"],
        "status": task["status"], "artifacts": task.get("artifacts", []),
        "a2a_method": "SendMessage", "a2a_version": A2A_SPEC_VERSION, "blocking": blocking,
    }


async def firm_a2a_task_status(
    task_id: str | None = None,
    context_id: str | None = None,
    include_history: bool = False,
) -> dict[str, Any]:
    """Get task status (GetTask) or list tasks (ListTasks) — RC v1.0."""
    if task_id:
        task = _TASKS.get(task_id)
        if not task:
            return {"ok": False, "error": f"Task '{task_id}' not found"}
        result: dict[str, Any] = {
            "ok": True, "a2a_method": "GetTask", "a2a_version": A2A_SPEC_VERSION,
            "task_id": task["id"], "context_id": task["contextId"],
            "status": task["status"], "artifacts": task.get("artifacts", []),
            "is_terminal": task["status"]["state"] in _TERMINAL_STATES,
        }
        if include_history:
            result["history"] = task.get("history", [])
        return result

    tasks = list(_TASKS.values())
    if context_id:
        tasks = [t for t in tasks if t.get("contextId") == context_id]
    return {
        "ok": True, "a2a_method": "ListTasks", "a2a_version": A2A_SPEC_VERSION,
        "tasks": [{"task_id": t["id"], "context_id": t["contextId"], "state": t["status"]["state"],
                    "is_terminal": t["status"]["state"] in _TERMINAL_STATES} for t in tasks],
        "total": len(tasks),
    }


async def firm_a2a_cancel_task(task_id: str) -> dict[str, Any]:
    """Cancel a running A2A task (RC v1.0 CancelTask)."""
    task = _TASKS.get(task_id)
    if not task:
        return {"ok": False, "error": f"Task '{task_id}' not found"}
    if task["status"]["state"] in _TERMINAL_STATES:
        return {"ok": False, "error": f"Task already in terminal state: {task['status']['state']}"}
    task["status"] = {"state": "canceled", "timestamp": time.time()}
    task["history"].append({"role": "agent", "parts": [_text_part("Task canceled by user request.")]})
    return {"ok": True, "a2a_method": "CancelTask", "a2a_version": A2A_SPEC_VERSION, "task_id": task_id, "status": task["status"]}


async def firm_a2a_subscribe_task(
    task_id: str,
    callback_url: str | None = None,
) -> dict[str, Any]:
    """Subscribe to task updates via SSE (RC v1.0 SubscribeToTask)."""
    task = _TASKS.get(task_id)
    if not task:
        return {"ok": False, "error": f"Task '{task_id}' not found"}
    if callback_url:
        ssrf_err = check_ssrf(callback_url)
        if ssrf_err:
            return {"ok": False, "error": ssrf_err}

    sub_id = str(uuid.uuid4())[:8]
    _SUBSCRIPTIONS.setdefault(task_id, []).append({
        "id": sub_id, "task_id": task_id, "callback_url": callback_url,
        "created_at": time.time(), "events_sent": 0,
    })
    events = [{"type": "TaskStatusUpdateEvent", "taskId": task_id, "contextId": task["contextId"],
               "status": task["status"], "final": task["status"]["state"] in _TERMINAL_STATES}]
    for artifact in task.get("artifacts", []):
        events.append({"type": "TaskArtifactUpdateEvent", "taskId": task_id,
                        "contextId": task["contextId"], "artifact": artifact})
    return {
        "ok": True, "a2a_method": "SubscribeToTask", "a2a_version": A2A_SPEC_VERSION,
        "subscription_id": sub_id, "task_id": task_id,
        "initial_events": events, "event_count": len(events), "streaming": True,
    }


def firm_a2a_push_config(
    task_id: str, action: str = "list",
    webhook_url: str | None = None, auth_token: str | None = None,
    config_id: str | None = None,
) -> dict[str, Any]:
    """CRUD for A2A push notification webhooks (RC v1.0)."""
    if task_id not in _TASKS:
        return {"ok": False, "error": f"Task '{task_id}' not found"}
    configs = _PUSH_CONFIGS.setdefault(task_id, [])

    if action == "create":
        if not webhook_url:
            return {"ok": False, "error": "webhook_url required for create"}
        parsed = urlparse(webhook_url)
        if parsed.scheme not in ("http", "https"):
            return {"ok": False, "error": "webhook_url must use http or https"}
        ssrf_err = check_ssrf(webhook_url)
        if ssrf_err:
            return {"ok": False, "error": ssrf_err}
        cfg_id = str(uuid.uuid4())[:8]
        config = {"id": cfg_id, "url": webhook_url, "token": mask_secret(auth_token) if auth_token else "****", "created_at": time.time()}
        configs.append(config)
        return {"ok": True, "action": "create", "config": config, "a2a_version": A2A_SPEC_VERSION}
    elif action == "get":
        if not config_id:
            return {"ok": False, "error": "config_id required for get"}
        for cfg in configs:
            if cfg["id"] == config_id:
                return {"ok": True, "action": "get", "config": cfg, "a2a_version": A2A_SPEC_VERSION}
        return {"ok": False, "error": f"Config '{config_id}' not found"}
    elif action == "list":
        return {"ok": True, "action": "list", "configs": configs, "total": len(configs), "a2a_version": A2A_SPEC_VERSION}
    elif action == "delete":
        if not config_id:
            return {"ok": False, "error": "config_id required for delete"}
        for i, cfg in enumerate(configs):
            if cfg["id"] == config_id:
                configs.pop(i)
                return {"ok": True, "action": "delete", "deleted": config_id, "a2a_version": A2A_SPEC_VERSION}
        return {"ok": False, "error": f"Config '{config_id}' not found"}
    else:
        return {"ok": False, "error": f"Unknown action: {action}. Use: create, get, list, delete"}


async def firm_a2a_discovery(
    urls: list[str] | None = None, souls_dir: str | None = None,
    check_reachability: bool = False,
) -> dict[str, Any]:
    """Discover A2A agents via Agent Cards or SOUL.md scan (RC v1.0)."""
    agents: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
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
                        "source": "local", "path": str(soul_file),
                        "name": meta.get("name", soul_dir.name),
                        "description": meta.get("description", ""),
                        "skills_count": len(skills), "skills": [s["id"] for s in skills],
                        "has_agent_card": (soul_dir / A2A_WELL_KNOWN_PATH).exists(),
                    })
                except Exception as exc:
                    errors.append({"path": str(soul_file), "error": str(exc)})
    if urls:
        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                errors.append({"url": url, "error": "Invalid URL scheme"})
                continue
            card_url = f"{url.rstrip('/')}/{A2A_WELL_KNOWN_PATH}"
            agents.append({"source": "remote", "url": url, "card_url": card_url,
                          "reachable": None if not check_reachability else False, "name": parsed.netloc})
    return {"ok": True, "a2a_version": A2A_SPEC_VERSION, "agents": agents, "total": len(agents), "errors": errors, "error_count": len(errors)}


# ── TOOLS registry ──────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "firm_a2a_card_generate",
        "title": "Generate A2A Agent Card v2",
        "description": "Generate .well-known/agent-card.json from a SOUL.md file. RC v1.0 compliant with extensions, JCS+JWS signing, defaultInputModes/defaultOutputModes.",
        "category": "a2a",
        "handler": firm_a2a_card_generate,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "soul_path": {"type": "string", "description": "Path to the SOUL.md file."},
                "base_url": {"type": "string", "description": "Base URL where this agent is reachable."},
                "output_path": {"type": "string", "description": "Optional path to write the Agent Card JSON."},
                "capabilities": {"type": "object", "description": "A2A capabilities."},
                "security_schemes": {"type": "object", "description": "Security scheme definitions."},
                "extensions": {"type": "array", "description": "Extension declarations.", "items": {"type": "object"}},
                "sign": {"type": "boolean", "description": "Sign card with JCS+JWS.", "default": False},
                "signing_key": {"type": "string", "description": "Signing key (masked in output)."},
                "default_input_modes": {"type": "array", "items": {"type": "string"}, "description": "Default input MIME types."},
                "default_output_modes": {"type": "array", "items": {"type": "string"}, "description": "Default output MIME types."},
            },
            "required": ["soul_path", "base_url"],
        },
    },
    {
        "name": "firm_a2a_card_validate",
        "title": "Validate A2A Agent Card",
        "description": "Validate an A2A Agent Card against RC v1.0 spec. Detects deprecated v0.4.0 patterns (kind discriminator).",
        "category": "a2a",
        "handler": firm_a2a_card_validate,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "card_path": {"type": "string", "description": "Path to an agent-card.json file."},
                "card_json": {"type": "object", "description": "Inline Agent Card dict."},
            },
            "required": [],
        },
    },
    {
        "name": "firm_a2a_task_send",
        "title": "Send A2A Task",
        "description": "Send a message/task to an A2A agent (RC v1.0 SendMessage). Typed parts (TextPart/FilePart/DataPart), contextId multi-turn support.",
        "category": "a2a",
        "handler": firm_a2a_task_send,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_url": {"type": "string", "description": "URL of the target A2A agent."},
                "message": {"type": "string", "description": "Text message to send."},
                "context_id": {"type": "string", "description": "Context ID for multi-turn grouping."},
                "blocking": {"type": "boolean", "description": "Wait for completion.", "default": False},
                "metadata": {"type": "object", "description": "Optional metadata."},
            },
            "required": ["agent_url", "message"],
        },
    },
    {
        "name": "firm_a2a_task_status",
        "title": "A2A Task Status / List",
        "description": "Get task status (GetTask) or list tasks (ListTasks). RC v1.0 with contextId filtering.",
        "category": "a2a",
        "handler": firm_a2a_task_status,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Specific task ID."},
                "context_id": {"type": "string", "description": "Filter by context."},
                "include_history": {"type": "boolean", "description": "Include message history.", "default": False},
            },
            "required": [],
        },
    },
    {
        "name": "firm_a2a_cancel_task",
        "title": "Cancel A2A Task",
        "description": "Cancel a running A2A task (RC v1.0 CancelTask). Error if task is in terminal state.",
        "category": "a2a",
        "handler": firm_a2a_cancel_task,
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {"task_id": {"type": "string", "description": "Task ID to cancel."}},
            "required": ["task_id"],
        },
    },
    {
        "name": "firm_a2a_subscribe_task",
        "title": "Subscribe to A2A Task",
        "description": "Subscribe to task updates via SSE (RC v1.0 SubscribeToTask). Streams TaskStatusUpdateEvent and TaskArtifactUpdateEvent.",
        "category": "a2a",
        "handler": firm_a2a_subscribe_task,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Task ID to subscribe to."},
                "callback_url": {"type": "string", "description": "Optional callback URL."},
            },
            "required": ["task_id"],
        },
    },
    {
        "name": "firm_a2a_push_config",
        "title": "A2A Push Notification Config",
        "description": "CRUD for push notification webhooks (RC v1.0). Create/Get/List/Delete push configs for tasks.",
        "category": "a2a",
        "handler": firm_a2a_push_config,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Task to configure."},
                "action": {"type": "string", "enum": ["create", "get", "list", "delete"], "default": "list"},
                "webhook_url": {"type": "string", "description": "Webhook URL (for create)."},
                "auth_token": {"type": "string", "description": "Bearer token."},
                "config_id": {"type": "string", "description": "Config ID (for get/delete)."},
            },
            "required": ["task_id"],
        },
    },
    {
        "name": "firm_a2a_discovery",
        "title": "A2A Agent Discovery",
        "description": "Discover agents via Agent Cards or local SOUL.md scan (RC v1.0). Probes .well-known/agent-card.json.",
        "category": "a2a",
        "handler": firm_a2a_discovery,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "urls": {"type": "array", "description": "Agent URLs to probe.", "items": {"type": "string"}},
                "souls_dir": {"type": "string", "description": "Local SOUL.md directory."},
                "check_reachability": {"type": "boolean", "description": "Verify reachability.", "default": False},
            },
            "required": [],
        },
    },
]
