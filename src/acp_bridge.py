"""
acp_bridge.py — ACP session persistence & autonomous session tools

Comble les gaps identifiés dans the server :
  C4 — ACP bridge session state en mémoire uniquement (crash = perte sessions)
  H3 — Sessions isolées ne peuvent pas accéder aux env vars des providers
  H4 — Cron tools sur denylist sandbox (automation bloquée)
  H5 — Race condition sur shared-workspace read/modify/write

Tools exposed:
  acp_session_persist       — persiste run_id → gateway_session_key sur disque
  acp_session_restore       — recharge sessions depuis le fichier persisté après crash
  acp_session_list_active   — liste toutes les sessions ACP actives
  fleet_session_inject_env  — injecte les provider env vars dans sessions non-main
  fleet_cron_schedule       — planifie un cron task sans passer par sandbox
  firm_workspace_lock   — advisory file lock pour éviter les race conditions
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

ACP_SESSIONS_PATH: str = os.getenv(
    "ACP_SESSIONS_PATH",
    os.path.expanduser("~/.firm/acp_sessions.json"),
)

WORKSPACE_LOCKS_DIR: str = os.getenv(
    "WORKSPACE_LOCKS_DIR",
    os.path.expanduser("~/.firm/locks"),
)

# Allowlist strict des clés d'env vars pouvant être injectées dans les sessions (H3)
_ENV_KEY_ALLOWLIST_PATTERN = re.compile(
    r"^(ANTHROPIC_API_KEY|OPENAI_API_KEY|OPENROUTER_API_KEY|GEMINI_API_KEY"
    r"|FIRM_MODEL|FIRM_PROVIDER|FIRM_MAX_TOKENS"
    r"|CLAW_MODEL|CLAW_PROVIDER|PROXY_URL|CUSTOM_[A-Z0-9_]+)$"
)

# Allowlist des commandes cron (H4)
_CRON_COMMAND_PATTERN = re.compile(r"^[a-zA-Z0-9 /._\-=]+$")
_CRON_COMMAND_BLOCKLIST = {"rm", "dd", "mkfs", "format", "shutdown", "reboot", "halt", "kill"}


# ── Helper: secret masking (delegates to shared config_helpers) ─────────────────

from src.config_helpers import mask_secret as _mask_secret  # noqa: E402


# ── ACP session persistence (C4) ─────────────────────────────────────────────

def _load_acp_sessions() -> dict[str, Any]:
    p = Path(ACP_SESSIONS_PATH)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.error("Failed to load ACP sessions from %s: %s", ACP_SESSIONS_PATH, exc)
        return {}


def _save_acp_sessions(sessions: dict[str, Any]) -> None:
    p = Path(ACP_SESSIONS_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = str(p) + ".tmp"
    try:
        Path(tmp).write_text(json.dumps(sessions, indent=2), encoding="utf-8")
        os.replace(tmp, str(p))  # atomic rename
    except Exception as exc:
        logger.error("Failed to save ACP sessions: %s", exc)
        if os.path.exists(tmp):
            os.unlink(tmp)


async def acp_session_persist(
    run_id: str,
    gateway_session_key: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Persists an ACP run_id → gateway_session_key mapping to disk.

    Addresses gap C4: ACP bridge sessions are in-memory only; a bridge crash
    loses all session mappings, causing IDE integrations to silently start new sessions.

    Call this immediately when an ACP session is created.

    Args:
        run_id: ACP run ID (from AgentRunRequest.run_id).
        gateway_session_key: The corresponding Firm Gateway session key.
        metadata: Optional metadata to store with the session.

    Returns:
        dict with keys: ok, run_id, persisted_at, total_sessions.
    """
    sessions = _load_acp_sessions()
    sessions[run_id] = {
        "gateway_session_key": gateway_session_key,
        "persisted_at": time.time(),
        "metadata": metadata or {},
    }
    _save_acp_sessions(sessions)
    logger.info("ACP session persisted: run_id=%s → session=%s", run_id, gateway_session_key)
    return {
        "ok": True,
        "run_id": run_id,
        "gateway_session_key": gateway_session_key,
        "persisted_at": sessions[run_id]["persisted_at"],
        "total_sessions": len(sessions),
    }


async def acp_session_restore(
    max_age_hours: int = 24,
) -> dict[str, Any]:
    """
    Restores ACP sessions from disk after a bridge crash or restart.

    Purges stale sessions (older than max_age_hours) automatically.

    Args:
        max_age_hours: Sessions older than this are considered stale and purged.

    Returns:
        dict with keys: ok, restored, purged, sessions.
    """
    sessions = _load_acp_sessions()
    now = time.time()
    max_age_s = max_age_hours * 3600

    restored: list[dict[str, Any]] = []
    purged: list[str] = []

    for run_id, data in list(sessions.items()):
        age_s = now - data.get("persisted_at", 0)
        if age_s > max_age_s:
            purged.append(run_id)
            del sessions[run_id]
        else:
            restored.append({
                "run_id": run_id,
                "gateway_session_key": data["gateway_session_key"],
                "age_minutes": round(age_s / 60, 1),
                "metadata": data.get("metadata", {}),
            })

    if purged:
        _save_acp_sessions(sessions)
        logger.info("Purged %d stale ACP sessions", len(purged))

    return {
        "ok": True,
        "restored": len(restored),
        "purged": len(purged),
        "sessions": restored,
    }


async def acp_session_list_active(
    include_stale: bool = False,
) -> dict[str, Any]:
    """
    Lists all persisted ACP sessions.

    Args:
        include_stale: If True, includes sessions older than 24h (normally stale).

    Returns:
        dict with keys: ok, total, sessions (list with run_id, age, status).
    """
    sessions = _load_acp_sessions()
    now = time.time()
    result: list[dict[str, Any]] = []

    for run_id, data in sessions.items():
        age_s = now - data.get("persisted_at", 0)
        stale = age_s > 86400  # 24h
        if stale and not include_stale:
            continue
        result.append({
            "run_id": run_id,
            "gateway_session_key": data["gateway_session_key"],
            "age_minutes": round(age_s / 60, 1),
            "status": "stale" if stale else "active",
            "metadata": data.get("metadata", {}),
        })

    return {
        "ok": True,
        "total": len(result),
        "sessions": sorted(result, key=lambda x: x["age_minutes"]),
    }


# ── Fleet session env injection (H3) ─────────────────────────────────────────

async def fleet_session_inject_env(
    env_vars: dict[str, str],
    filter_tags: list[str] | None = None,
    allowlist_keys: list[str] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Broadcasts provider env vars to all non-main Gateway sessions in the fleet.

    Addresses gap H3: isolated sessions (spawn/cron) cannot access configured
    provider env vars, blocking all LLM calls in non-main sessions.

    Secrets are masked in logs and return values.
    Only allowlisted env var keys are injected (security gate).

    Args:
        env_vars: dict of env var key → value to inject.
        filter_tags: Only target fleet instances with these tags.
        allowlist_keys: Extra allowed key patterns (in addition to built-in allowlist).
        dry_run: If True, validates without sending.

    Returns:
        dict with keys: ok, validated_keys, rejected_keys, injected_to, dry_run.
    """
    # Build effective allowlist
    extra_pattern = None
    if allowlist_keys:
        combined = "|".join(re.escape(k) for k in allowlist_keys)
        extra_pattern = re.compile(f"^({combined})$")

    validated: dict[str, str] = {}
    rejected: list[dict[str, str]] = []

    for key, val in env_vars.items():
        allowed = bool(_ENV_KEY_ALLOWLIST_PATTERN.match(key))
        if not allowed and extra_pattern:
            allowed = bool(extra_pattern.match(key))
        if allowed:
            validated[key] = val
        else:
            rejected.append({"key": key, "reason": "Key not in env allowlist"})

    if not validated:
        return {
            "ok": False,
            "error": "No env vars passed allowlist validation",
            "rejected": rejected,
        }

    # Mask secrets for log/return
    masked = {k: _mask_secret(v) for k, v in validated.items()}
    logger.info("fleet_session_inject_env: injecting %d vars (masked): %s", len(validated), masked)

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "validated_keys": list(validated.keys()),
            "masked_values": masked,
            "rejected": rejected,
            "injected_to": [],
        }

    # Build broadcast message for fleet
    # This delegates to firm_gateway_fleet_broadcast with the env injection payload
    from src.gateway_fleet import firm_gateway_fleet_broadcast  # local import to avoid cycle

    broadcast_result = await firm_gateway_fleet_broadcast(
        agent="firm",
        message=json.dumps({
            "type": "env_inject",
            "env": validated,
            "scope": "non-main",
        }),
        filter_tags=filter_tags,
    )

    return {
        "ok": True,
        "dry_run": False,
        "validated_keys": list(validated.keys()),
        "masked_values": masked,
        "rejected": rejected,
        "broadcast_result": broadcast_result,
        "note": (
            "Env vars injected via Gateway broadcast. "
            "Non-main sessions can now call configured LLM providers (resolves gap H3)."
        ),
    }


# ── Fleet cron schedule (H4) ──────────────────────────────────────────────────

_CRON_SCHEDULE_PATH: str = os.path.expanduser("~/.firm/cron_schedules.json")


def _validate_cron_expression(expr: str) -> bool:
    """Basic cron expression validation (5 fields)."""
    parts = expr.strip().split()
    return len(parts) == 5


async def fleet_cron_schedule(
    command: str,
    schedule: str,
    session: str = "main",
    description: str | None = None,
) -> dict[str, Any]:
    """
    Schedules a cron task on the main session (bypassing sandbox denylist).

    Addresses gap H4: cron tools are on the sandbox denylist, blocking all
    autonomous scheduled workflows in non-main Docker sessions.

    Uses strict command allowlist (alphanumeric + safe chars only) and blocklist
    to prevent abuse.

    Args:
        command: Command to schedule. Must match r'^[a-zA-Z0-9 /._-=]+$'.
        schedule: Cron expression (5 fields, e.g. '0 9 * * 1-5').
        session: Target session ('main' only for now — non-main blocks cron).
        description: Human-readable description of what this cron does.

    Returns:
        dict with keys: ok, cron_id, schedule, next_run_hint, command_masked.
    """
    # Validate command against allowlist pattern
    if not _CRON_COMMAND_PATTERN.match(command):
        return {
            "ok": False,
            "error": (
                f"Command contains disallowed characters. "
                f"Only [a-zA-Z0-9 /._-=] are permitted. Got: {command!r}"
            ),
        }

    # Blocklist check — deny destructive commands
    command_base = command.strip().split()[0].lower() if command.strip() else ""
    if command_base in _CRON_COMMAND_BLOCKLIST:
        return {
            "ok": False,
            "error": f"Command '{command_base}' is in the cron blocklist for safety.",
        }

    if not _validate_cron_expression(schedule):
        return {
            "ok": False,
            "error": f"Invalid cron expression: {schedule!r}. Expected 5 fields (min hour dom mon dow).",
        }

    if session != "main":
        return {
            "ok": False,
            "error": (
                "Cron tasks can only be scheduled on the 'main' session — "
                "non-main (sandbox) sessions have 'cron' on the denylist (gap H4). "
                "Use session='main' for scheduled tasks."
            ),
        }

    # Persist schedule
    cron_id = f"cron_{int(time.time() * 1000)}"
    p = Path(_CRON_SCHEDULE_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    schedules: dict[str, Any] = {}
    if p.exists():
        try:
            schedules = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            schedules = {}

    schedules[cron_id] = {
        "command": command,
        "schedule": schedule,
        "session": session,
        "description": description or "",
        "created_at": time.time(),
    }

    tmp = str(p) + ".tmp"
    Path(tmp).write_text(json.dumps(schedules, indent=2), encoding="utf-8")
    os.replace(tmp, str(p))

    return {
        "ok": True,
        "cron_id": cron_id,
        "command": command,
        "schedule": schedule,
        "session": session,
        "description": description,
        "note": (
            "Schedule persisted. To activate, use the cron integration "
            "on the main session (not inside sandbox). See gap H4 workaround."
        ),
        "next_run_hint": f"Cron expression '{schedule}' — use crontab.guru to verify timing.",
    }


# ── Workspace advisory lock (H5) ─────────────────────────────────────────────

async def firm_workspace_lock(
    path: str,
    action: str,
    owner: str,
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    """
    Advisory file lock with timeout and owner tracking.

    Addresses gap H5: race condition in shared-workspace read/modify/write —
    multiple agent sessions can concurrently modify the same workspace resource.

    Implements acquire/release/status protocol via atomic lock files.

    Args:
        path: Workspace resource path to lock (no '..' allowed).
        action: One of 'acquire', 'release', 'status'.
        owner: Identifier for the lock holder (e.g. session ID, agent name).
        timeout_s: Max seconds to wait for lock acquisition (1-300).

    Returns:
        dict with keys: ok, action, locked, lock_owner, lock_age_s, lock_path.
    """
    if ".." in path:
        return {"ok": False, "error": "Path must not contain path traversal (..)"}

    action = action.lower()
    if action not in ("acquire", "release", "status"):
        return {"ok": False, "error": f"action must be 'acquire', 'release', or 'status'. Got: {action!r}"}

    locks_dir = Path(WORKSPACE_LOCKS_DIR)
    locks_dir.mkdir(parents=True, exist_ok=True)

    # Create a safe lock filename from the resource path
    safe_name = re.sub(r"[^a-zA-Z0-9_\-.]", "_", path.strip("/"))[:200]
    lock_path = locks_dir / f"{safe_name}.lock"

    if action == "status":
        if not lock_path.exists():
            return {"ok": True, "action": "status", "locked": False, "lock_path": str(lock_path)}
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
            age_s = time.time() - data.get("acquired_at", time.time())
            return {
                "ok": True,
                "action": "status",
                "locked": True,
                "lock_owner": data.get("owner"),
                "lock_age_s": round(age_s, 1),
                "lock_path": str(lock_path),
            }
        except Exception as exc:
            return {"ok": False, "error": f"Could not read lock file: {exc}"}

    if action == "release":
        if not lock_path.exists():
            return {"ok": True, "action": "release", "note": "Lock did not exist — nothing to release."}
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}

        if data.get("owner") != owner:
            return {
                "ok": False,
                "error": f"Lock is owned by '{data.get('owner')}', not '{owner}'. Cannot release.",
            }
        lock_path.unlink(missing_ok=True)
        return {"ok": True, "action": "release", "lock_path": str(lock_path), "released_by": owner}

    # action == "acquire"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not lock_path.exists():
            # Try to atomically create the lock
            try:
                with open(str(lock_path), "x", encoding="utf-8") as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    json.dump({"owner": owner, "path": path, "acquired_at": time.time()}, f)
                    f.flush()
                return {
                    "ok": True,
                    "action": "acquire",
                    "locked": True,
                    "lock_owner": owner,
                    "lock_path": str(lock_path),
                }
            except (FileExistsError, BlockingIOError):
                pass  # Race — another process got it first, retry
        await asyncio.sleep(0.1)

    # Timeout
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.exists() else {}
    except Exception:
        data = {}

    return {
        "ok": False,
        "action": "acquire",
        "locked": False,
        "error": f"Timed out after {timeout_s}s waiting for lock.",
        "current_owner": data.get("owner"),
        "lock_path": str(lock_path),
    }


# ── ACPX version pin check (2026.3.1) ─────────────────────────────────────────

_ACPX_MIN_VERSION = "0.1.15"
_ACPX_RECOMMENDED_STREAMING = "final_only"


async def firm_acpx_version_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Checks that the ACPX plugin is pinned to >= 0.1.15 and uses final_only streaming.

    2026.3.1 broke ACPX < 0.1.15 due to the new task streaming protocol.
    The `final_only` streaming mode is required to avoid partial task results.

    Args:
        config_path: Path to config.json (default: ~/.firm/config.json).

    Returns:
        {ok, severity, findings, config_path}
    """
    from src.config_helpers import no_path_traversal

    if config_path:
        no_path_traversal(config_path)

    resolved = config_path or os.path.expanduser("~/.firm/config.json")
    p = Path(resolved)
    if not p.exists():
        return {
            "ok": True, "severity": "INFO",
            "findings": [{"id": "config_not_found", "severity": "INFO",
                          "message": f"Config not found at {resolved}"}],
            "finding_count": 0, "config_path": resolved,
        }

    try:
        config = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"ok": False, "severity": "CRITICAL",
                "findings": [{"id": "config_parse_error", "severity": "CRITICAL",
                              "message": str(exc)}],
                "finding_count": 1, "config_path": resolved}

    findings: list[dict[str, Any]] = []

    # Check plugins section for ACPX
    plugins = config.get("plugins", {})
    acpx_cfg = plugins.get("acpx", plugins.get("@firm/acpx", {}))

    if not acpx_cfg:
        findings.append({
            "id": "acpx_not_configured",
            "severity": "INFO",
            "message": "ACPX plugin not found in config — skipping version check.",
        })
    else:
        # Check version pin
        version = acpx_cfg.get("version", "")
        if version:
            # Parse version: strip leading v/^/~
            clean = re.sub(r"^[v^~>=<]+", "", version).strip()
            parts = clean.split(".")
            try:
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
                version_tuple = (major, minor, patch)
                min_parts = _ACPX_MIN_VERSION.split(".")
                min_tuple = (int(min_parts[0]), int(min_parts[1]), int(min_parts[2]))
                if version_tuple < min_tuple:
                    findings.append({
                        "id": "acpx_version_too_old",
                        "severity": "CRITICAL",
                        "message": (
                            f"ACPX pinned to {version} but 2026.3.1 requires >= {_ACPX_MIN_VERSION}. "
                            "Older versions break under the new task streaming protocol. "
                            f"Update to: plugins.acpx.version: '{_ACPX_MIN_VERSION}'"
                        ),
                    })
            except (ValueError, IndexError):
                findings.append({
                    "id": "acpx_version_unparseable",
                    "severity": "MEDIUM",
                    "message": f"Cannot parse ACPX version '{version}'. Pin to >= {_ACPX_MIN_VERSION}.",
                })
        else:
            findings.append({
                "id": "acpx_version_unpinned",
                "severity": "HIGH",
                "message": (
                    "ACPX plugin has no version pin. 2026.3.1 requires >= 0.1.15 "
                    f"for the new task streaming protocol. Pin to: '{_ACPX_MIN_VERSION}'"
                ),
            })

        # Check streaming mode
        streaming = acpx_cfg.get("streaming", {}).get("mode", "")
        if streaming != _ACPX_RECOMMENDED_STREAMING:
            findings.append({
                "id": "acpx_streaming_not_final_only",
                "severity": "HIGH" if streaming else "MEDIUM",
                "message": (
                    f"ACPX streaming mode is '{streaming or 'unset'}' — "
                    f"recommended '{_ACPX_RECOMMENDED_STREAMING}' to avoid partial task results "
                    "with the 2026.3.1 streaming protocol. "
                    f"Set plugins.acpx.streaming.mode: '{_ACPX_RECOMMENDED_STREAMING}'"
                ),
            })

    severity = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            severity = "CRITICAL"
            break
        elif f["severity"] == "HIGH" and severity != "CRITICAL":
            severity = "HIGH"
        elif f["severity"] == "MEDIUM" and severity not in ("CRITICAL", "HIGH"):
            severity = "MEDIUM"

    return {
        "ok": len(findings) == 0 or all(f["severity"] == "INFO" for f in findings),
        "severity": severity,
        "findings": findings,
        "finding_count": len([f for f in findings if f["severity"] != "INFO"]),
        "config_path": resolved,
    }


# ── Tool registry ─────────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "acp_session_persist",
        "title": "Persist ACP Session",
        "description": (
            "Persists an ACP run_id → gateway_session_key mapping to disk. "
            "Gap C4: ACP bridge sessions are in-memory only — a crash loses all sessions. "
            "Call immediately when an ACP session is created. Uses atomic file write."
        ),
        "category": "acp",
        "handler": acp_session_persist,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string", "description": "ACP run ID."},
                "gateway_session_key": {"type": "string", "description": "Firm Gateway session key."},
                "metadata": {"type": "object", "description": "Optional metadata dict."},
            },
            "required": ["run_id", "gateway_session_key"],
        },
    },
    {
        "name": "acp_session_restore",
        "title": "Restore ACP Sessions",
        "description": (
            "Reloads ACP sessions from disk after a bridge crash or restart. "
            "Purges stale sessions (> max_age_hours) automatically. "
            "Call on bridge startup to restore all in-flight sessions."
        ),
        "category": "acp",
        "handler": acp_session_restore,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "max_age_hours": {
                    "type": "integer",
                    "description": "Sessions older than this are purged. Default: 24.",
                    "default": 24,
                },
            },
            "required": [],
        },
    },
    {
        "name": "acp_session_list_active",
        "title": "List Active ACP Sessions",
        "description": "Lists all persisted ACP sessions with their age and status (active/stale).",
        "category": "acp",
        "handler": acp_session_list_active,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_stale": {
                    "type": "boolean",
                    "description": "Include sessions older than 24h. Default: false.",
                    "default": False,
                },
            },
            "required": [],
        },
    },
    {
        "name": "fleet_session_inject_env",
        "title": "Inject Fleet Env Vars",
        "description": (
            "Broadcasts provider env vars (API keys, model config) to all non-main Gateway sessions. "
            "Gap H3: isolated spawn/cron sessions cannot access provider env vars, blocking LLM calls. "
            "Enforces a strict key allowlist. Masks secrets in all logs and return values."
        ),
        "category": "acp",
        "handler": fleet_session_inject_env,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "env_vars": {
                    "type": "object",
                    "description": "Dict of env var key → value to inject.",
                },
                "filter_tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Only target fleet instances with these tags.",
                },
                "allowlist_keys": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Extra env var keys to allow beyond the built-in allowlist.",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "Validate without sending. Default: false.",
                    "default": False,
                },
            },
            "required": ["env_vars"],
        },
    },
    {
        "name": "fleet_cron_schedule",
        "title": "Schedule Cron Task",
        "description": (
            "Schedules a cron task on the main session, bypassing sandbox denylist. "
            "Gap H4: cron tools are on the denylist in Docker sessions, blocking autonomous scheduled workflows. "
            "Enforces strict command allowlist and blocklist for safety."
        ),
        "category": "acp",
        "handler": fleet_cron_schedule,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Command to schedule. Only [a-zA-Z0-9 /._-=] allowed.",
                },
                "schedule": {
                    "type": "string",
                    "description": "Cron expression (5 fields, e.g. '0 9 * * 1-5').",
                },
                "session": {
                    "type": "string",
                    "description": "Target session. Must be 'main' (cron blocked in sandbox).",
                    "default": "main",
                },
                "description": {
                    "type": "string",
                    "description": "Human-readable description of the task.",
                },
            },
            "required": ["command", "schedule"],
        },
    },
    {
        "name": "firm_workspace_lock",
        "title": "Workspace Advisory Lock",
        "description": (
            "Advisory file lock with timeout and owner tracking. "
            "Gap H5: race condition in shared-workspace read/modify/write — multiple agent sessions "
            "can corrupt shared resources. Actions: acquire / release / status."
        ),
        "category": "acp",
        "handler": firm_workspace_lock,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Workspace resource path to lock. No '..' allowed.",
                },
                "action": {
                    "type": "string",
                    "enum": ["acquire", "release", "status"],
                    "description": "Lock action.",
                },
                "owner": {
                    "type": "string",
                    "description": "Lock owner identifier (e.g. session ID, agent name).",
                },
                "timeout_s": {
                    "type": "number",
                    "description": "Max seconds to wait for lock acquisition (1-300). Default: 30.",
                    "minimum": 1,
                    "maximum": 300,
                    "default": 30.0,
                },
            },
            "required": ["path", "action", "owner"],
        },
    },
    {
        "name": "firm_acpx_version_check",
        "title": "ACPX Version Pin Check",
        "description": (
            "Checks ACPX plugin version pin (>= 0.1.15) and streaming mode (final_only). "
            "2026.3.1 broke ACPX < 0.1.15 due to the new task streaming protocol. "
            "Returns: version status, streaming mode recommendation."
        ),
        "category": "acp",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "handler": firm_acpx_version_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Path to config.json (default: ~/.firm/config.json).",
                },
            },
            "required": [],
        },
    },
]
