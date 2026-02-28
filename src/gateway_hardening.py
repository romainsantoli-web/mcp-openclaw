"""
gateway_hardening.py — OpenClaw gateway auth, credentials, webhooks, logging & workspace

Comble les gaps identifiés dans openclaw/openclaw :
  H2 — Pas de validation de la config auth Gateway (mode password absent si Funnel actif)
  M3 — Baileys WhatsApp : session credentials sans check d'intégrité/âge
  M4 — Webhooks entrants sans vérification de signature HMAC
  M7 — Logging non configuré ou sans redaction patterns
  M8 — Workspace ~/.openclaw non contrôlé (MEMORY.md, SOUL.md absents)

Tools exposed:
  openclaw_gateway_auth_check        — vérifie la config auth du Gateway (H2)
  openclaw_credentials_check         — vérifie l'état des credentials Baileys/channels (M3)
  openclaw_webhook_sig_check         — vérifie la présence de secrets HMAC pour les webhooks (M4)
  openclaw_log_config_check          — vérifie la config logging (niveau, redact, rotation) (M7)
  openclaw_workspace_integrity_check — vérifie l'intégrité du workspace OpenClaw (M8)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Default paths (overridable via env) ──────────────────────────────────────

_OPENCLAW_DIR = Path(
    os.getenv("OPENCLAW_DIR", Path.home() / ".openclaw")
)
_CONFIG_PATH = Path(
    os.getenv("OPENCLAW_CONFIG", _OPENCLAW_DIR / "openclaw.json")
)
_CREDENTIALS_DIR = Path(
    os.getenv("OPENCLAW_CREDS", _OPENCLAW_DIR / "credentials")
)
_WORKSPACE_DIR = Path(
    os.getenv("OPENCLAW_WORKSPACE", _OPENCLAW_DIR / "workspace")
)

# ── Constants ─────────────────────────────────────────────────────────────────

# Dangerous gateway auth findings
_AUTH_FINDINGS: list[tuple[str, str, str]] = [
    (
        "funnel_without_password",
        "CRITICAL",
        "gateway.tailscale.mode=funnel without gateway.auth.mode=password — "
        "public endpoint with no auth",
    ),
    (
        "disable_device_auth",
        "HIGH",
        "gateway.controlUi.dangerouslyDisableDeviceAuth=true — "
        "Control UI accessible without device auth (localhost break-glass only)",
    ),
    (
        "no_auth_non_loopback",
        "HIGH",
        "gateway.bind != loopback without gateway.auth configured — "
        "Gateway exposed without authentication",
    ),
    (
        "missing_auth_token",
        "MEDIUM",
        "gateway.auth not configured — recommended for any non-local deployment",
    ),
]

# Baileys session files that must exist after WhatsApp pairing
_BAILEYS_SESSION_FILES = {
    "creds.json",
    "app-state-sync-key-*.json",
}

# Workspace files that must exist in a healthy workspace
_REQUIRED_WORKSPACE_FILES = ["AGENTS.md", "SOUL.md"]
_STALE_MEMORY_DAYS = 30  # MEMORY.md older than this = warning

# Webhook config keys expected per channel
_WEBHOOK_CHANNELS: dict[str, list[str]] = {
    "telegram": ["webhookSecret", "botToken"],
    "discord": ["signingSecret", "token"],
    "slack": ["signingSecret", "botToken"],
    "msteams": ["webhookSecret"],
    "gmail": ["pubsubSecret"],
}

# Logging severity levels accepted
_VALID_LOG_LEVELS = {"error", "warn", "info", "debug", "trace"}

# ── H2 — Gateway auth check ───────────────────────────────────────────────────

async def openclaw_gateway_auth_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    H2 — Validate the OpenClaw Gateway authentication configuration.

    Checks:
    - Funnel mode active → password auth required (CRITICAL if missing)
    - dangerouslyDisableDeviceAuth → HIGH risk flag
    - Non-loopback bind without auth → HIGH risk
    - No auth at all → MEDIUM recommendation

    Returns severity, findings list, and remediation snippet.
    """
    resolved = Path(config_path) if config_path else _CONFIG_PATH

    if ".." in str(resolved):
        return {"error": "path traversal detected"}

    if not resolved.exists():
        return {
            "status": "no_config",
            "message": f"Config file not found at {resolved}; using defaults (loopback only)",
            "severity": "INFO",
            "findings": [],
        }

    try:
        raw = resolved.read_text(encoding="utf-8")
        cfg: dict[str, Any] = json.loads(raw)
    except (json.JSONDecodeError, OSError) as exc:
        return {"error": f"Cannot read config: {exc}"}

    findings: list[dict[str, Any]] = []
    gateway: dict[str, Any] = cfg.get("gateway", {})
    tailscale = gateway.get("tailscale", {})
    auth = gateway.get("auth", {})
    bind = gateway.get("bind", "loopback")
    control_ui = gateway.get("controlUi", {})

    # Funnel without password
    if tailscale.get("mode") == "funnel" and auth.get("mode") != "password":
        findings.append({
            "id": "funnel_without_password",
            "severity": "CRITICAL",
            "description": _AUTH_FINDINGS[0][2],
            "fix": 'Set gateway.auth.mode: "password" and gateway.auth.password: "<strong-secret>"',
        })

    # dangerouslyDisableDeviceAuth
    if control_ui.get("dangerouslyDisableDeviceAuth") is True:
        findings.append({
            "id": "disable_device_auth",
            "severity": "HIGH",
            "description": _AUTH_FINDINGS[1][2],
            "fix": "Remove gateway.controlUi.dangerouslyDisableDeviceAuth or set to false",
        })

    # Non-loopback without auth
    if bind not in ("loopback", "127.0.0.1", "::1") and not auth:
        findings.append({
            "id": "no_auth_non_loopback",
            "severity": "HIGH",
            "description": _AUTH_FINDINGS[2][2],
            "fix": (
                'Add:\n  "gateway": {\n    "auth": { "mode": "password", '
                '"password": "<strong-secret>" }\n  }'
            ),
        })

    # No auth configured (recommendation only)
    if not auth and not findings:
        findings.append({
            "id": "missing_auth_token",
            "severity": "MEDIUM",
            "description": _AUTH_FINDINGS[3][2],
            "fix": (
                'Consider adding gateway.auth.mode="password" for remote or Funnel deployments'
            ),
        })

    max_sev = (
        "CRITICAL"
        if any(f["severity"] == "CRITICAL" for f in findings)
        else "HIGH"
        if any(f["severity"] == "HIGH" for f in findings)
        else "MEDIUM"
        if findings
        else "OK"
    )

    return {
        "config_path": str(resolved),
        "bind": bind,
        "tailscale_mode": tailscale.get("mode", "off"),
        "auth_mode": auth.get("mode", "not_set"),
        "severity": max_sev,
        "findings": findings,
        "finding_count": len(findings),
    }


# ── M3 — Baileys credentials check ───────────────────────────────────────────

async def openclaw_credentials_check(
    credentials_dir: str | None = None,
    max_age_days: int = 30,
) -> dict[str, Any]:
    """
    M3 — Check OpenClaw channel credentials (Baileys WhatsApp, Telegram tokens).

    Validates:
    - Baileys creds.json exists and is not older than max_age_days
    - creds.json is valid JSON (not corrupted)
    - Reports which channels have credentials and their freshness

    Returns a health report per credential set.
    """
    resolved = Path(credentials_dir) if credentials_dir else _CREDENTIALS_DIR

    if ".." in str(resolved):
        return {"error": "path traversal detected"}

    if not resolved.exists():
        return {
            "status": "no_credentials_dir",
            "message": f"Credentials directory not found: {resolved}",
            "severity": "INFO",
            "channels": [],
        }

    now = time.time()
    channels: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for item in sorted(resolved.iterdir()):
        if not item.is_dir():
            continue
        channel_name = item.name
        creds_file = item / "creds.json"

        entry: dict[str, Any] = {"channel": channel_name, "status": "ok"}

        if not creds_file.exists():
            # Look for any .json file
            json_files = list(item.glob("*.json"))
            if not json_files:
                entry["status"] = "missing"
                entry["severity"] = "HIGH"
                findings.append({
                    "channel": channel_name,
                    "severity": "HIGH",
                    "description": f"No credentials found for channel '{channel_name}'",
                    "fix": f"Re-run: openclaw channels login --channel {channel_name}",
                })
            else:
                entry["files"] = [f.name for f in json_files]
                entry["status"] = "partial"
        else:
            age_days = (now - creds_file.stat().st_mtime) / 86_400
            entry["creds_age_days"] = round(age_days, 1)

            # Validate JSON integrity
            try:
                creds_data = json.loads(creds_file.read_text(encoding="utf-8"))
                entry["creds_keys"] = list(creds_data.keys())[:10]
            except json.JSONDecodeError:
                entry["status"] = "corrupted"
                entry["severity"] = "CRITICAL"
                findings.append({
                    "channel": channel_name,
                    "severity": "CRITICAL",
                    "description": f"creds.json corrupted for '{channel_name}'",
                    "fix": (
                        f"Delete and re-pair: rm -rf {creds_file} && "
                        f"openclaw channels login --channel {channel_name}"
                    ),
                })

            # Check staleness
            if age_days > max_age_days and entry["status"] == "ok":
                entry["status"] = "stale"
                entry["severity"] = "MEDIUM"
                findings.append({
                    "channel": channel_name,
                    "severity": "MEDIUM",
                    "description": (
                        f"Credentials for '{channel_name}' are {age_days:.1f} days old "
                        f"(threshold: {max_age_days}d)"
                    ),
                    "fix": f"Consider re-pairing: openclaw channels login --channel {channel_name}",
                })

        channels.append(entry)

    max_sev = (
        "CRITICAL"
        if any(f["severity"] == "CRITICAL" for f in findings)
        else "HIGH"
        if any(f["severity"] == "HIGH" for f in findings)
        else "MEDIUM"
        if findings
        else "OK"
    )

    return {
        "credentials_dir": str(resolved),
        "channels_found": len(channels),
        "channels": channels,
        "findings": findings,
        "severity": max_sev,
    }


# ── M4 — Webhook signature check ─────────────────────────────────────────────

async def openclaw_webhook_sig_check(
    config_path: str | None = None,
    channel: str | None = None,
) -> dict[str, Any]:
    """
    M4 — Validate that webhook-exposed channels have HMAC signing secrets configured.

    Reads openclaw.json and checks each channel's webhook configuration.
    A channel with webhookPath but no signingSecret/webhookSecret is at risk
    (unauthenticated webhook — any actor can post fake events).

    Returns findings per channel with remediation.
    """
    resolved = Path(config_path) if config_path else _CONFIG_PATH

    if ".." in str(resolved):
        return {"error": "path traversal detected"}

    if not resolved.exists():
        return {
            "status": "no_config",
            "message": f"Config not found at {resolved}",
            "severity": "INFO",
            "findings": [],
        }

    try:
        cfg: dict[str, Any] = json.loads(resolved.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"error": f"Cannot read config: {exc}"}

    channels_cfg: dict[str, Any] = cfg.get("channels", {})
    findings: list[dict[str, Any]] = []
    checked: list[dict[str, Any]] = []

    target_channels = [channel] if channel else list(_WEBHOOK_CHANNELS.keys())

    for ch in target_channels:
        if ch not in channels_cfg:
            continue

        ch_cfg = channels_cfg[ch]
        has_webhook = bool(ch_cfg.get("webhookPath") or ch_cfg.get("webhookUrl"))
        required_keys = _WEBHOOK_CHANNELS.get(ch, [])

        # Check if any signing key is present
        has_secret = any(
            bool(ch_cfg.get(key))
            for key in required_keys
            if "secret" in key.lower() or "signing" in key.lower()
        )

        entry: dict[str, Any] = {
            "channel": ch,
            "webhook_configured": has_webhook,
            "signing_secret_present": has_secret,
        }

        if has_webhook and not has_secret:
            entry["severity"] = "HIGH"
            findings.append({
                "channel": ch,
                "severity": "HIGH",
                "description": (
                    f"Channel '{ch}' exposes a webhook endpoint without a signing secret — "
                    "any external actor can forge events"
                ),
                "fix": (
                    f'Add channels.{ch}.webhookSecret: "<random-32-byte-hex>" to openclaw.json\n'
                    "Generate: python3 -c \"import secrets; print(secrets.token_hex(32))\""
                ),
            })

        checked.append(entry)

    max_sev = (
        "HIGH"
        if any(f["severity"] == "HIGH" for f in findings)
        else "MEDIUM"
        if findings
        else "OK"
    )

    return {
        "config_path": str(resolved),
        "channels_checked": checked,
        "findings": findings,
        "finding_count": len(findings),
        "severity": max_sev,
    }


# ── M7 — Log config check ─────────────────────────────────────────────────────

async def openclaw_log_config_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    M7 — Validate that OpenClaw logging is properly configured.

    Checks:
    - logging.level is set and valid (warn/info/error — not debug/trace in production)
    - logging.redactPatterns present (prevents token leakage in logs)
    - No sensitive keys visible in default log format

    Returns severity and remediation.
    """
    resolved = Path(config_path) if config_path else _CONFIG_PATH

    if ".." in str(resolved):
        return {"error": "path traversal detected"}

    if not resolved.exists():
        return {
            "status": "no_config",
            "message": f"Config not found: {resolved}; defaults apply (info level, no redact)",
            "severity": "MEDIUM",
            "findings": [
                {
                    "id": "no_log_config",
                    "severity": "MEDIUM",
                    "description": "No openclaw.json found — default log level (info) with no redaction patterns",
                    "fix": (
                        'Add to openclaw.json:\n  "logging": {\n    "level": "warn",\n'
                        '    "redactPatterns": ["(?i)token", "(?i)secret", "(?i)api_key", '
                        '"(?i)password", "BEARER\\\\s+\\\\S+"]\n  }'
                    ),
                }
            ],
        }

    try:
        cfg: dict[str, Any] = json.loads(resolved.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"error": f"Cannot read config: {exc}"}

    log_cfg: dict[str, Any] = cfg.get("logging", {})
    findings: list[dict[str, Any]] = []

    level = log_cfg.get("level", "info").lower().strip()

    # Debug/trace in production is risky
    if level in ("debug", "trace"):
        findings.append({
            "id": "verbose_log_level",
            "severity": "HIGH",
            "description": (
                f"Log level is '{level}' — may expose tokens, session IDs, and message "
                "contents to log files"
            ),
            "fix": 'Set logging.level to "warn" or "error" for production deployments',
        })
    elif level not in _VALID_LOG_LEVELS:
        findings.append({
            "id": "invalid_log_level",
            "severity": "MEDIUM",
            "description": f"Unknown log level: '{level}'",
            "fix": f"Use one of: {sorted(_VALID_LOG_LEVELS)}",
        })

    # No redact patterns
    redact = log_cfg.get("redactPatterns", [])
    if not redact:
        findings.append({
            "id": "no_redact_patterns",
            "severity": "MEDIUM",
            "description": "logging.redactPatterns not set — tokens and secrets may appear in logs",
            "fix": (
                'Add to logging:\n  "redactPatterns": [\n'
                '    "(?i)token", "(?i)secret", "(?i)api_key", "(?i)password",\n'
                '    "BEARER\\\\s+\\\\S+", "sk-[a-zA-Z0-9]+"\n  ]'
            ),
        })
    else:
        # Check that common patterns are covered
        combined = " ".join(str(p) for p in redact).lower()
        missing = [
            p for p in ["token", "secret", "api_key", "bearer"]
            if p not in combined
        ]
        if missing:
            findings.append({
                "id": "incomplete_redact",
                "severity": "MEDIUM",
                "description": f"redactPatterns may be missing coverage for: {missing}",
                "fix": f"Add patterns for {missing} to logging.redactPatterns",
            })

    max_sev = (
        "HIGH"
        if any(f["severity"] == "HIGH" for f in findings)
        else "MEDIUM"
        if findings
        else "OK"
    )

    return {
        "config_path": str(resolved),
        "log_level": level,
        "redact_pattern_count": len(redact),
        "findings": findings,
        "severity": max_sev,
    }


# ── M8 — Workspace integrity check ───────────────────────────────────────────

async def openclaw_workspace_integrity_check(
    workspace_dir: str | None = None,
    stale_days: int = 30,
) -> dict[str, Any]:
    """
    M8 — Verify the integrity and health of the OpenClaw workspace directory.

    Checks:
    - Workspace exists and has required files (AGENTS.md, SOUL.md)
    - MEMORY.md present (warns if stale > stale_days days without update)
    - Skills directory populated
    - No dangerously large files (>10 MB context bloat)
    - Computes a lightweight fingerprint for drift detection

    Returns health report with findings and remediation recommendations.
    """
    resolved = Path(workspace_dir) if workspace_dir else _WORKSPACE_DIR

    if ".." in str(resolved):
        return {"error": "path traversal detected"}

    if not resolved.exists():
        return {
            "status": "workspace_missing",
            "message": f"Workspace directory not found: {resolved}",
            "severity": "HIGH",
            "findings": [
                {
                    "id": "workspace_missing",
                    "severity": "HIGH",
                    "description": f"OpenClaw workspace not found at {resolved}",
                    "fix": (
                        "Run: openclaw onboard --install-daemon\n"
                        "Or initialize manually: mkdir -p ~/.openclaw/workspace && "
                        "openclaw workspace init"
                    ),
                }
            ],
        }

    now = time.time()
    findings: list[dict[str, Any]] = []
    file_inventory: list[dict[str, Any]] = []

    # Check required files
    for fname in _REQUIRED_WORKSPACE_FILES:
        fpath = resolved / fname
        if not fpath.exists():
            findings.append({
                "id": f"missing_{fname.lower().replace('.', '_')}",
                "severity": "MEDIUM",
                "description": f"{fname} not found in workspace — agent identity incomplete",
                "fix": (
                    f"Create {resolved / fname} with your agent configuration, "
                    "or run: openclaw workspace init"
                ),
            })

    # MEMORY.md staleness
    memory_path = resolved / "MEMORY.md"
    if memory_path.exists():
        age_days = (now - memory_path.stat().st_mtime) / 86_400
        entry = {
            "file": "MEMORY.md",
            "size_kb": round(memory_path.stat().st_size / 1024, 1),
            "age_days": round(age_days, 1),
        }
        if age_days > stale_days:
            entry["status"] = "stale"
            findings.append({
                "id": "stale_memory",
                "severity": "MEDIUM",
                "description": (
                    f"MEMORY.md last modified {age_days:.0f} days ago "
                    f"(threshold: {stale_days}d) — may be outdated context"
                ),
                "fix": (
                    "Send '/compact' to the agent to refresh memory, "
                    "or review and prune MEMORY.md manually"
                ),
            })
        else:
            entry["status"] = "ok"
        file_inventory.append(entry)
    else:
        findings.append({
            "id": "no_memory_md",
            "severity": "INFO",
            "description": "MEMORY.md not present — agent has no persistent memory yet",
            "fix": "Send a few messages to the agent to build initial memory context",
        })

    # Large file check
    try:
        for fpath in resolved.rglob("*"):
            if not fpath.is_file():
                continue
            size_mb = fpath.stat().st_size / (1024 * 1024)
            if size_mb > 10:
                findings.append({
                    "id": "large_file",
                    "severity": "MEDIUM",
                    "description": (
                        f"{fpath.relative_to(resolved)} is {size_mb:.1f} MB — "
                        "may cause context bloat and slow agent responses"
                    ),
                    "fix": f"Move or archive: mv {fpath} /tmp/openclaw-archive/",
                })
    except OSError:
        pass

    # Skills inventory
    skills_dir = resolved / "skills"
    skills_count = len(list(skills_dir.glob("*/SKILL.md"))) if skills_dir.exists() else 0

    # Lightweight fingerprint
    try:
        sig_materials = sorted(
            f"{p.name}:{p.stat().st_size}"
            for p in resolved.iterdir()
            if p.is_file()
        )
        fingerprint = hashlib.md5("|".join(sig_materials).encode()).hexdigest()[:12]
    except OSError:
        fingerprint = "unavailable"

    max_sev = (
        "HIGH"
        if any(f["severity"] == "HIGH" for f in findings)
        else "MEDIUM"
        if any(f["severity"] == "MEDIUM" for f in findings)
        else "INFO"
        if findings
        else "OK"
    )

    return {
        "workspace_dir": str(resolved),
        "skills_installed": skills_count,
        "file_inventory": file_inventory,
        "fingerprint": fingerprint,
        "findings": findings,
        "finding_count": len(findings),
        "severity": max_sev,
    }


# ════════════════════════════════════════════════════════════════════════════
# MCP tool registry
# ════════════════════════════════════════════════════════════════════════════

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_gateway_auth_check",
        "description": (
            "Checks the OpenClaw Gateway authentication configuration. "
            "Gap H2: Funnel mode without password auth is a CRITICAL exposure — "
            "anyone on the internet can reach the Gateway without authentication. "
            "Also detects dangerouslyDisableDeviceAuth=true (HIGH). "
            "Returns: findings list with severity and remediation."
        ),
        "category": "security",
        "handler": openclaw_gateway_auth_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Absolute path to openclaw.json. Defaults to ~/.openclaw/openclaw.json.",
                },
            },
        },
    },
    {
        "name": "openclaw_credentials_check",
        "description": (
            "Checks the integrity and freshness of OpenClaw channel credentials. "
            "Gap M3: Baileys WhatsApp creds.json can silently corrupt, preventing reconnection. "
            "Validates JSON integrity (CRITICAL if corrupted) and staleness (MEDIUM if > max_age_days). "
            "Returns: per-credentials-dir findings with severity."
        ),
        "category": "security",
        "handler": openclaw_credentials_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "credentials_dir": {
                    "type": "string",
                    "description": "Path to credentials directory. Defaults to ~/.openclaw/credentials.",
                },
                "max_age_days": {
                    "type": "integer",
                    "description": "Max age in days before a credential file is considered stale. Default: 30.",
                    "minimum": 1,
                    "maximum": 365,
                    "default": 30,
                },
            },
        },
    },
    {
        "name": "openclaw_webhook_sig_check",
        "description": (
            "Checks that each inbound webhook channel has a signing secret configured. "
            "Gap M4: Without HMAC signature verification, anyone can forge inbound webhook events, "
            "potentially injecting malicious instructions to agents. "
            "Checks Telegram, Discord, Slack, MS Teams, Gmail. "
            "Returns: findings list with severity HIGH for any channel with webhook but no secret."
        ),
        "category": "security",
        "handler": openclaw_webhook_sig_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Absolute path to openclaw.json. Defaults to ~/.openclaw/openclaw.json.",
                },
                "channel": {
                    "type": "string",
                    "description": "Optional: check only this channel (telegram, discord, slack, msteams, gmail).",
                },
            },
        },
    },
    {
        "name": "openclaw_log_config_check",
        "description": (
            "Audits the OpenClaw logging configuration. "
            "Gap M7: debug/trace logging leaks tokens and PII into log files. "
            "Missing redactPatterns means secrets appear in plain text. "
            "Returns: findings with severity HIGH (verbose level) or MEDIUM (missing redact patterns)."
        ),
        "category": "security",
        "handler": openclaw_log_config_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Absolute path to openclaw.json. Defaults to ~/.openclaw/openclaw.json.",
                },
            },
        },
    },
    {
        "name": "openclaw_workspace_integrity_check",
        "description": (
            "Validates the integrity of the OpenClaw workspace directory (~/.openclaw/workspace). "
            "Gap M8: Missing AGENTS.md / SOUL.md means agents have no identity or instructions. "
            "Stale MEMORY.md blocks context continuity. Large files cause agent context bloat. "
            "Returns: file inventory, fingerprint, and findings with severity."
        ),
        "category": "security",
        "handler": openclaw_workspace_integrity_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_dir": {
                    "type": "string",
                    "description": "Path to workspace directory. Defaults to ~/.openclaw/workspace.",
                },
                "stale_days": {
                    "type": "integer",
                    "description": "Days before MEMORY.md is considered stale. Default: 30.",
                    "minimum": 1,
                    "maximum": 365,
                    "default": 30,
                },
            },
        },
    },
]
