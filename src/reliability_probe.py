"""
reliability_probe.py — Firm reliability, documentation & architecture tools

Comble les gaps identifiés dans the server :
  H6  — Gateway/browser indisponible après sleep/wake macOS
  H7  — macOS LaunchAgent WS close 1006 intermittent
  M1  — @line/bot-sdk en deps, zéro doc (canaux zombies)
  M5  — docs.acp.md SDK version stale (0.13.x vs 0.14.1 réel)
  M6  — Aucun ADR (Architecture Decision Record) dans le repo

Tools exposed:
  firm_gateway_probe   — teste la connectivité Gateway avec backoff exponentiel
  firm_doc_sync_check  — compare versions deps package.json vs docs
  firm_channel_audit   — détecte les canaux channel non documentés (canaux zombies)
  firm_adr_generate        — génère un ADR structuré (format MADR)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Gateway probe with reconnect backoff (H6, H7) ────────────────────────────

_LAUNCHCTL_RESTART_CMD = (
    "launchctl kickstart -k gui/$(id -u)/com.firm.gateway\n"
    "# If that fails:\n"
    "launchctl stop com.firm.gateway && launchctl start com.firm.gateway"
)

_WS_1006_EXPLAIN = (
    "WebSocket close code 1006 = abnormal closure (no close frame sent). "
    "Common causes: network interface went down (sleep/wake), process was killed, "
    "or the LaunchAgent watchdog loop crashed. "
    "Fix: restart the LaunchAgent with the command provided."
)

_SLEEP_WAKE_FIX = (
    "After macOS sleep/wake, the Gateway WS port may become unreachable. "
    "The LaunchAgent should auto-restart, but if it doesn't:\n"
    "1. Run: launchctl kickstart -k gui/$(id -u)/com.firm.gateway\n"
    "2. Wait 3s, retry connection\n"
    "3. If still failing, check: tail -f ~/Library/Logs/firm/gateway.log"
)

# ── Health endpoints (2026.3.1) ──────────────────────────────────────────────

_HEALTH_ENDPOINTS = ["/health", "/healthz", "/ready", "/readyz"]


async def _check_health_endpoints(gateway_url: str) -> dict[str, Any]:
    """Check HTTP liveness/readiness endpoints added in 2026.3.1."""
    import aiohttp

    # Convert ws:// to http://
    http_base = gateway_url.replace("ws://", "http://").replace("wss://", "https://")
    # Strip path component
    if "/" in http_base.split("//", 1)[-1]:
        http_base = http_base.rsplit("/", 1)[0]

    results: dict[str, Any] = {}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            for ep in _HEALTH_ENDPOINTS:
                url = f"{http_base}{ep}"
                try:
                    async with session.get(url) as resp:
                        results[ep] = {
                            "status": resp.status,
                            "ok": resp.status in (200, 204),
                        }
                except Exception as exc:
                    results[ep] = {"status": None, "ok": False, "error": str(exc)}
    except Exception as exc:
        for ep in _HEALTH_ENDPOINTS:
            results[ep] = {"status": None, "ok": False, "error": str(exc)}

    results["all_ok"] = all(r.get("ok", False) for r in results.values() if isinstance(r, dict))
    if not results["all_ok"]:
        results["recommendation"] = (
            "2026.3.1 added built-in HTTP health endpoints (/health, /healthz, /ready, /readyz) "
            "for Docker/K8s. Missing endpoints indicate gateway version <2026.3.1 or "
            "custom handler shadowing. Upgrade and verify container health probes."
        )
    return results


async def firm_gateway_probe(
    gateway_url: str = "ws://127.0.0.1:18789",
    max_retries: int = 3,
    backoff_factor: float = 1.0,
    check_health_endpoints: bool = True,
) -> dict[str, Any]:
    """
    Tests Gateway WebSocket connectivity with exponential backoff.

    Addresses gaps H6 (sleep/wake instability) and H7 (LaunchAgent WS 1006).
    Attempts reconnection with configurable backoff before reporting failure.
    If WS 1006 detected, provides the exact launchctl restart command.

    Since 2026.3.1: Also checks HTTP liveness/readiness endpoints
    (/health, /healthz, /ready, /readyz) for Docker/K8s health checks.

    Args:
        gateway_url: Gateway WebSocket URL. Default: ws://127.0.0.1:18789.
        max_retries: Number of reconnection attempts (1-5). Default: 3.
        backoff_factor: Base seconds between retries (doubles each attempt). Default: 1.0.
        check_health_endpoints: Also check HTTP health/ready endpoints. Default: True.

    Returns:
        dict with keys: ok, status, latency_ms, attempts, close_code,
                        action_required, restart_command, health_endpoints.
    """
    try:
        import websockets  # noqa: F401
        from websockets.exceptions import WebSocketException  # noqa: F401
    except ImportError:
        return {
            "ok": False,
            "error": "websockets package not available — run: pip install websockets",
        }

    attempts: list[dict[str, Any]] = []
    close_code: int | None = None

    for attempt_num in range(1, max_retries + 1):
        start = time.time()
        try:
            async with websockets.connect(
                gateway_url,
                open_timeout=5,
                close_timeout=3,
            ) as ws:
                # Send a minimal ping-style message
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}))
                await asyncio.wait_for(ws.recv(), timeout=5)
                latency_ms = round((time.time() - start) * 1000, 1)
                attempts.append({"attempt": attempt_num, "status": "ok", "latency_ms": latency_ms})

                # 2026.3.1: Check HTTP health endpoints if enabled
                health_endpoints: dict[str, Any] = {}
                if check_health_endpoints:
                    health_endpoints = await _check_health_endpoints(gateway_url)

                return {
                    "ok": True,
                    "status": "connected",
                    "latency_ms": latency_ms,
                    "attempts": attempts,
                    "close_code": None,
                    "action_required": None,
                    "health_endpoints": health_endpoints,
                }
        except OSError as exc:
            latency_ms = round((time.time() - start) * 1000, 1)
            attempts.append({"attempt": attempt_num, "status": "unreachable", "error": str(exc), "latency_ms": latency_ms})
            close_code = None
        except Exception as exc:
            latency_ms = round((time.time() - start) * 1000, 1)
            err_str = str(exc)
            # Detect WS 1006 (abnormal closure)
            if "1006" in err_str or "abnormal" in err_str.lower():
                close_code = 1006
                attempts.append({"attempt": attempt_num, "status": "ws_1006", "error": err_str, "latency_ms": latency_ms})
            else:
                attempts.append({"attempt": attempt_num, "status": "error", "error": err_str, "latency_ms": latency_ms})

        if attempt_num < max_retries:
            wait = backoff_factor * (2 ** (attempt_num - 1))
            logger.info("Gateway probe attempt %d failed, retrying in %.1fs…", attempt_num, wait)
            await asyncio.sleep(wait)

    # All attempts failed
    action: str
    if close_code == 1006:
        action = "WS 1006 detected (abnormal closure — likely sleep/wake or LaunchAgent crash)"
        restart_cmd = _LAUNCHCTL_RESTART_CMD
        explain = _WS_1006_EXPLAIN
    else:
        action = "Gateway unreachable after all retries — check if Firm is running"
        restart_cmd = _LAUNCHCTL_RESTART_CMD
        explain = _SLEEP_WAKE_FIX

    return {
        "ok": False,
        "status": "unreachable",
        "latency_ms": None,
        "attempts": attempts,
        "close_code": close_code,
        "action_required": action,
        "explanation": explain,
        "restart_command": restart_cmd,
        "log_check": "tail -f ~/Library/Logs/firm/gateway.log",
        "issue_refs": ["#29883 (LaunchAgent WS 1006)", "#29884 (sleep/wake instability)"],
    }


# ── Doc sync check (M5) ───────────────────────────────────────────────────────

_HIGH_RISK_DEPS = {"@agentclientprotocol/sdk", "@buape/carbon", "baileys", "@line/bot-sdk"}


async def firm_doc_sync_check(
    package_json_path: str,
    docs_glob: str = "**/*.md",
) -> dict[str, Any]:
    """
    Compares dependency versions in package.json against versions documented in .md files.

    Addresses gap M5: docs.acp.md states ACP SDK '0.13.x' but package.json has '0.14.1'.
    Catches documentation drift before it confuses contributors and users.

    Args:
        package_json_path: Path to package.json.
        docs_glob: Glob for markdown files to search for version references. Default: '**/*.md'.

    Returns:
        dict with keys: ok, desynced, total_checked, findings, high_risk_desynced.
    """
    p = Path(package_json_path)
    if not p.exists():
        return {"ok": False, "error": f"package.json not found: {package_json_path}"}

    try:
        pkg = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"ok": False, "error": f"Failed to parse package.json: {exc}"}

    all_deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        all_deps.update(pkg.get(section, {}))

    if not all_deps:
        return {"ok": True, "desynced": 0, "total_checked": 0, "findings": []}

    # Find all markdown files
    base = p.parent
    md_files: list[Path] = list(base.glob(docs_glob))
    if not md_files:
        return {
            "ok": True,
            "desynced": 0,
            "total_checked": 0,
            "findings": [],
            "note": f"No markdown files found matching {docs_glob} from {base}",
        }

    # Aggregate all markdown content
    all_md = ""
    for mdf in md_files:
        try:
            all_md += mdf.read_text(encoding="utf-8", errors="ignore") + "\n"
        except Exception:
            pass

    findings: list[dict[str, Any]] = []

    for dep_name, dep_version in all_deps.items():
        # Normalize version (strip ^~>=)
        clean_version = re.sub(r"^[\^~>=<]+", "", dep_version).strip()
        if not clean_version or clean_version in ("*", "latest"):
            continue

        # Build short name for searching (e.g. @agentclientprotocol/sdk → agentclientprotocol/sdk)
        short_name = dep_name.lstrip("@")

        # Look for mentions in docs
        pattern = rf"{re.escape(short_name)}[^`\n]{{0,30}}{re.escape(clean_version[:4])}"
        found_match = bool(re.search(pattern, all_md, re.IGNORECASE))

        # Also look for older version patterns
        ".".join(clean_version.split(".")[:2])
        prev_pattern = rf"{re.escape(short_name)}[^`\n]{{0,30}}0\.1[0-3]"
        found_old = bool(re.search(prev_pattern, all_md, re.IGNORECASE))

        if found_old and not found_match:
            findings.append({
                "dependency": dep_name,
                "version_in_code": dep_version,
                "version_in_docs": "older version found (likely stale)",
                "severity": "HIGH" if dep_name in _HIGH_RISK_DEPS else "MEDIUM",
                "note": f"Docs reference an older version of {dep_name}. Update docs to {dep_version}.",
            })

    high_risk = [f for f in findings if f["severity"] == "HIGH"]

    return {
        "ok": True,
        "desynced": len(findings),
        "total_checked": len(all_deps),
        "high_risk_desynced": len(high_risk),
        "findings": findings,
        "issue_ref": "M5 — docs.acp.md SDK version stale (0.13.x vs 0.14.1 in package.json)",
    }


# ── Channel audit (M1) ────────────────────────────────────────────────────────

# Known channel SDK package names → human-readable channel names
_CHANNEL_PACKAGES: dict[str, str] = {
    "baileys": "WhatsApp (Baileys)",
    "grammy": "Telegram (grammY)",
    "@slack/bolt": "Slack",
    "discord.js": "Discord",
    "@buape/carbon": "Discord (Carbon)",
    "signal-cli": "Signal",
    "@larksuiteoapi/node-sdk": "Feishu/Lark",
    "@line/bot-sdk": "LINE",
    "matrix-js-sdk": "Matrix",
    "botframework-connector": "Microsoft Teams",
    "@microsoft/teams-js": "Microsoft Teams",
}

_DOCUMENTED_CHANNELS = {
    "whatsapp", "telegram", "slack", "discord", "signal", "feishu", "lark",
    "imessage", "bluebubbles", "matrix", "teams", "google chat", "zalo",
}


async def firm_channel_audit(
    package_json_path: str,
    readme_path: str,
) -> dict[str, Any]:
    """
    Detects channel SDK dependencies that are present in package.json but
    undocumented in the README — 'zombie dependencies'.

    Addresses gap M1: @line/bot-sdk is in package.json but LINE has zero
    documentation, zero tests, and no README mention.

    Args:
        package_json_path: Path to package.json.
        readme_path: Path to README.md.

    Returns:
        dict with keys: ok, zombie_deps, documented_channels,
                        code_channels, missing_in_docs, missing_in_code.
    """
    pp = Path(package_json_path)
    rp = Path(readme_path)

    if not pp.exists():
        return {"ok": False, "error": f"package.json not found: {package_json_path}"}
    if not rp.exists():
        return {"ok": False, "error": f"README not found: {readme_path}"}

    try:
        pkg = json.loads(pp.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"ok": False, "error": f"Failed to parse package.json: {exc}"}

    readme_content = rp.read_text(encoding="utf-8", errors="ignore").lower()

    all_deps: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        all_deps.update(pkg.get(section, {}).keys())

    # Find channel packages present in deps
    code_channels: dict[str, str] = {}
    for pkg_name, channel_name in _CHANNEL_PACKAGES.items():
        if pkg_name in all_deps:
            code_channels[pkg_name] = channel_name

    # Check README documentation
    zombie_deps: list[dict[str, str]] = []
    for pkg_name, channel_name in code_channels.items():
        channel_lower = channel_name.lower()
        # Check if any word from the channel name appears in README
        channel_words = [w for w in channel_lower.split() if len(w) > 3]
        documented = any(w in readme_content for w in channel_words)
        if not documented:
            zombie_deps.append({
                "package": pkg_name,
                "channel": channel_name,
                "severity": "MEDIUM",
                "finding": (
                    f"{pkg_name} ({channel_name}) is in package.json "
                    f"but has no mention in README. "
                    f"Either document it or remove the dependency."
                ),
            })

    # ── 2026.3.1: Discord thread lifecycle check ──────────────────────────────
    discord_lifecycle: list[dict[str, str]] = []
    discord_cfg = pkg.get("firm", {}).get("channels", {}).get("discord", {})
    if "discord.js" in all_deps or "@buape/carbon" in all_deps:
        idle_hours = discord_cfg.get("threads", {}).get("idleHours")
        max_age_hours = discord_cfg.get("threads", {}).get("maxAgeHours")
        if idle_hours is None:
            discord_lifecycle.append({
                "finding": "discord.threads.idleHours not set",
                "severity": "MEDIUM",
                "detail": (
                    "2026.3.1 added automatic Discord thread archival. "
                    "Set threads.idleHours (e.g. 24) to auto-archive idle threads."
                ),
            })
        if max_age_hours is None:
            discord_lifecycle.append({
                "finding": "discord.threads.maxAgeHours not set",
                "severity": "MEDIUM",
                "detail": (
                    "2026.3.1 added Discord thread max age management. "
                    "Set threads.maxAgeHours (e.g. 168 = 7 days) to limit thread lifespan."
                ),
            })

    return {
        "ok": True,
        "zombie_deps": len(zombie_deps),
        "code_channels": list(code_channels.values()),
        "zombie_details": zombie_deps,
        "discord_thread_lifecycle": discord_lifecycle,
        "total_channel_packages_detected": len(code_channels),
        "issue_ref": "M1 — @line/bot-sdk in deps, zero documentation",
        "⚠️": "Contenu généré par IA — vérification manuelle recommandée.",
    }


# ── ADR generator (M6) ────────────────────────────────────────────────────────

_ADR_TEMPLATE = """\
# {adr_id}. {title}

Date: {date}
Status: {status}

## Context

{context}

## Decision

{decision}

## Alternatives Considered

{alternatives}

## Consequences

{consequences}

---
> ⚠️ Generated by AI — human review required before committing to docs/decisions/.
"""


async def firm_adr_generate(
    title: str,
    context: str,
    decision: str,
    alternatives: list[str],
    consequences: list[str],
    status: str = "proposed",
    adr_id: str | None = None,
) -> dict[str, Any]:
    """
    Generates a structured Architecture Decision Record (ADR) in MADR format.

    Addresses gap M6: no ADRs document major Firm design choices (MCP-via-mcporter,
    Carbon frozen, Baileys vs WhatsApp Cloud API, dual iMessage path).

    Args:
        title: Short decision title (e.g. 'Use mcporter for MCP instead of native support').
        context: Problem context and forces at play.
        decision: The decision that was made.
        alternatives: List of alternatives that were considered.
        consequences: Positive and negative consequences.
        status: One of 'proposed', 'accepted', 'deprecated'. Default: 'proposed'.
        adr_id: Optional ADR number (e.g. 'ADR-0001'). Auto-generated if not provided.

    Returns:
        dict with keys: ok, adr_id, title, status, markdown, commit_path.
    """
    import datetime

    valid_statuses = ("proposed", "accepted", "deprecated", "superseded")
    if status not in valid_statuses:
        return {
            "ok": False,
            "error": f"status must be one of {valid_statuses}. Got: {status!r}",
        }

    generated_id = adr_id or f"ADR-{int(time.time()) % 10000:04d}"
    today = datetime.date.today().isoformat()

    # Format alternatives as markdown list
    alts_md = "\n".join(f"- {a}" for a in alternatives) if alternatives else "- None documented"
    # Format consequences as markdown list
    cons_md = "\n".join(f"- {c}" for c in consequences) if consequences else "- None documented"

    markdown = _ADR_TEMPLATE.format(
        adr_id=generated_id,
        title=title,
        date=today,
        status=status,
        context=context.strip(),
        decision=decision.strip(),
        alternatives=alts_md,
        consequences=cons_md,
    )

    # Suggest commit path
    safe_title = re.sub(r"[^a-zA-Z0-9]+", "-", title.lower()).strip("-")[:60]
    commit_path = f"docs/decisions/{generated_id.lower()}-{safe_title}.md"

    return {
        "ok": True,
        "adr_id": generated_id,
        "title": title,
        "status": status,
        "markdown": markdown,
        "commit_path": commit_path,
        "commit_command": f"git add {commit_path} && git commit -m 'docs(adr): {generated_id} {title}'",
        "⚠️": "Contenu généré par IA — validation humaine requise avant commit.",
    }


# ── Tool registry ─────────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "firm_gateway_probe",
        "title": "Gateway Connectivity Probe",
        "description": (
            "Tests Gateway WebSocket connectivity with exponential backoff reconnection. "
            "Gaps H6+H7: Gateway unreachable after macOS sleep/wake, LaunchAgent WS 1006 closure. "
            "Returns: connection status, latency, close code, exact launchctl restart command."
        ),
        "category": "reliability",
        "handler": firm_gateway_probe,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "gateway_url": {
                    "type": "string",
                    "description": "Gateway WebSocket URL. Default: ws://127.0.0.1:18789.",
                    "default": "ws://127.0.0.1:18789",
                },
                "max_retries": {
                    "type": "integer",
                    "description": "Number of reconnection attempts (1-5). Default: 3.",
                    "minimum": 1,
                    "maximum": 5,
                    "default": 3,
                },
                "backoff_factor": {
                    "type": "number",
                    "description": "Base seconds between retries (doubles each attempt). Default: 1.0.",
                    "default": 1.0,
                },
                "check_health_endpoints": {
                    "type": "boolean",
                    "description": "Also probe /health, /healthz, /ready, /readyz HTTP endpoints (2026.3.1). Default: true.",
                    "default": True,
                },
            },
            "required": [],
        },
    },
    {
        "name": "firm_doc_sync_check",
        "title": "Doc Version Sync Check",
        "description": (
            "Compares dependency versions in package.json against versions referenced in markdown docs. "
            "Gap M5: docs.acp.md says ACP SDK '0.13.x' but package.json has '0.14.1'. "
            "Returns: desynced dependencies, severity (HIGH for ACP SDK/Carbon), update instructions."
        ),
        "category": "reliability",
        "handler": firm_doc_sync_check,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_json_path": {
                    "type": "string",
                    "description": "Path to package.json.",
                },
                "docs_glob": {
                    "type": "string",
                    "description": "Glob for markdown files to scan. Default: '**/*.md'.",
                    "default": "**/*.md",
                },
            },
            "required": ["package_json_path"],
        },
    },
    {
        "name": "firm_channel_audit",
        "title": "Channel SDK Audit",
        "description": (
            "Detects channel SDK packages present in package.json but absent from README (zombie dependencies). "
            "Gap M1: @line/bot-sdk is in deps but LINE has zero documentation — a maintenance liability "
            "for 75M+ users in JP/TH. Returns: zombie deps, channel coverage matrix."
        ),
        "category": "reliability",
        "handler": firm_channel_audit,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_json_path": {
                    "type": "string",
                    "description": "Path to package.json.",
                },
                "readme_path": {
                    "type": "string",
                    "description": "Path to README.md.",
                },
            },
            "required": ["package_json_path", "readme_path"],
        },
    },
    {
        "name": "firm_adr_generate",
        "title": "Generate ADR Document",
        "description": (
            "Generates a structured Architecture Decision Record (ADR) in MADR format. "
            "Gap M6: no ADRs exist for major Firm architectural choices "
            "(MCP-via-mcporter, Carbon frozen, Baileys, dual iMessage path). "
            "Returns: ADR markdown, suggested commit path and git command."
        ),
        "category": "reliability",
        "handler": firm_adr_generate,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short decision title."},
                "context": {"type": "string", "description": "Problem context and forces."},
                "decision": {"type": "string", "description": "The decision made."},
                "alternatives": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Alternatives considered.",
                },
                "consequences": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Positive and negative consequences.",
                },
                "status": {
                    "type": "string",
                    "enum": ["proposed", "accepted", "deprecated", "superseded"],
                    "description": "ADR status. Default: 'proposed'.",
                    "default": "proposed",
                },
                "adr_id": {
                    "type": "string",
                    "description": "Optional ADR ID (e.g. 'ADR-0001'). Auto-generated if omitted.",
                },
            },
            "required": ["title", "context", "decision", "alternatives", "consequences"],
        },
    },
]
