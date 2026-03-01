"""
security_audit.py — OpenClaw security audit & hardening tools

Comble les gaps critiques identifiés dans openclaw/openclaw :
  C1 — SQL injection dans /api/metrics/database
  C2 — sandbox.mode: off par défaut (RCE potentiel via prompt injection)
  C3 — express-session secret régénéré à chaque restart container
  H8 — Pas de rate limiting documenté sur le WS Gateway

Tools exposed:
  openclaw_security_scan         — détection SQL injection et patterns dangereux
  openclaw_sandbox_audit         — vérifie la config sandbox avant déploiement
  openclaw_session_config_check  — vérifie la persistance du session secret
  openclaw_rate_limit_check      — vérifie la présence d'un rate limiter devant le Gateway
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── SQL injection patterns (C1) ───────────────────────────────────────────────

_SQL_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (
        r"[\"'`]?\s*\+\s*\w+\s*\+\s*[\"'`]?",
        "String concatenation in query — use parameterized queries",
    ),
    (
        r"query\s*\(.*?\$\{",
        "Template literal in SQL query — injection risk",
    ),
    (
        r"\.query\s*\(\s*[\"'`][^\"'`]*\$\{",
        "Template literal interpolation inside .query() call",
    ),
    (
        r"raw\s*\(",
        "Raw SQL call detected — verify parameterization",
    ),
    (
        r"SELECT\s+\*\s+FROM\s+\S+\s+WHERE\s+\S+\s*=\s*['\"]?\s*\+",
        "WHERE clause with string concatenation",
    ),
    (
        r"exec\s*\(\s*[\"'`][^\"'`]*['\"`;]\s*\+",
        "exec() with concatenated string",
    ),
]

_SEVERITY_MAP = {
    "String concatenation in query": "HIGH",
    "Template literal in SQL query": "HIGH",
    "Template literal interpolation": "HIGH",
    "Raw SQL call detected": "MEDIUM",
    "WHERE clause with string concatenation": "CRITICAL",
    "exec() with concatenated string": "HIGH",
}

_REMEDIATION = {
    "HIGH": (
        "Replace string concatenation / template literals with parameterized queries.\n"
        "Example fix:\n"
        "  // Before (vulnerable)\n"
        "  db.query(`SELECT * FROM metrics WHERE id = ${userInput}`);\n"
        "  // After (safe)\n"
        "  db.query('SELECT * FROM metrics WHERE id = ?', [userInput]);"
    ),
    "CRITICAL": (
        "IMMEDIATE ACTION REQUIRED — parameterize this query.\n"
        "  db.query('SELECT * FROM metrics WHERE id = ?', [userInput]);\n"
        "Also review: input sanitization, WAF rules, least-privilege DB user."
    ),
    "MEDIUM": (
        "Audit all raw() calls and confirm parameterization is applied to every user-controlled value."
    ),
}


async def openclaw_security_scan(
    target_path: str,
    endpoint: str | None = None,
    scan_depth: int = 3,
) -> dict[str, Any]:
    """
    Scans source files for SQL injection and dangerous query patterns.

    Specifically targets the /api/metrics/database vulnerability (issue #29951).

    Args:
        target_path: Absolute path to file or directory to scan.
        endpoint: Optional endpoint name to highlight in report (e.g. '/api/metrics/database').
        scan_depth: Maximum directory recursion depth (1-5).

    Returns:
        dict with keys: ok, vulnerabilities, total_files_scanned, critical_count,
                        high_count, medium_count, remediation_by_severity.
    """
    path = Path(target_path)
    if not path.exists():
        return {"ok": False, "error": f"Path not found: {target_path}"}

    files_to_scan: list[Path] = []
    if path.is_file():
        files_to_scan = [path]
    else:
        for root, dirs, files in os.walk(path):
            depth = len(Path(root).relative_to(path).parts)
            if depth > scan_depth:
                dirs.clear()
                continue
            # Skip node_modules, .git, build dirs
            dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "dist", "build", ".next"}]
            for f in files:
                if f.endswith((".ts", ".js", ".mjs", ".cjs", ".py", ".sql")):
                    files_to_scan.append(Path(root) / f)

    vulnerabilities: list[dict[str, Any]] = []

    for file_path in files_to_scan:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            for pattern, description in _SQL_INJECTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = "HIGH"
                    for key, sev in _SEVERITY_MAP.items():
                        if key in description:
                            severity = sev
                            break

                    vuln: dict[str, Any] = {
                        "file": str(file_path),
                        "line": line_num,
                        "pattern": description,
                        "severity": severity,
                        "snippet": line.strip()[:200],
                    }
                    if endpoint and endpoint in str(file_path):
                        vuln["endpoint"] = endpoint
                        vuln["note"] = f"Matches reported issue #29951 for {endpoint}"
                    vulnerabilities.append(vuln)

    critical = sum(1 for v in vulnerabilities if v["severity"] == "CRITICAL")
    high = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
    medium = sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM")

    severities_found = set(v["severity"] for v in vulnerabilities)
    rem = {sev: _REMEDIATION[sev] for sev in severities_found if sev in _REMEDIATION}

    return {
        "ok": True,
        "⚠️": "Contenu généré par IA — validation par un expert sécurité requise.",
        "total_files_scanned": len(files_to_scan),
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "vulnerabilities": vulnerabilities,
        "remediation_by_severity": rem,
    }


# ── Sandbox audit (C2) ────────────────────────────────────────────────────────

_SANDBOX_FIX = """
# Fix: activer le sandbox sur les sessions non-main
# Dans config.yaml ou config.json OpenClaw :

agents:
  defaults:
    sandbox:
      mode: non-main       # ← était 'off', exposait l'hôte à toute session
      tools:
        allow: []          # denylist vide = tout autorisé dans sandbox
        deny:
          - bash.exec
          - file.write
  sessions:
    main:
      sandbox:
        mode: off          # main session conserve l'accès hôte (intentionnel)
"""

_SANDBOX_EXPLAIN = (
    "Avec sandbox.mode: off (défaut), toute session agent a accès au shell hôte complet. "
    "Un prompt injection sur n'importe quelle session = RCE sur la machine. "
    "Fix: passer non-main sessions en sandbox Docker (mode: non-main)."
)


async def openclaw_sandbox_audit(
    config_path: str,
) -> dict[str, Any]:
    """
    Audits the OpenClaw config for sandbox.mode settings.

    Addresses gap C2: sandbox.mode defaults to 'off', exposing the host to
    prompt injection attacks with full shell access.

    Args:
        config_path: Absolute path to the OpenClaw config file (YAML or JSON).

    Returns:
        dict with keys: ok, severity, sandbox_mode, finding, fix, command.
    """
    p = Path(config_path)
    if not p.exists():
        return {"ok": False, "error": f"Config file not found: {config_path}"}

    content = p.read_text(encoding="utf-8", errors="ignore").lower()

    # Detect sandbox mode
    if "mode: off" in content or '"mode": "off"' in content or "mode:off" in content:
        mode_found = "off"
    elif "mode: non-main" in content or '"mode": "non-main"' in content:
        mode_found = "non-main"
    elif "mode: all" in content or '"mode": "all"' in content:
        mode_found = "all"
    else:
        # Default in OpenClaw is 'off' if not specified
        mode_found = "off (implicit default — not set in config)"

    if "off" in mode_found:
        return {
            "ok": True,
            "severity": "CRITICAL",
            "sandbox_mode": mode_found,
            "finding": _SANDBOX_EXPLAIN,
            "fix_snippet": _SANDBOX_FIX,
            "command": f"# Edit {config_path} and set agents.defaults.sandbox.mode: non-main",
            "⚠️": "Contenu généré par IA — validation humaine requise avant modification en production.",
        }

    if mode_found in ("non-main", "all"):
        return {
            "ok": True,
            "severity": "OK",
            "sandbox_mode": mode_found,
            "finding": f"Sandbox is active (mode: {mode_found}) — host shell is protected.",
        }

    return {
        "ok": True,
        "severity": "UNKNOWN",
        "sandbox_mode": mode_found,
        "finding": "Could not determine sandbox mode — manual check required.",
    }


# ── Session config check (C3) ─────────────────────────────────────────────────

_SESSION_SECRET_FIX_DOCKER = """
# Fix: session secret persistant pour déploiements Docker/container
# docker-compose.yml

services:
  openclaw:
    image: ghcr.io/openclaw/openclaw:stable
    environment:
      # Charger le secret depuis un fichier ou une variable d'environnement externe
      SESSION_SECRET: "${SESSION_SECRET:?SESSION_SECRET env var required}"
    volumes:
      - openclaw_data:/home/user/.openclaw

# Créer le secret :
#   openssl rand -base64 48 > /etc/openclaw/session.secret
#   export SESSION_SECRET=$(cat /etc/openclaw/session.secret)
"""

_SESSION_SECRET_FIX_ENV = """
# Fix: ajouter dans .env (et .env dans .gitignore!)
SESSION_SECRET=<run: openssl rand -base64 48>

# Vérifier que .gitignore contient bien :
# .env
# *.secret
"""


async def openclaw_session_config_check(
    env_file_path: str | None = None,
    compose_file_path: str | None = None,
) -> dict[str, Any]:
    """
    Checks if the express-session secret is configured as a persistent env var.

    Addresses gap C3: OpenClaw regenerates the session secret on every container
    restart, causing infinite login loops in rolling/crash deployments.

    Args:
        env_file_path: Path to .env file to check (optional).
        compose_file_path: Path to docker-compose.yml to check (optional).

    Returns:
        dict with keys: ok, severity, session_secret_found, findings, fix_docker, fix_env.
    """
    findings: list[str] = []
    session_secret_detected = False

    if env_file_path:
        ep = Path(env_file_path)
        if ep.exists():
            content = ep.read_text(encoding="utf-8", errors="ignore")
            if "SESSION_SECRET" in content:
                session_secret_detected = True
                findings.append(f"SESSION_SECRET found in {env_file_path}")
            else:
                findings.append(f"SESSION_SECRET NOT found in {env_file_path}")
        else:
            findings.append(f"{env_file_path} not found")

    if compose_file_path:
        cp = Path(compose_file_path)
        if cp.exists():
            content = cp.read_text(encoding="utf-8", errors="ignore")
            if "SESSION_SECRET" in content:
                session_secret_detected = True
                findings.append(f"SESSION_SECRET found in {compose_file_path}")
            else:
                findings.append(f"SESSION_SECRET NOT found in {compose_file_path}")
                if "openclaw" in content.lower():
                    findings.append(
                        "docker-compose references openclaw but has no SESSION_SECRET — "
                        "container restarts will regenerate the secret and break active web sessions (issue #29955)"
                    )
        else:
            findings.append(f"{compose_file_path} not found")

    if not env_file_path and not compose_file_path:
        findings.append(
            "No config file provided — checking env var SESSION_SECRET in current process"
        )
        session_secret_detected = bool(os.getenv("SESSION_SECRET"))
        if session_secret_detected:
            findings.append("SESSION_SECRET is set in the current environment")
        else:
            findings.append("SESSION_SECRET is NOT set — session secret will be regenerated on restart")

    severity = "OK" if session_secret_detected else "HIGH"

    return {
        "ok": True,
        "severity": severity,
        "session_secret_found": session_secret_detected,
        "findings": findings,
        "fix_docker": _SESSION_SECRET_FIX_DOCKER if not session_secret_detected else None,
        "fix_env": _SESSION_SECRET_FIX_ENV if not session_secret_detected else None,
        "issue_ref": "#29955 — express-session secret regenerated on container restart",
        "⚠️": "Contenu généré par IA — validation humaine requise avant déploiement.",
    }


# ── Rate limit check (H8) ─────────────────────────────────────────────────────

_RATE_LIMIT_NGINX = """
# Nginx rate limiting for OpenClaw Gateway
limit_req_zone $binary_remote_addr zone=openclaw_ws:10m rate=30r/m;

server {
    listen 80;
    server_name your-gateway.example.com;

    location /ws {
        limit_req zone=openclaw_ws burst=10 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:18789;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location / {
        limit_req zone=openclaw_ws burst=20 nodelay;
        proxy_pass http://127.0.0.1:18789;
    }
}
"""

_RATE_LIMIT_CADDY = """
# Caddyfile rate limiting (requires caddy-ratelimit plugin)
your-gateway.example.com {
    rate_limit {
        zone openclaw_ws {
            key {remote_host}
            events 30
            window 1m
        }
    }
    reverse_proxy 127.0.0.1:18789
}
"""

_RATE_LIMIT_WARNING_FUNNEL = (
    "⚠️  CRITICAL: gateway.funnel is enabled — the Gateway WS port is exposed to the public internet. "
    "Without rate limiting, any IP can flood sessions_send/sessions_spawn. "
    "Apply Nginx/Caddy rate limiting immediately OR disable funnel until hardened."
)


async def openclaw_rate_limit_check(
    gateway_config_path: str,
    check_funnel: bool = True,
) -> dict[str, Any]:
    """
    Checks if a rate limiter is configured in front of the OpenClaw Gateway.

    Addresses gap H8: no rate limiting documented, Tailscale Funnel exposure
    creates an amplification risk.

    Args:
        gateway_config_path: Path to OpenClaw config file.
        check_funnel: If True, checks whether funnel mode is active.

    Returns:
        dict with keys: ok, severity, funnel_active, rate_limiter_detected,
                        findings, fix_nginx, fix_caddy.
    """
    p = Path(gateway_config_path)
    if not p.exists():
        return {"ok": False, "error": f"Config file not found: {gateway_config_path}"}

    content = p.read_text(encoding="utf-8", errors="ignore")
    content_lower = content.lower()

    funnel_active = False
    if check_funnel:
        funnel_active = (
            "funnel: true" in content_lower
            or '"funnel": true' in content_lower
            or "tailscale" in content_lower
        )

    # Detect common reverse proxy configs
    rate_limiter_hints = [
        "nginx", "caddy", "haproxy", "traefik", "rate_limit", "ratelimit",
        "limit_req", "x-ratelimit", "429",
    ]
    rate_limiter_detected = any(hint in content_lower for hint in rate_limiter_hints)

    # Check env for proxy hints
    proxy_env = os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY") or os.getenv("NGINX_CONF")
    if proxy_env:
        rate_limiter_detected = True

    findings: list[str] = []
    severity = "OK"

    if funnel_active and not rate_limiter_detected:
        severity = "CRITICAL"
        findings.append(_RATE_LIMIT_WARNING_FUNNEL)
    elif not rate_limiter_detected:
        severity = "MEDIUM"
        findings.append(
            "No rate limiter detected in config. If Gateway is exposed beyond localhost, "
            "a reverse proxy with rate limiting is strongly recommended."
        )
    else:
        findings.append("Rate limiter configuration detected.")

    if funnel_active:
        findings.append("Tailscale Funnel is active — Gateway is publicly reachable.")

    return {
        "ok": True,
        "severity": severity,
        "funnel_active": funnel_active,
        "rate_limiter_detected": rate_limiter_detected,
        "findings": findings,
        "fix_nginx": _RATE_LIMIT_NGINX if not rate_limiter_detected else None,
        "fix_caddy": _RATE_LIMIT_CADDY if not rate_limiter_detected else None,
        "⚠️": "Contenu généré par IA — validation par un expert sécurité requise.",
    }


# ── Tool registry ─────────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_security_scan",
        "title": "Security Source Scan",
        "description": (
            "Scans source files for SQL injection patterns and dangerous query constructs. "
            "Specifically targets the /api/metrics/database vulnerability (openclaw issue #29951). "
            "Returns: vulnerabilities with file/line/severity, CVSS-style severity classification, "
            "and ready-to-apply remediation snippets."
        ),
        "category": "security",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "handler": openclaw_security_scan,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Absolute path to file or directory to scan.",
                },
                "endpoint": {
                    "type": "string",
                    "description": "Optional endpoint name to highlight (e.g. '/api/metrics/database').",
                },
                "scan_depth": {
                    "type": "integer",
                    "description": "Maximum directory recursion depth (1-5). Default: 3.",
                    "minimum": 1,
                    "maximum": 5,
                    "default": 3,
                },
            },
            "required": ["target_path"],
        },
    },
    {
        "name": "openclaw_sandbox_audit",
        "title": "Sandbox Mode Audit",
        "description": (
            "Audits the OpenClaw config for sandbox.mode setting. "
            "CRITICAL gap C2: sandbox defaults to 'off', giving any agent session full host shell access. "
            "A prompt injection → RCE with mode:off. Returns: severity, current mode, fix snippet."
        ),
        "category": "security",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "handler": openclaw_sandbox_audit,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Absolute path to the OpenClaw config file (YAML or JSON).",
                },
            },
            "required": ["config_path"],
        },
    },
    {
        "name": "openclaw_session_config_check",
        "title": "Session Config Check",
        "description": (
            "Checks if the express-session secret is configured as a persistent env var. "
            "Gap C3: OpenClaw regenerates the session secret on every container restart, "
            "causing infinite login loops in rolling/crash deployments (issue #29955). "
            "Returns: severity, secret found?, Docker and .env fix snippets."
        ),
        "category": "security",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "handler": openclaw_session_config_check,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "env_file_path": {
                    "type": "string",
                    "description": "Path to .env file to check (optional).",
                },
                "compose_file_path": {
                    "type": "string",
                    "description": "Path to docker-compose.yml to check (optional).",
                },
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_rate_limit_check",
        "title": "Rate Limit Check",
        "description": (
            "Checks if a rate limiter is configured in front of the OpenClaw Gateway. "
            "Gap H8: no rate limiting means Tailscale Funnel exposure creates amplification risk. "
            "Returns: funnel status, rate limiter detected?, Nginx/Caddy fix snippets."
        ),
        "category": "security",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "handler": openclaw_rate_limit_check,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "gateway_config_path": {
                    "type": "string",
                    "description": "Path to OpenClaw config file.",
                },
                "check_funnel": {
                    "type": "boolean",
                    "description": "If true, checks whether Tailscale Funnel mode is active. Default: true.",
                    "default": True,
                },
            },
            "required": ["gateway_config_path"],
        },
    },
]
