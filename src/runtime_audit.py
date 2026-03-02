"""
runtime_audit.py — OpenClaw runtime environment & config safety audits

Comble les gaps identifiés dans openclaw/openclaw (CHANGELOG ≤ 2026.2.27) :
  C5  — Node.js version < 22.12.0 (CVE-2025-59466, CVE-2026-21636)
  C6  — Secrets hardcodés dans openclaw.json au lieu d'utiliser le workflow
         `openclaw secrets` (External Secrets Management, 2026.2.26)
  H9  — HTTP security headers absents (HSTS, X-Content-Type-Options,
         Referrer-Policy) ajoutés en 2026.2.23 / 2026.2.20
  H10 — gateway.nodes.allowCommands override dangereux (critical si gateway exposé)
  H11 — Trusted-proxy mal configuré (bind + trustedProxies + auth mode incohérents)
  M15 — Budget disque des sessions non configuré (session.maintenance.maxDiskBytes)
  M16 — dmPolicy=allowlist avec allowFrom vide → fail-closed non appliqué

Tools exposed:
  openclaw_node_version_check       — vérifie la version Node.js (C5)
  openclaw_secrets_workflow_check   — détecte les secrets hardcodés (C6)
  openclaw_http_headers_check       — vérifie les security headers HTTP (H9)
  openclaw_nodes_commands_check     — vérifie gateway.nodes.allowCommands (H10)
  openclaw_trusted_proxy_check      — vérifie la config trusted-proxy (H11)
  openclaw_session_disk_budget_check— vérifie le budget disque des sessions (M15)
  openclaw_dm_allowlist_check       — vérifie dmPolicy + allowFrom (M16)
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.config_helpers import load_config as _load_config_base, get_nested as _get_nested  # noqa: E402

logger = logging.getLogger(__name__)

# ── Default paths (overridable via env) ──────────────────────────────────────

_OPENCLAW_DIR = Path(os.getenv("OPENCLAW_DIR", Path.home() / ".openclaw"))
_CONFIG_PATH = Path(os.getenv("OPENCLAW_CONFIG", _OPENCLAW_DIR / "openclaw.json"))

# ── Node.js minimum version requirement (SECURITY.md Runtime Requirements) ───

_MIN_NODE_MAJOR = 22
_MIN_NODE_MINOR = 12
_MIN_NODE_PATCH = 0

# ── Secret-looking key patterns in config  ────────────────────────────────────

_SECRET_KEY_PATTERNS = re.compile(
    r"(token|password|apikey|api_key|secret|key|credential|passwd|auth_password|"
    r"webhooksecret|signingsecret|bottoken|publickey|privkey|private_key)",
    re.IGNORECASE,
)
_SECRET_VALUE_PATTERNS = re.compile(
    r"^[A-Za-z0-9+/]{20,}={0,2}$|"     # base64-like
    r"^[a-fA-F0-9]{32,}$|"              # hex tokens
    r"^[A-Za-z0-9\-_\.]{40,}$",         # JWT-style / long tokens
)

# ── Channels that support dmPolicy ────────────────────────────────────────────

_DM_POLICY_CHANNELS = [
    "telegram", "whatsapp", "signal", "imessage",
    "discord", "slack", "line", "matrix", "feishu",
]


# ════════════════════════════════════════════════════════════════════════════
# Helper — delegates to shared config_helpers
# ════════════════════════════════════════════════════════════════════════════

def _load_config(config_path: str | None) -> tuple[dict[str, Any], str]:
    """Load config — delegates to config_helpers.load_config."""
    return _load_config_base(config_path)



# ════════════════════════════════════════════════════════════════════════════
# Tool 1 — C5: Node.js version check
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_node_version_check(node_binary: str | None = None) -> dict[str, Any]:
    """
    C5 — Vérifie que Node.js ≥ 22.12.0 est installé.

    Node < 22.12.0 expose :
      - CVE-2025-59466 : async_hooks DoS vulnerability
      - CVE-2026-21636 : Permission model bypass vulnerability

    Args:
        node_binary: Chemin vers le binaire node (default: auto-detect via PATH)

    Returns:
        {status, node_path, version, findings}
    """
    findings: list[dict[str, Any]] = []
    node_bin = node_binary or shutil.which("node")

    if not node_bin:
        return {
            "status": "error",
            "node_path": None,
            "version": None,
            "findings": [{
                "id": "node_not_found",
                "severity": "CRITICAL",
                "message": "node binary not found in PATH — OpenClaw requires Node.js ≥ 22.12.0",
            }],
        }

    try:
        result = subprocess.run(
            [node_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        raw_version = result.stdout.strip().lstrip("v")
    except (subprocess.SubprocessError, OSError) as exc:
        return {
            "status": "error",
            "node_path": node_bin,
            "version": None,
            "findings": [{
                "id": "node_version_check_failed",
                "severity": "HIGH",
                "message": f"Failed to run node --version: {exc}",
            }],
        }

    parts = raw_version.split(".")
    try:
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2].split("-")[0])
    except (ValueError, IndexError):
        return {
            "status": "error",
            "node_path": node_bin,
            "version": raw_version,
            "findings": [{
                "id": "node_version_parse_error",
                "severity": "HIGH",
                "message": f"Cannot parse Node.js version: {raw_version!r}",
            }],
        }

    meets_min = (major, minor, patch) >= (_MIN_NODE_MAJOR, _MIN_NODE_MINOR, _MIN_NODE_PATCH)

    if not meets_min:
        req = f"{_MIN_NODE_MAJOR}.{_MIN_NODE_MINOR}.{_MIN_NODE_PATCH}"
        findings.append({
            "id": "node_version_too_old",
            "severity": "CRITICAL",
            "message": (
                f"Node.js {raw_version} is below minimum {req}. "
                "Exposes CVE-2025-59466 (async_hooks DoS) and "
                "CVE-2026-21636 (Permission model bypass). Update immediately."
            ),
        })

    return {
        "status": "ok" if meets_min else "critical",
        "node_path": node_bin,
        "version": raw_version,
        "meets_minimum": meets_min,
        "minimum_required": f"{_MIN_NODE_MAJOR}.{_MIN_NODE_MINOR}.{_MIN_NODE_PATCH}",
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 2 — C6: Secrets workflow check (hardcoded secrets in config)
# ════════════════════════════════════════════════════════════════════════════

def _scan_secrets_in_dict(
    d: Any,
    path: str = "",
    hits: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Recursively scan a dict for hardcoded secret-looking values."""
    if hits is None:
        hits = []
    if isinstance(d, dict):
        for k, v in d.items():
            full_path = f"{path}.{k}" if path else k
            if isinstance(v, str) and _SECRET_KEY_PATTERNS.search(k):
                # Key looks like a secret field
                if v and not v.startswith("$") and not v.startswith("{{") and len(v) > 8:
                    # Value is not an env-var placeholder and looks like a real secret
                    if _SECRET_VALUE_PATTERNS.match(v) or len(v) >= 20:
                        hits.append({
                            "path": full_path,
                            "severity": "CRITICAL",
                            "message": (
                                f"Hardcoded secret detected at '{full_path}' — "
                                "migrate to `openclaw secrets configure` / env var / "
                                "$include with restricted permissions"
                            ),
                        })
            _scan_secrets_in_dict(v, full_path, hits)
    elif isinstance(d, list):
        for i, item in enumerate(d):
            _scan_secrets_in_dict(item, f"{path}[{i}]", hits)
    return hits


async def openclaw_secrets_workflow_check(config_path: str | None = None) -> dict[str, Any]:
    """
    C6 — Détecte les secrets hardcodés dans openclaw.json.

    La version 2026.2.26 introduit `openclaw secrets` (audit/configure/apply/reload).
    Tout token/apiKey/password stocké en clair dans le fichier de config est un C6.

    Args:
        config_path: Chemin vers openclaw.json (default: ~/.openclaw/openclaw.json)

    Returns:
        {status, config_path, hardcoded_count, findings}
    """
    try:
        config, resolved = _load_config(config_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "findings": []}

    if not config:
        return {
            "status": "ok",
            "config_path": resolved,
            "hardcoded_count": 0,
            "findings": [{"id": "config_not_found", "severity": "INFO",
                          "message": f"Config not found at {resolved} — skipping"}],
        }

    hits = _scan_secrets_in_dict(config)
    # Deduplicate by path
    seen: set[str] = set()
    unique_hits: list[dict[str, Any]] = []
    for h in hits:
        if h["path"] not in seen:
            seen.add(h["path"])
            unique_hits.append(h)

    return {
        "status": "critical" if unique_hits else "ok",
        "config_path": resolved,
        "hardcoded_count": len(unique_hits),
        "findings": unique_hits,
        "remediation": (
            "Run `openclaw secrets configure` to migrate secrets to the "
            "External Secrets Management workflow (2026.2.26+). "
            "Use `$ENV_VAR` placeholders or `$include` restricted files."
        ) if unique_hits else None,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 3 — H9: HTTP security headers check
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_http_headers_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H9 — Vérifie la présence des security headers HTTP dans la config gateway.

    Headers requis (ajoutés dans 2026.2.23 et 2026.2.20) :
      - gateway.http.securityHeaders.strictTransportSecurity (HSTS)
      - X-Content-Type-Options: nosniff  (présent si gateway.http.securityHeaders configuré)
      - Referrer-Policy: no-referrer

    Args:
        config_path: Chemin vers openclaw.json (default: ~/.openclaw/openclaw.json)

    Returns:
        {status, config_path, findings}
    """
    try:
        config, resolved = _load_config(config_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "findings": []}

    if not config:
        return {"status": "ok", "config_path": resolved, "findings": [
            {"id": "config_not_found", "severity": "INFO",
             "message": f"Config not found at {resolved} — skipping"}
        ]}

    findings: list[dict[str, Any]] = []
    sec_headers = _get_nested(config, "gateway", "http", "securityHeaders", default={})
    bind = _get_nested(config, "gateway", "bind", default="loopback")
    is_public = bind not in ("loopback", "127.0.0.1", "::1")

    # HSTS — only relevant for HTTPS (non-loopback)
    hsts = sec_headers.get("strictTransportSecurity") if isinstance(sec_headers, dict) else None
    if is_public and not hsts:
        findings.append({
            "id": "missing_hsts",
            "severity": "HIGH",
            "message": (
                "gateway.http.securityHeaders.strictTransportSecurity not set on non-loopback "
                "deployment. Add: securityHeaders.strictTransportSecurity: "
                "'max-age=31536000; includeSubDomains'"
            ),
        })

    # X-Content-Type-Options — baseline protection
    xcto = (
        sec_headers.get("xContentTypeOptions") if isinstance(sec_headers, dict) else None
    )
    if not xcto and is_public:
        findings.append({
            "id": "missing_xcontent_type_options",
            "severity": "MEDIUM",
            "message": (
                "gateway.http.securityHeaders.xContentTypeOptions not set — "
                "recommended: 'nosniff' to prevent MIME-sniffing attacks"
            ),
        })

    # Referrer-Policy
    referrer = (
        sec_headers.get("referrerPolicy") if isinstance(sec_headers, dict) else None
    )
    if not referrer and is_public:
        findings.append({
            "id": "missing_referrer_policy",
            "severity": "MEDIUM",
            "message": (
                "gateway.http.securityHeaders.referrerPolicy not set — "
                "recommended: 'no-referrer' (added in 2026.2.20)"
            ),
        })

    # If loopback and no headers, just note it
    if not is_public and not sec_headers:
        findings.append({
            "id": "no_security_headers_loopback",
            "severity": "INFO",
            "message": (
                "No HTTP security headers configured (loopback deployment — low risk). "
                "Consider adding them before exposing the gateway to non-loopback."
            ),
        })

    return {
        "status": "high" if any(f["severity"] == "HIGH" for f in findings) else
                  "medium" if any(f["severity"] == "MEDIUM" for f in findings) else "ok",
        "config_path": resolved,
        "bind": bind,
        "is_public": is_public,
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 4 — H10: gateway.nodes.allowCommands dangerous override
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_nodes_commands_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H10 — Détecte les overrides dangereux de gateway.nodes.allowCommands.

    `openclaw security audit` émet `gateway.nodes.allow_commands_dangerous`
    quand ce champ est configuré, avec severity CRITICAL si le gateway est
    exposé à distance (2026.2.20 changelog).

    Args:
        config_path: Chemin vers openclaw.json (default: ~/.openclaw/openclaw.json)

    Returns:
        {status, config_path, allow_commands, findings}
    """
    try:
        config, resolved = _load_config(config_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "findings": []}

    if not config:
        return {"status": "ok", "config_path": resolved, "findings": [
            {"id": "config_not_found", "severity": "INFO",
             "message": f"Config not found at {resolved} — skipping"}
        ]}

    findings: list[dict[str, Any]] = []
    allow_commands = _get_nested(config, "gateway", "nodes", "allowCommands")
    deny_commands = _get_nested(config, "gateway", "nodes", "denyCommands")
    bind = _get_nested(config, "gateway", "bind", default="loopback")
    is_remote = bind not in ("loopback", "127.0.0.1", "::1")

    if allow_commands:
        severity = "CRITICAL" if is_remote else "HIGH"
        findings.append({
            "id": "allow_commands_dangerous",
            "severity": severity,
            "message": (
                f"gateway.nodes.allowCommands is set ({allow_commands!r}). "
                f"This expands node command allowlists {'on a remote-exposed gateway' if is_remote else 'on a local gateway'}. "
                "Use `openclaw security audit` finding `gateway.nodes.allow_commands_dangerous` "
                "and review explicitly. Remove or restrict to minimum needed."
            ),
        })

        # Check 2026.3.1 BREAKING: system.run now pins to canonical path (realpath)
        # Entries using token-form (e.g. 'tr') must now use canonical paths (e.g. '/usr/bin/tr')
        if isinstance(allow_commands, list):
            non_canonical = [cmd for cmd in allow_commands
                            if isinstance(cmd, str) and not cmd.startswith("/")]
            if non_canonical:
                findings.append({
                    "id": "allow_commands_non_canonical_path",
                    "severity": "CRITICAL",
                    "message": (
                        f"BREAKING 2026.3.1: gateway.nodes.allowCommands contains "
                        f"non-canonical (token-form) entries: {non_canonical!r}. "
                        "Node system.run now pins commands to canonical executable "
                        "paths (realpath). Replace token-form commands with their "
                        "canonical paths (e.g. 'tr' → '/usr/bin/tr'). "
                        "Both allowlist and approval flows use canonical paths now."
                    ),
                })

    # Check for ineffective denyCommands (audit finding added 2026.2.13)
    if deny_commands:
        findings.append({
            "id": "deny_commands_check",
            "severity": "MEDIUM",
            "message": (
                f"gateway.nodes.denyCommands is set ({deny_commands!r}). "
                "Verify entries are not ineffective (no path wildcards issues). "
                "See `openclaw security audit` finding for gating guidance."
            ),
        })

    return {
        "status": "critical" if any(f["severity"] == "CRITICAL" for f in findings)
                  else "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "ok",
        "config_path": resolved,
        "allow_commands": allow_commands,
        "deny_commands": deny_commands,
        "bind": bind,
        "is_remote": is_remote,
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 5 — H11: Trusted proxy misconfiguration
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_trusted_proxy_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H11 — Vérifie la cohérence de la config trusted-proxy.

    Règles (fixes 2026.2.22 + 2026.2.13) :
      - auth.mode=trusted-proxy + bind=loopback → trustedProxies doit être configuré
      - auth.mode=trusted-proxy → bind doit être loopback ou lan (pas funnel/custom sans proxy)
      - trustedProxies non-loopback → severity CRITICAL (real_ip_fallback_enabled)
      - parse X-Forwarded-For selon proxies configurés

    Args:
        config_path: Chemin vers openclaw.json (default: ~/.openclaw/openclaw.json)

    Returns:
        {status, config_path, auth_mode, bind, trusted_proxies, findings}
    """
    try:
        config, resolved = _load_config(config_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "findings": []}

    if not config:
        return {"status": "ok", "config_path": resolved, "findings": [
            {"id": "config_not_found", "severity": "INFO",
             "message": f"Config not found at {resolved} — skipping"}
        ]}

    findings: list[dict[str, Any]] = []
    auth_mode = _get_nested(config, "gateway", "auth", "mode", default="token")
    bind = _get_nested(config, "gateway", "bind", default="loopback")
    trusted_proxies: list = _get_nested(config, "gateway", "trustedProxies", default=[])
    real_ip_fallback = _get_nested(config, "gateway", "real_ip_fallback_enabled", default=False)

    if auth_mode == "trusted-proxy":
        if not trusted_proxies:
            findings.append({
                "id": "trusted_proxy_no_proxies_configured",
                "severity": "CRITICAL",
                "message": (
                    "auth.mode=trusted-proxy but gateway.trustedProxies is empty. "
                    "Auth will fail or fall back to insecure behavior. "
                    "Add the reverse proxy IP(s) to trustedProxies. (Fix 2026.2.22)"
                ),
            })
        else:
            # Check for non-loopback trusted proxies
            loopback_ips = {"127.0.0.1", "::1", "localhost"}
            non_loopback = [p for p in trusted_proxies if p not in loopback_ips]
            if non_loopback:
                findings.append({
                    "id": "non_loopback_trusted_proxies",
                    "severity": "CRITICAL" if len(non_loopback) > 0 else "HIGH",
                    "message": (
                        f"Non-loopback trusted proxies configured: {non_loopback}. "
                        "Only loopback proxy addresses are safe for trusted-proxy auth "
                        "on same-host setups. CRITICAL if external proxies are trusted "
                        "without strict network controls. (Audit 2026.2.22 real_ip_fallback)"
                    ),
                })

        if bind not in ("loopback", "lan") and auth_mode == "trusted-proxy":
            findings.append({
                "id": "trusted_proxy_incompatible_bind",
                "severity": "HIGH",
                "message": (
                    f"auth.mode=trusted-proxy with bind={bind!r} may be misconfigured. "
                    "Recommended: bind=loopback (same-host proxy) or bind=lan "
                    "for LAN-proxy setups. Tailscale funnel forces bind=lan "
                    "and disables this mode. (Guide 2026.2.13)"
                ),
            })

    if real_ip_fallback:
        has_non_loopback = any(
            p not in {"127.0.0.1", "::1", "localhost"}
            for p in trusted_proxies
        )
        sev = "CRITICAL" if has_non_loopback else "HIGH"
        findings.append({
            "id": "real_ip_fallback_enabled",
            "severity": sev,
            "message": (
                f"gateway.real_ip_fallback_enabled=true — "
                f"{'CRITICAL: non-loopback proxies trusted' if has_non_loopback else 'HIGH: loopback-only proxies'}. "
                "This can allow IP spoofing via X-Forwarded-For. "
                "Disable unless explicitly needed. (Security audit 2026.2.22)"
            ),
        })

    return {
        "status": "critical" if any(f["severity"] == "CRITICAL" for f in findings)
                  else "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "ok",
        "config_path": resolved,
        "auth_mode": auth_mode,
        "bind": bind,
        "trusted_proxies": trusted_proxies,
        "real_ip_fallback_enabled": real_ip_fallback,
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 6 — M15: Session disk budget
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_session_disk_budget_check(config_path: str | None = None) -> dict[str, Any]:
    """
    M15 — Vérifie que le budget disque des sessions est configuré.

    La version 2026.2.23 introduit `session.maintenance.maxDiskBytes` et
    `highWaterBytes` pour contrôler la croissance des transcripts de sessions.
    Sans ces limites, les sessions peuvent consommer de l'espace disque illimité.

    Args:
        config_path: Chemin vers openclaw.json (default: ~/.openclaw/openclaw.json)

    Returns:
        {status, config_path, max_disk_bytes, high_water_bytes, findings}
    """
    try:
        config, resolved = _load_config(config_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "findings": []}

    if not config:
        return {"status": "ok", "config_path": resolved, "findings": [
            {"id": "config_not_found", "severity": "INFO",
             "message": f"Config not found at {resolved} — skipping"}
        ]}

    findings: list[dict[str, Any]] = []
    max_disk_bytes = _get_nested(config, "session", "maintenance", "maxDiskBytes")
    high_water_bytes = _get_nested(config, "session", "maintenance", "highWaterBytes")

    _DEFAULT_RECOMMENDED_BYTES = 500 * 1024 * 1024  # 500 MB

    if max_disk_bytes is None:
        findings.append({
            "id": "session_max_disk_bytes_missing",
            "severity": "MEDIUM",
            "message": (
                "session.maintenance.maxDiskBytes not configured. "
                "Sessions can grow unbounded on disk. "
                f"Recommended: set to a reasonable limit (e.g., {_DEFAULT_RECOMMENDED_BYTES // (1024*1024)} MB). "
                "Feature added in 2026.2.23 via `openclaw sessions cleanup`."
            ),
        })
    elif isinstance(max_disk_bytes, (int, float)) and max_disk_bytes <= 0:
        findings.append({
            "id": "session_max_disk_bytes_invalid",
            "severity": "MEDIUM",
            "message": (
                f"session.maintenance.maxDiskBytes={max_disk_bytes} is invalid (must be > 0)."
            ),
        })

    if high_water_bytes is None and max_disk_bytes is not None:
        findings.append({
            "id": "session_high_water_bytes_missing",
            "severity": "INFO",
            "message": (
                "session.maintenance.highWaterBytes not configured. "
                "Consider adding it as an early-warning threshold before maxDiskBytes is reached."
            ),
        })

    return {
        "status": "medium" if any(f["severity"] == "MEDIUM" for f in findings) else "ok",
        "config_path": resolved,
        "max_disk_bytes": max_disk_bytes,
        "high_water_bytes": high_water_bytes,
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 7 — M16: DM allowlist safety (fail-closed)
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_dm_allowlist_check(config_path: str | None = None) -> dict[str, Any]:
    """
    M16 — Vérifie que dmPolicy=allowlist avec allowFrom vide est détecté.

    Fix 2026.2.26 : `dmPolicy: "allowlist"` avec `allowFrom: []` doit rejeter
    tous les senders (fail-closed). OpenClaw doctor --fix peut réparer cela,
    mais cette combinaison dangereuse doit être détectée en audit.

    Args:
        config_path: Chemin vers openclaw.json (default: ~/.openclaw/openclaw.json)

    Returns:
        {status, config_path, channel_findings, findings}
    """
    try:
        config, resolved = _load_config(config_path)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "findings": []}

    if not config:
        return {"status": "ok", "config_path": resolved, "findings": [
            {"id": "config_not_found", "severity": "INFO",
             "message": f"Config not found at {resolved} — skipping"}
        ]}

    findings: list[dict[str, Any]] = []
    channel_findings: list[dict[str, str]] = []

    channels_config = config.get("channels", {})

    for channel in _DM_POLICY_CHANNELS:
        chan_cfg = channels_config.get(channel, {})
        if not isinstance(chan_cfg, dict):
            continue

        dm_policy = chan_cfg.get("dmPolicy") or chan_cfg.get("dm", {}).get("policy")
        allow_from = chan_cfg.get("allowFrom") or chan_cfg.get("dm", {}).get("allowFrom", [])

        if dm_policy == "allowlist":
            if not allow_from:
                channel_findings.append({"channel": channel, "issue": "empty_allowFrom"})
                findings.append({
                    "id": f"dm_allowlist_empty_{channel}",
                    "severity": "HIGH",
                    "message": (
                        f"channels.{channel}.dmPolicy='allowlist' with empty allowFrom. "
                        "This was silently allowing all senders in older versions. "
                        "Run `openclaw doctor --fix` to restore expected fail-closed behavior, "
                        "or add explicit allowFrom entries. (Fix 2026.2.26)"
                    ),
                })
            elif "*" in allow_from:
                channel_findings.append({"channel": channel, "issue": "wildcard_allowFrom"})
                findings.append({
                    "id": f"dm_allowlist_wildcard_{channel}",
                    "severity": "MEDIUM",
                    "message": (
                        f"channels.{channel}.dmPolicy='allowlist' with allowFrom=['*']. "
                        "Wildcard defeats the allowlist — equivalent to dmPolicy='open'."
                    ),
                })
        elif dm_policy == "open" and not channels_config.get(channel, {}).get("allowFrom"):
            findings.append({
                "id": f"dm_policy_open_{channel}",
                "severity": "MEDIUM",
                "message": (
                    f"channels.{channel}.dmPolicy='open' without allowFrom restriction. "
                    "Anyone can DM this channel. Consider using 'pairing' or 'allowlist' "
                    "with explicit allowFrom. (Security 2026.1.8 DM lockdown)"
                ),
            })

    # Check 2026.3.1: requireTopic for Telegram DMs
    tg_cfg = channels_config.get("telegram", {})
    if isinstance(tg_cfg, dict):
        tg_direct = tg_cfg.get("direct", {})
        if isinstance(tg_direct, dict):
            require_topic = tg_direct.get("requireTopic", None)
            if require_topic is None:
                findings.append({
                    "id": "telegram_require_topic_missing",
                    "severity": "HIGH",
                    "message": (
                        "channels.telegram.direct.requireTopic not set. "
                        "2026.3.1 added requireTopic to enforce topic threads in Telegram DMs. "
                        "Without it, messages may be sent outside topic threads, bypassing "
                        "audit trails. Set requireTopic: true for production."
                    ),
                })
            topic_allowlist = tg_direct.get("topicAllowlist", [])
            if require_topic and not topic_allowlist:
                findings.append({
                    "id": "telegram_topic_allowlist_empty",
                    "severity": "MEDIUM",
                    "message": (
                        "channels.telegram.direct.requireTopic=true but topicAllowlist is empty. "
                        "All topics are accepted — consider restricting to known topic IDs "
                        "for tighter DM scoping. (New in 2026.3.1)"
                    ),
                })

    # Also check top-level defaults
    defaults_dm = _get_nested(config, "channels", "defaults", "dmPolicy")
    if defaults_dm == "open":
        findings.append({
            "id": "channels_defaults_dm_open",
            "severity": "MEDIUM",
            "message": (
                "channels.defaults.dmPolicy='open' — all channels default to open DMs. "
                "Set to 'pairing' (recommended default since 2026.1.8) to require "
                "explicit approval before allowing new DM senders."
            ),
        })

    return {
        "status": "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "medium" if any(f["severity"] == "MEDIUM" for f in findings)
                  else "ok",
        "config_path": resolved,
        "channels_checked": _DM_POLICY_CHANNELS,
        "channel_findings": channel_findings,
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# MCP Tool Registry
# ════════════════════════════════════════════════════════════════════════════

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_node_version_check",
        "title": "Node.js Version Check",
        "description": (
            "C5 — Vérifie que Node.js ≥ 22.12.0 est installé "
            "(CVE-2025-59466 async_hooks DoS + CVE-2026-21636 Permission model bypass). "
            "Détecte les versions insuffisantes avec guidance de mise à jour."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "node_binary": {
                    "type": "string",
                    "description": "Chemin vers le binaire node (default: auto-detect via PATH)",
                },
            },
        },
        "handler": openclaw_node_version_check,
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
    },
    {
        "name": "openclaw_secrets_workflow_check",
        "title": "Hardcoded Secrets Check",
        "description": (
            "C6 — Détecte les secrets hardcodés dans openclaw.json "
            "(tokens, API keys, passwords). Guide la migration vers "
            "`openclaw secrets` workflow (External Secrets Management, 2026.2.26+)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Chemin vers openclaw.json (default: ~/.openclaw/openclaw.json)",
                },
            },
        },
        "handler": openclaw_secrets_workflow_check,
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
    },
    {
        "name": "openclaw_http_headers_check",
        "title": "HTTP Security Headers Check",
        "description": (
            "H9 — Vérifie la présence des HTTP security headers dans la config gateway "
            "(HSTS, X-Content-Type-Options, Referrer-Policy). "
            "Ajoutés dans OpenClaw 2026.2.23 / 2026.2.20."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Chemin vers openclaw.json",
                },
            },
        },
        "handler": openclaw_http_headers_check,
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
    },
    {
        "name": "openclaw_nodes_commands_check",
        "title": "Dangerous Commands Check",
        "description": (
            "H10 — Détecte les overrides dangereux de gateway.nodes.allowCommands. "
            "Remplace le finding `gateway.nodes.allow_commands_dangerous` "
            "de `openclaw security audit` (severity CRITICAL si gateway exposé)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Chemin vers openclaw.json",
                },
            },
        },
        "handler": openclaw_nodes_commands_check,
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
    },
    {
        "name": "openclaw_trusted_proxy_check",
        "title": "Trusted Proxy Check",
        "description": (
            "H11 — Vérifie la cohérence de la config trusted-proxy "
            "(auth.mode, bind, trustedProxies, real_ip_fallback_enabled). "
            "Détecte les combinaisons invalides corrigées en 2026.2.22 / 2026.2.13."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Chemin vers openclaw.json",
                },
            },
        },
        "handler": openclaw_trusted_proxy_check,
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
    },
    {
        "name": "openclaw_session_disk_budget_check",
        "title": "Session Disk Budget Check",
        "description": (
            "M15 — Vérifie que session.maintenance.maxDiskBytes et highWaterBytes "
            "sont configurés pour éviter la croissance illimitée des transcripts. "
            "Fonctionnalité ajoutée dans OpenClaw 2026.2.23."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Chemin vers openclaw.json",
                },
            },
        },
        "handler": openclaw_session_disk_budget_check,
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
    },
    {
        "name": "openclaw_dm_allowlist_check",
        "title": "DM Allowlist Policy Check",
        "description": (
            "M16 — Vérifie que dmPolicy=allowlist avec allowFrom vide est détecté "
            "(fail-closed non appliqué). Vérifie tous les canaux : telegram, whatsapp, "
            "signal, imessage, discord, slack, line, matrix, feishu. (Fix 2026.2.26)"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Chemin vers openclaw.json",
                },
            },
        },
        "handler": openclaw_dm_allowlist_check,
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
    },
]
