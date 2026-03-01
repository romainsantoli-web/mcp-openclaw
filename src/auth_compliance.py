"""
auth_compliance.py — OAuth 2.1 / OIDC Discovery compliance audit tools.

Covers gap H4: OAuth Resource Server + OIDC Discovery (MCP 2025-06-18 / 2025-11-25).

Audits MCP server configuration for proper OAuth 2.1 authorization,
OIDC provider discovery, token validation, and scope enforcement.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any


# ─── Helpers ───────────────────────────────────────────────────────────────

def _load_config(config_path: str | None) -> tuple[dict, str]:
    """Load JSON config from path, with fallback to default."""
    path = config_path or "openclaw.json"
    if ".." in path:
        return {}, path
    if not os.path.isfile(path):
        return {}, path
    try:
        with open(path) as f:
            return json.load(f), path
    except (json.JSONDecodeError, OSError):
        return {}, path


def _get_nested(data: dict, dotpath: str, default: Any = None) -> Any:
    """Get a nested dict value by dot-separated path."""
    keys = dotpath.split(".")
    current = data
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k, default)
        else:
            return default
    return current


# ─── H4: OAuth / OIDC Compliance Audit ────────────────────────────────────

async def handle_oauth_oidc_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit OAuth 2.1 / OIDC Discovery compliance (MCP 2025-06-18 / 2025-11-25).

    Checks:
    - OAuth 2.1 authorization server metadata
    - Protected Resource Metadata (RFC 9728) since 2025-06-18
    - OIDC Discovery endpoint (.well-known/openid-configuration) since 2025-11-25
    - Token validation configuration (audience, issuer, algorithms)
    - Scope enforcement per tool
    - PKCE requirement (S256 only)
    - Token rotation / refresh support
    - Resource indicators (RFC 8707)
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    auth = _get_nested(config, "mcp.auth", {})

    if not auth:
        findings.append("HIGH: No mcp.auth configuration — OAuth/OIDC not configured")
        return {
            "ok": False,
            "severity": "HIGH",
            "findings": findings,
            "finding_count": len(findings),
            "config_path": path,
            "feature": "oauth_oidc",
        }

    # OAuth type
    auth_type = auth.get("type", "")
    if auth_type not in ("oauth2", "oidc"):
        findings.append(f"HIGH: Auth type '{auth_type}' — expected 'oauth2' or 'oidc' for MCP compliance")

    # OIDC Discovery (2025-11-25)
    oidc_issuer = auth.get("issuer", "")
    if not oidc_issuer:
        findings.append("HIGH: No OIDC issuer configured — OIDC Discovery requires issuer URL")
    elif not oidc_issuer.startswith("https://"):
        findings.append(f"CRITICAL: OIDC issuer '{oidc_issuer}' must use HTTPS")

    discovery_url = auth.get("discoveryUrl", "")
    if not discovery_url and oidc_issuer:
        findings.append("MEDIUM: No explicit discoveryUrl — will use {issuer}/.well-known/openid-configuration")

    # Protected Resource Metadata (RFC 9728, MCP 2025-06-18)
    resource_metadata = auth.get("protectedResourceMetadata", {})
    if not resource_metadata:
        findings.append("MEDIUM: No Protected Resource Metadata (RFC 9728) — required since MCP 2025-06-18")
    else:
        if not resource_metadata.get("resource"):
            findings.append("HIGH: protectedResourceMetadata.resource not set (required)")
        if not resource_metadata.get("authorization_servers"):
            findings.append("HIGH: protectedResourceMetadata.authorization_servers empty")

    # PKCE
    pkce = auth.get("pkce", {})
    pkce_method = pkce.get("method", "")
    if pkce_method != "S256":
        findings.append(f"HIGH: PKCE method '{pkce_method}' — OAuth 2.1 requires S256")
    if not pkce.get("required", False):
        findings.append("HIGH: PKCE not marked as required — should be mandatory for OAuth 2.1")

    # Token validation
    token = auth.get("tokenValidation", {})
    if not token.get("audience"):
        findings.append("HIGH: No token audience configured — tokens could be replayed from other services")
    if not token.get("algorithms"):
        findings.append("MEDIUM: No explicit algorithm allowlist for token validation")
    else:
        algos = token["algorithms"]
        if "none" in algos:
            findings.append("CRITICAL: 'none' algorithm in token validation — allows unsigned tokens")
        if any(a.startswith("HS") for a in algos):
            findings.append("MEDIUM: Symmetric algorithms (HS*) in token validation — prefer RS256/ES256")

    # Scopes
    scopes = auth.get("scopes", {})
    tool_scopes = auth.get("toolScopes", {})
    if not scopes and not tool_scopes:
        findings.append("MEDIUM: No scope definitions — tools are unrestricted")

    # Resource indicators (RFC 8707)
    resource_indicators = auth.get("resourceIndicators", {})
    if not resource_indicators.get("enabled"):
        findings.append("INFO: RFC 8707 resource indicators not enabled (recommended since MCP 2025-06-18)")

    # Token refresh
    if not auth.get("refreshTokenRotation"):
        findings.append("MEDIUM: Token refresh rotation not configured")

    severity = "OK"
    if any("CRITICAL" in f for f in findings):
        severity = "CRITICAL"
    elif any("HIGH" in f for f in findings):
        severity = "HIGH"
    elif any("MEDIUM" in f for f in findings):
        severity = "MEDIUM"
    elif findings:
        severity = "INFO"

    return {
        "ok": len(findings) == 0 or severity in ("OK", "INFO"),
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "config_path": path,
        "feature": "oauth_oidc",
        "spec_versions": ["2025-06-18", "2025-11-25"],
    }


# ─── OAuth Token Scope Check ──────────────────────────────────────────────

async def handle_token_scope_check(config_path: str | None = None) -> dict[str, Any]:
    """Check if OAuth scopes properly restrict tool access.

    Verifies that each tool has scope requirements and that
    no tool is accessible without authentication.
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    tool_scopes = _get_nested(config, "mcp.auth.toolScopes", {})
    tools_config = _get_nested(config, "mcp.tools", [])
    public_tools = _get_nested(config, "mcp.auth.publicTools", [])

    if not isinstance(tools_config, list):
        tools_config = []

    tool_names = {t.get("name") for t in tools_config if isinstance(t, dict) and "name" in t}

    # Check unscoped tools
    scoped_tools = set(tool_scopes.keys()) if isinstance(tool_scopes, dict) else set()
    public_set = set(public_tools) if isinstance(public_tools, list) else set()
    unscoped = tool_names - scoped_tools - public_set

    if unscoped:
        findings.append(
            f"HIGH: {len(unscoped)} tool(s) have no scope restriction and are not marked public: "
            f"{', '.join(sorted(list(unscoped)[:5]))}"
        )

    # Check for wildcard scopes
    if isinstance(tool_scopes, dict):
        for tool_name, scope_list in tool_scopes.items():
            if isinstance(scope_list, list) and "*" in scope_list:
                findings.append(f"HIGH: Tool '{tool_name}' has wildcard scope '*' — too permissive")

    severity = "OK"
    if any("CRITICAL" in f for f in findings):
        severity = "CRITICAL"
    elif any("HIGH" in f for f in findings):
        severity = "HIGH"
    elif any("MEDIUM" in f for f in findings):
        severity = "MEDIUM"
    elif findings:
        severity = "INFO"

    return {
        "ok": len(findings) == 0 or severity in ("OK", "INFO"),
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "config_path": path,
        "total_tools": len(tool_names),
        "scoped_tools": len(scoped_tools),
        "public_tools": len(public_set),
        "unscoped_tools": len(unscoped),
    }


# ─── TOOLS Registration ───────────────────────────────────────────────────

_CONFIG_PATH_SCHEMA = {
    "type": "object",
    "properties": {
        "config_path": {"type": "string", "description": "Path to openclaw.json config file"},
    },
}

_AUDIT_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean"},
        "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
        "findings": {"type": "array", "items": {"type": "string"}},
        "finding_count": {"type": "integer"},
        "config_path": {"type": "string"},
    },
    "required": ["ok", "severity", "findings", "finding_count"],
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_oauth_oidc_audit",
        "title": "OAuth/OIDC Compliance Audit",
        "description": (
            "Audit OAuth 2.1 / OIDC Discovery compliance (MCP 2025-06-18 / 2025-11-25). "
            "Checks issuer, PKCE S256, Protected Resource Metadata (RFC 9728), "
            "token validation, scope enforcement, resource indicators (RFC 8707)."
        ),
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "handler": handle_oauth_oidc_audit,
        "category": "auth_compliance",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
    {
        "name": "openclaw_token_scope_check",
        "title": "Token Scope Enforcement Check",
        "description": (
            "Check if OAuth scopes properly restrict tool access. "
            "Verifies each tool has scope requirements, detects wildcards, "
            "and identifies unscoped tools."
        ),
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "handler": handle_token_scope_check,
        "category": "auth_compliance",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
]
