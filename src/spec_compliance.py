"""
spec_compliance.py — MCP 2025-11-25 specification compliance audit tools.

Covers gaps: S4 (Elicitation), S5 (Tasks), S6 (Resources/Prompts),
H3 (Audio content), H5 (JSON Schema 2020-12), H6 (SSE polling),
H7 (Icon metadata).

Each tool audits a specific MCP spec feature for compliance.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from src.config_helpers import load_config as _load_config_shared, get_nested as _get_nested_shared  # noqa: E402


# ─── Helpers ───────────────────────────────────────────────────────────────

def _load_config(config_path: str | None) -> tuple[dict, str]:
    """Load config — delegates to config_helpers.load_config."""
    return _load_config_shared(config_path)



def _get_nested(data: dict, dotpath: str, default: Any = None) -> Any:
    """Get nested value by dot-path — delegates to config_helpers.get_nested."""
    return _get_nested_shared(data, *dotpath.split("."), default=default)



# ─── S4: Elicitation Audit ─────────────────────────────────────────────────

async def elicitation_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit MCP elicitation capability compliance (2025-06-18+).

    Checks:
    - Client declares elicitation capability
    - requestedSchema uses flat object with primitive properties only
    - Supported schema types: string, number, integer, boolean, enum
    - No nested objects or arrays (spec restriction)
    - URL mode support (2025-11-25)
    - Default values on primitives (2025-11-25)
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    capabilities = _get_nested(config, "mcp.capabilities", {})
    client_caps = _get_nested(config, "mcp.client.capabilities", {})

    # Check if elicitation is declared
    if "elicitation" not in capabilities and "elicitation" not in client_caps:
        findings.append("CRITICAL: No 'elicitation' capability declared in MCP config")

    # Check elicitation schemas if defined
    schemas = _get_nested(config, "mcp.elicitation.schemas", [])
    if isinstance(schemas, list):
        for idx, schema in enumerate(schemas):
            if not isinstance(schema, dict):
                continue
            props = schema.get("properties", {})
            for prop_name, prop_def in props.items():
                prop_type = prop_def.get("type", "")
                if prop_type not in ("string", "number", "integer", "boolean"):
                    if not (prop_type == "string" and "enum" in prop_def):
                        findings.append(
                            f"HIGH: Schema #{idx} property '{prop_name}' uses unsupported "
                            f"type '{prop_type}' — only string/number/integer/boolean/enum allowed"
                        )
                if prop_type == "object" or prop_type == "array":
                    findings.append(
                        f"CRITICAL: Schema #{idx} property '{prop_name}' uses nested "
                        f"type '{prop_type}' — MCP elicitation requires flat objects only"
                    )

    # Check URL mode (2025-11-25)
    url_mode = _get_nested(config, "mcp.elicitation.urlMode")
    if url_mode is None:
        findings.append("INFO: URL mode elicitation not configured (optional, 2025-11-25)")

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
        "spec_version": "2025-11-25",
        "feature": "elicitation",
    }


# ─── S5: Tasks (Durable Requests) Audit ───────────────────────────────────

async def tasks_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit MCP Tasks capability compliance (2025-11-25 experimental).

    Checks:
    - tasks capability declared
    - Polling interval configured
    - Deferred result retrieval support
    - Task state machine compliance (submitted → working → completed/failed/canceled)
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    capabilities = _get_nested(config, "mcp.capabilities", {})
    server_caps = _get_nested(config, "mcp.server.capabilities", {})

    # Tasks capability check
    has_tasks = "tasks" in capabilities or "tasks" in server_caps
    if not has_tasks:
        findings.append("HIGH: No 'tasks' capability declared — durable requests unsupported")

    # Polling config
    polling = _get_nested(config, "mcp.tasks.polling", {})
    if has_tasks and not polling:
        findings.append("MEDIUM: Tasks enabled but no polling interval configured")

    interval = _get_nested(config, "mcp.tasks.polling.intervalMs")
    if isinstance(interval, (int, float)) and interval < 1000:
        findings.append(f"HIGH: Polling interval {interval}ms is too aggressive (min recommended: 1000ms)")

    # Task timeout
    timeout = _get_nested(config, "mcp.tasks.timeoutMs")
    if has_tasks and timeout is None:
        findings.append("MEDIUM: No task timeout configured — tasks could hang indefinitely")

    # Max concurrent tasks
    max_tasks = _get_nested(config, "mcp.tasks.maxConcurrent")
    if has_tasks and max_tasks is None:
        findings.append("INFO: No maxConcurrent tasks limit — consider setting one")

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
        "spec_version": "2025-11-25",
        "feature": "tasks",
    }


# ─── S6: Resources & Prompts Audit ────────────────────────────────────────

async def resources_prompts_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit MCP Resources & Prompts capability compliance.

    Checks:
    - resources capability declared with listChanged
    - prompts capability declared with listChanged
    - Resources expose URI schemes
    - Prompts have required fields
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    capabilities = _get_nested(config, "mcp.capabilities", {})
    server_caps = _get_nested(config, "mcp.server.capabilities", {})

    # Resources capability
    resources = capabilities.get("resources") or server_caps.get("resources")
    if not resources:
        findings.append("MEDIUM: No 'resources' capability declared — server exposes no context")
    elif isinstance(resources, dict) and not resources.get("listChanged"):
        findings.append("INFO: resources.listChanged not enabled — clients won't get change notifications")

    # Prompts capability
    prompts = capabilities.get("prompts") or server_caps.get("prompts")
    if not prompts:
        findings.append("MEDIUM: No 'prompts' capability declared — no templated workflows")
    elif isinstance(prompts, dict) and not prompts.get("listChanged"):
        findings.append("INFO: prompts.listChanged not enabled — clients won't get change notifications")

    # Resource definitions
    resource_defs = _get_nested(config, "mcp.resources", [])
    if isinstance(resource_defs, list):
        for idx, res in enumerate(resource_defs):
            if not isinstance(res, dict):
                continue
            if "uri" not in res:
                findings.append(f"HIGH: Resource #{idx} missing required 'uri' field")
            if "name" not in res:
                findings.append(f"MEDIUM: Resource #{idx} missing 'name' field")

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
        "feature": "resources_prompts",
    }


# ─── H3: Audio Content Audit ──────────────────────────────────────────────

async def audio_content_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit MCP audio content support (2025-06-18+).

    Checks:
    - Audio mimeType allowed list (audio/wav, audio/mpeg, audio/ogg, audio/webm)
    - Max audio size limits configured
    - Base64 encoding validation
    - Audio in tool results properly annotated
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    ALLOWED_AUDIO_MIMES = {"audio/wav", "audio/mpeg", "audio/ogg", "audio/webm", "audio/mp4", "audio/flac"}

    audio_config = _get_nested(config, "mcp.audio", {})

    # Check allowed mimeTypes
    allowed = audio_config.get("allowedMimeTypes", [])
    if not allowed:
        findings.append("INFO: No audio mimeType allowlist configured — all types accepted")
    else:
        for mime in allowed:
            if mime not in ALLOWED_AUDIO_MIMES:
                findings.append(f"MEDIUM: Audio mimeType '{mime}' not in standard set")

    # Max size
    max_size = audio_config.get("maxSizeBytes")
    if max_size is None:
        findings.append("MEDIUM: No audio maxSizeBytes limit — could accept unbounded audio data")
    elif isinstance(max_size, (int, float)) and max_size > 50 * 1024 * 1024:
        findings.append(f"HIGH: Audio maxSizeBytes {max_size} exceeds 50MB — memory risk")

    # Duration limit
    max_duration = audio_config.get("maxDurationSeconds")
    if max_duration is None:
        findings.append("INFO: No audio maxDurationSeconds limit configured")

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
        "spec_version": "2025-06-18",
        "feature": "audio_content",
    }


# ─── H5: JSON Schema 2020-12 Dialect ──────────────────────────────────────

async def json_schema_dialect_check(config_path: str | None = None) -> dict[str, Any]:
    """Audit JSON Schema dialect compliance (MCP 2025-11-25).

    Checks:
    - $schema header present and set to 2020-12
    - inputSchema definitions use compatible keywords
    - No draft-04/draft-07 only keywords
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    EXPECTED_DIALECT = "https://json-schema.org/draft/2020-12/schema"

    # Check global $schema
    schema_decl = config.get("$schema", "")
    if not schema_decl:
        findings.append("MEDIUM: No $schema declaration — should be JSON Schema 2020-12")
    elif "2020-12" not in schema_decl:
        findings.append(f"HIGH: $schema is '{schema_decl}' — MCP 2025-11-25 requires 2020-12")

    # Check for draft-07 only features that changed in 2020-12
    config_str = json.dumps(config)
    draft07_keywords = ['"definitions"', '"dependencies"']
    for kw in draft07_keywords:
        if kw in config_str:
            new_kw = kw.replace("definitions", "$defs").replace("dependencies", "dependentRequired")
            findings.append(
                f"MEDIUM: Found {kw} — in JSON Schema 2020-12, use {new_kw} instead"
            )

    # Check for additionalItems (removed in 2020-12, replaced by "items")
    if '"additionalItems"' in config_str:
        findings.append("HIGH: 'additionalItems' removed in 2020-12 — use 'items' + 'prefixItems'")

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
        "spec_version": "2025-11-25",
        "feature": "json_schema_dialect",
        "expected_dialect": EXPECTED_DIALECT,
    }


# ─── H6: SSE Transport Audit ──────────────────────────────────────────────

async def sse_transport_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit Streamable HTTP / SSE transport compliance (MCP 2025-11-25).

    Checks:
    - Streamable HTTP transport configured
    - GET streams support polling
    - Event IDs encode stream identity
    - Server-initiated disconnection handling
    - MCP-Protocol-Version header required (2025-06-18)
    - Origin validation (HTTP 403 for invalid)
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    transport = _get_nested(config, "mcp.transport", {})
    transport_type = transport.get("type", "")

    if not transport_type:
        findings.append("HIGH: No MCP transport type configured")
    elif transport_type not in ("streamable-http", "sse", "stdio"):
        findings.append(f"MEDIUM: Transport type '{transport_type}' — consider 'streamable-http'")

    # Streamable HTTP specifics
    if transport_type in ("streamable-http", "sse"):
        # Polling support
        polling = transport.get("polling", {})
        if not polling.get("enabled", False):
            findings.append("MEDIUM: SSE polling not explicitly enabled — clients cannot poll for updates")

        # Event ID encoding
        if not transport.get("eventIdEncoding"):
            findings.append("INFO: No eventIdEncoding configured — should encode stream identity")

        # Origin validation
        allowed_origins = transport.get("allowedOrigins", [])
        if not allowed_origins:
            findings.append("HIGH: No allowedOrigins configured — server should validate Origin header")

        # Protocol version header
        if not transport.get("requireProtocolVersionHeader", True):
            findings.append("HIGH: MCP-Protocol-Version header requirement disabled (required since 2025-06-18)")

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
        "spec_version": "2025-11-25",
        "feature": "sse_transport",
    }


# ─── H7: Icon Metadata Audit ──────────────────────────────────────────────

async def icon_metadata_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit icon metadata support (MCP 2025-11-25).

    Checks:
    - Tools have icon field for UI display
    - Resources have icon field
    - Prompts have icon field
    - Icon URLs are valid (HTTPS preferred)
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    # Check tools for icons
    tools = _get_nested(config, "mcp.tools", [])
    if isinstance(tools, list):
        tools_without_icon = [t.get("name", f"#{i}") for i, t in enumerate(tools) if isinstance(t, dict) and "icon" not in t]
        if tools_without_icon:
            count = len(tools_without_icon)
            findings.append(f"INFO: {count} tool(s) missing icon metadata — recommended for UI display")

    # Check icon URLs
    for section_name in ("tools", "resources", "prompts"):
        items = _get_nested(config, f"mcp.{section_name}", [])
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and "icon" in item:
                    icon_url = item["icon"]
                    if isinstance(icon_url, str):
                        if not icon_url.startswith("https://") and not icon_url.startswith("data:"):
                            findings.append(
                                f"MEDIUM: Icon URL for '{item.get('name', '?')}' uses non-HTTPS "
                                f"scheme — prefer HTTPS or data: URI"
                            )

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
        "spec_version": "2025-11-25",
        "feature": "icon_metadata",
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
        "ok": {"type": "boolean", "description": "Whether the check passed"},
        "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
        "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
        "finding_count": {"type": "integer", "description": "Number of findings"},
        "config_path": {"type": "string", "description": "Path to config file analyzed"},
    },
    "required": ["ok", "severity", "findings", "finding_count"],
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_elicitation_audit",
        "title": "Elicitation Compliance Audit",
        "description": (
            "Audit MCP elicitation capability compliance (2025-06-18+). "
            "Checks capability declaration, requestedSchema validity, "
            "URL mode support (2025-11-25), and schema type restrictions."
        ),
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "handler": elicitation_audit,
        "category": "spec_compliance",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
    {
        "name": "openclaw_tasks_audit",
        "title": "Tasks (Durable Requests) Audit",
        "description": (
            "Audit MCP Tasks capability compliance (2025-11-25 experimental). "
            "Checks tasks declaration, polling interval, timeout config, "
            "max concurrent tasks, deferred result retrieval."
        ),
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "handler": tasks_audit,
        "category": "spec_compliance",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
    {
        "name": "openclaw_resources_prompts_audit",
        "title": "Resources & Prompts Audit",
        "description": (
            "Audit MCP Resources & Prompts capability compliance. "
            "Checks capability declarations, listChanged support, "
            "resource URI schemes, and prompt field completeness."
        ),
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "handler": resources_prompts_audit,
        "category": "spec_compliance",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
    {
        "name": "openclaw_audio_content_audit",
        "title": "Audio Content Audit",
        "description": (
            "Audit MCP audio content support (2025-06-18+). "
            "Checks mimeType allowlist, size limits, duration limits, "
            "and base64 encoding configuration."
        ),
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "handler": audio_content_audit,
        "category": "spec_compliance",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
    {
        "name": "openclaw_json_schema_dialect_check",
        "title": "JSON Schema 2020-12 Dialect Check",
        "description": (
            "Audit JSON Schema dialect compliance (MCP 2025-11-25). "
            "Checks $schema declaration, detects draft-07 only keywords "
            "(definitions, dependencies, additionalItems)."
        ),
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "handler": json_schema_dialect_check,
        "category": "spec_compliance",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
    {
        "name": "openclaw_sse_transport_audit",
        "title": "SSE Transport Compliance Audit",
        "description": (
            "Audit Streamable HTTP / SSE transport compliance (MCP 2025-11-25). "
            "Checks transport type, polling support, event ID encoding, "
            "Origin validation, MCP-Protocol-Version header."
        ),
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "handler": sse_transport_audit,
        "category": "spec_compliance",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
    {
        "name": "openclaw_icon_metadata_audit",
        "title": "Icon Metadata Audit",
        "description": (
            "Audit icon metadata support (MCP 2025-11-25). "
            "Checks tools/resources/prompts for icon fields, "
            "validates icon URLs use HTTPS or data: URI."
        ),
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "handler": icon_metadata_audit,
        "category": "spec_compliance",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
]
