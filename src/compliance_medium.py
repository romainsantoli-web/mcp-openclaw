"""
compliance_medium.py — Sprint 3 Medium-priority compliance tools.

Covers gaps: M1 (Tool deprecation lifecycle), M2 (Circuit breaker audit),
M3 (GDPR / data residency), M4 (Agent identity / DID),
M5 (Multi-model routing), M6 (Resource links in tool results).

Each tool audits config for a specific compliance domain.
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



# ─── M1: Tool Deprecation Lifecycle ───────────────────────────────────────

# MCP 2025-03-26 annotations include hints but no formal deprecation.
# Best practice: use a custom `deprecated` annotation + `sunset` date.

_DEPRECATION_KEYS = {"deprecated", "sunset", "replacement", "deprecatedMessage"}


async def tool_deprecation_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit tool deprecation lifecycle compliance.

    Checks:
    - Tools with deprecated=true have a sunset date
    - Sunset dates are ISO 8601 format
    - Deprecated tools have a replacement tool specified
    - No circular deprecation chains (A→B→A)
    - Annotations include deprecation metadata if deprecated
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    tools_config = _get_nested(config, "mcp.tools", [])
    if not isinstance(tools_config, list):
        tools_config = _get_nested(config, "tools", [])
    if not isinstance(tools_config, list):
        findings.append("INFO: No tools list found in config — cannot audit deprecation lifecycle")
        return {
            "ok": len(findings) == 0,
            "severity": "INFO",
            "findings": findings,
            "finding_count": len(findings),
            "config_path": path,
            "feature": "tool_deprecation",
        }

    deprecated_tools: dict[str, dict] = {}
    replacement_map: dict[str, str] = {}
    all_tool_names = set()

    for tool in tools_config:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name", "")
        all_tool_names.add(name)
        annotations = tool.get("annotations", {})
        if not isinstance(annotations, dict):
            continue

        is_deprecated = annotations.get("deprecated", False)
        if not is_deprecated:
            # Check if tool has sunset date without being marked deprecated
            if "sunset" in annotations:
                findings.append(
                    f"HIGH: Tool '{name}' has sunset date but deprecated=false — inconsistent"
                )
            continue

        deprecated_tools[name] = annotations

        # Must have sunset date
        sunset = annotations.get("sunset")
        if not sunset:
            findings.append(f"HIGH: Deprecated tool '{name}' has no sunset date")
        else:
            # Validate ISO 8601 format
            iso_pattern = r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})?)?$"
            if not re.match(iso_pattern, str(sunset)):
                findings.append(
                    f"MEDIUM: Tool '{name}' sunset date '{sunset}' is not valid ISO 8601"
                )

        # Must have replacement
        replacement = annotations.get("replacement")
        if not replacement:
            findings.append(
                f"MEDIUM: Deprecated tool '{name}' has no replacement tool specified"
            )
        else:
            replacement_map[name] = replacement

        # Must have deprecation message
        if not annotations.get("deprecatedMessage"):
            findings.append(
                f"INFO: Deprecated tool '{name}' has no deprecatedMessage for users"
            )

    # Check circular deprecation chains
    for tool_name, replacement in replacement_map.items():
        visited = {tool_name}
        current = replacement
        while current in replacement_map:
            if current in visited:
                findings.append(
                    f"CRITICAL: Circular deprecation chain detected: "
                    f"{tool_name} → ... → {current} → loop"
                )
                break
            visited.add(current)
            current = replacement_map[current]

    # Check replacements point to existing tools
    for tool_name, replacement in replacement_map.items():
        if replacement not in all_tool_names:
            findings.append(
                f"HIGH: Deprecated tool '{tool_name}' replacement '{replacement}' "
                f"does not exist in tool registry"
            )

    severity = "OK"
    if any(f.startswith("CRITICAL") for f in findings):
        severity = "CRITICAL"
    elif any(f.startswith("HIGH") for f in findings):
        severity = "HIGH"
    elif any(f.startswith("MEDIUM") for f in findings):
        severity = "MEDIUM"
    elif findings:
        severity = "INFO"

    return {
        "ok": not any(f.startswith(("CRITICAL", "HIGH")) for f in findings),
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "config_path": path,
        "feature": "tool_deprecation",
        "deprecated_tool_count": len(deprecated_tools),
        "total_tool_count": len(all_tool_names),
    }


# ─── M2: Circuit Breaker Pattern Audit ────────────────────────────────────

_EXTERNAL_CALL_PATTERNS = {
    "http", "https", "webhook", "a2a", "n8n", "api",
    "fetch", "request", "proxy", "upstream", "remote",
}


async def circuit_breaker_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit circuit breaker / resilience patterns for external calls.

    Checks:
    - External-facing tools have timeout configuration
    - Retry policies are defined with backoff
    - Circuit breaker state management (open/half-open/closed)
    - Fallback behavior is specified
    - Max retry count is bounded (≤ 5)
    - Timeout values are reasonable (1s-120s)
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    resilience = _get_nested(config, "mcp.resilience", {})
    if not isinstance(resilience, dict):
        resilience = {}

    # Check global circuit breaker config
    cb_config = resilience.get("circuitBreaker", {})
    if not cb_config:
        findings.append(
            "HIGH: No global circuit breaker configuration found — "
            "external calls have no resilience"
        )
    else:
        # Threshold
        failure_threshold = cb_config.get("failureThreshold")
        if failure_threshold is None:
            findings.append("MEDIUM: Circuit breaker missing failureThreshold")
        elif not isinstance(failure_threshold, (int, float)) or failure_threshold < 1:
            findings.append(
                f"MEDIUM: Circuit breaker failureThreshold={failure_threshold} invalid (must be ≥1)"
            )

        # Reset timeout
        reset_timeout = cb_config.get("resetTimeoutMs")
        if reset_timeout is None:
            findings.append("MEDIUM: Circuit breaker missing resetTimeoutMs")
        elif not isinstance(reset_timeout, (int, float)) or reset_timeout < 1000:
            findings.append(
                f"MEDIUM: Circuit breaker resetTimeoutMs={reset_timeout} too low (<1s)"
            )

        # Half-open max requests
        half_open_max = cb_config.get("halfOpenMaxRequests", 1)
        if not isinstance(half_open_max, int) or half_open_max < 1:
            findings.append("MEDIUM: Circuit breaker halfOpenMaxRequests must be ≥1")

    # Check retry policy
    retry = resilience.get("retry", {})
    if not retry:
        findings.append("HIGH: No retry policy configured for external calls")
    else:
        max_retries = retry.get("maxRetries")
        if max_retries is None:
            findings.append("MEDIUM: Retry policy missing maxRetries")
        elif not isinstance(max_retries, int) or max_retries > 5:
            findings.append(
                f"HIGH: Retry maxRetries={max_retries} too high (max recommended: 5)"
            )
        elif max_retries < 0:
            findings.append(f"MEDIUM: Retry maxRetries={max_retries} invalid (must be ≥0)")

        backoff = retry.get("backoff", retry.get("backoffMs"))
        if not backoff:
            findings.append("MEDIUM: Retry policy has no backoff/backoffMs — risk of thundering herd")

        backoff_type = retry.get("backoffType", "")
        if backoff_type and backoff_type not in ("exponential", "linear", "fixed", "jitter"):
            findings.append(
                f"INFO: Retry backoffType='{backoff_type}' is non-standard "
                f"(expected: exponential, linear, fixed, jitter)"
            )

    # Check timeout configuration
    timeout = resilience.get("timeout", resilience.get("timeoutMs"))
    if not timeout:
        timeout = _get_nested(config, "mcp.timeout", None)
    if not timeout:
        findings.append("HIGH: No timeout configured for external calls")
    else:
        timeout_val = timeout if isinstance(timeout, (int, float)) else 0
        if timeout_val > 120000:
            findings.append(
                f"MEDIUM: Timeout {timeout_val}ms exceeds 120s recommended maximum"
            )
        elif timeout_val < 1000 and timeout_val > 0:
            findings.append(
                f"MEDIUM: Timeout {timeout_val}ms is very low (<1s) — may cause false failures"
            )

    # Check fallback configuration
    fallback = resilience.get("fallback", {})
    if not fallback:
        findings.append("INFO: No fallback behavior configured — errors propagate directly")

    # Check per-tool resilience overrides
    tools_config = _get_nested(config, "mcp.tools", [])
    if isinstance(tools_config, list):
        for tool in tools_config:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "")
            tool_desc = str(tool.get("description", "")).lower()
            has_external = any(p in tool_desc for p in _EXTERNAL_CALL_PATTERNS)
            if has_external and "resilience" not in tool and "timeout" not in tool:
                findings.append(
                    f"INFO: External-facing tool '{name}' has no per-tool resilience override"
                )

    severity = "OK"
    if any(f.startswith("CRITICAL") for f in findings):
        severity = "CRITICAL"
    elif any(f.startswith("HIGH") for f in findings):
        severity = "HIGH"
    elif any(f.startswith("MEDIUM") for f in findings):
        severity = "MEDIUM"
    elif findings:
        severity = "INFO"

    return {
        "ok": not any(f.startswith(("CRITICAL", "HIGH")) for f in findings),
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "config_path": path,
        "feature": "circuit_breaker",
    }


# ─── M3: GDPR / Data Residency Audit ─────────────────────────────────────

_PII_FIELD_PATTERNS = re.compile(
    r"(email|phone|address|name|ssn|birth|passport|national_id|"
    r"credit_card|iban|ip_address|location|gps|latitude|longitude|"
    r"first.?name|last.?name|date.?of.?birth|social.?security)",
    re.IGNORECASE,
)

_VALID_LEGAL_BASES = {
    "consent", "contract", "legal_obligation", "vital_interests",
    "public_task", "legitimate_interests",
}

_VALID_REGIONS = {
    "eu", "eea", "us", "uk", "ch", "ca", "au", "jp", "kr", "sg",
    "br", "in", "cn", "za", "global",
}


async def gdpr_residency_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit GDPR and data residency compliance.

    Checks:
    - Data processing declarations exist
    - Legal basis for processing is specified
    - Data retention periods are defined
    - Data residency / region constraints
    - PII field declarations in tool schemas
    - Right to erasure mechanism
    - Data processing agreements (DPA) reference
    - Cross-border transfer safeguards (SCC, adequacy)
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    privacy = _get_nested(config, "mcp.privacy", {})
    if not isinstance(privacy, dict):
        privacy = {}
    gdpr = _get_nested(config, "mcp.gdpr", privacy.get("gdpr", {}))
    if not isinstance(gdpr, dict):
        gdpr = {}

    # Check data processing declaration
    if not privacy and not gdpr:
        findings.append(
            "HIGH: No privacy/GDPR configuration found — "
            "data processing without legal basis"
        )
    else:
        # Legal basis
        legal_basis = gdpr.get("legalBasis", privacy.get("legalBasis"))
        if not legal_basis:
            findings.append("HIGH: No legal basis for data processing declared")
        elif isinstance(legal_basis, str) and legal_basis.lower() not in _VALID_LEGAL_BASES:
            findings.append(
                f"MEDIUM: Legal basis '{legal_basis}' is non-standard GDPR basis"
            )

        # Retention period
        retention = gdpr.get("retentionDays", privacy.get("retentionDays"))
        if retention is None:
            findings.append("HIGH: No data retention period defined")
        elif isinstance(retention, (int, float)):
            if retention <= 0:
                findings.append("MEDIUM: Data retention period must be positive")
            elif retention > 3650:
                findings.append(
                    f"MEDIUM: Data retention {retention} days (>10 years) — "
                    f"verify proportionality"
                )

        # Right to erasure
        erasure = gdpr.get("rightToErasure", privacy.get("erasure", {}))
        if not erasure:
            findings.append("HIGH: No right-to-erasure mechanism declared")
        else:
            if isinstance(erasure, dict):
                if not erasure.get("endpoint") and not erasure.get("tool"):
                    findings.append(
                        "MEDIUM: Right to erasure declared but no endpoint/tool specified"
                    )

        # DPA reference
        if not gdpr.get("dpa") and not privacy.get("dpa"):
            findings.append("INFO: No Data Processing Agreement (DPA) reference")

    # Check data residency
    residency = _get_nested(config, "mcp.dataResidency", {})
    if not isinstance(residency, dict):
        residency = privacy.get("dataResidency", {})
    if not residency:
        findings.append("MEDIUM: No data residency configuration — "
                        "data may be processed in any region")
    else:
        region = residency.get("region", residency.get("primaryRegion"))
        if not region:
            findings.append("MEDIUM: Data residency declared but no primary region set")
        elif isinstance(region, str) and region.lower() not in _VALID_REGIONS:
            findings.append(f"INFO: Data residency region '{region}' is non-standard")

        # Cross-border transfers
        transfers = residency.get("crossBorderTransfers", {})
        if isinstance(transfers, dict):
            mechanism = transfers.get("mechanism")
            if mechanism and mechanism not in (
                "scc", "adequacy_decision", "bcr", "derogation", "none"
            ):
                findings.append(
                    f"INFO: Cross-border transfer mechanism '{mechanism}' is non-standard"
                )
        elif residency.get("allowCrossBorder", True):
            findings.append(
                "INFO: Cross-border transfers allowed but no safeguard mechanism specified"
            )

    # Check tool schemas for undeclared PII fields
    tools_config = _get_nested(config, "mcp.tools", [])
    if isinstance(tools_config, list):
        for tool in tools_config:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "")
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            for field_name in props:
                if _PII_FIELD_PATTERNS.search(field_name):
                    pii_decl = tool.get("piiFields", tool.get("annotations", {}).get("piiFields"))
                    if not pii_decl:
                        findings.append(
                            f"HIGH: Tool '{name}' has PII-like field '{field_name}' "
                            f"but no piiFields declaration"
                        )
                    break

    severity = "OK"
    if any(f.startswith("CRITICAL") for f in findings):
        severity = "CRITICAL"
    elif any(f.startswith("HIGH") for f in findings):
        severity = "HIGH"
    elif any(f.startswith("MEDIUM") for f in findings):
        severity = "MEDIUM"
    elif findings:
        severity = "INFO"

    return {
        "ok": not any(f.startswith(("CRITICAL", "HIGH")) for f in findings),
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "config_path": path,
        "feature": "gdpr_residency",
    }


# ─── M4: Agent Identity / DID Audit ──────────────────────────────────────

_VALID_DID_METHODS = {"did:web", "did:key", "did:pkh", "did:ion", "did:ethr", "did:jwk"}
_DID_PATTERN = re.compile(r"^did:[a-z]+:[a-zA-Z0-9._:%-]+$")


async def agent_identity_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit agent identity and DID (Decentralized Identifier) compliance.

    Checks:
    - Agent cards have identity declarations
    - DID format is valid (did:method:specific-id)
    - DID method is well-known (did:web, did:key, etc.)
    - Verification methods are present
    - Agent signing capabilities
    - Multi-agent identity federation
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    # Check agent identity config
    agents = _get_nested(config, "mcp.agents", [])
    if not isinstance(agents, list):
        agents_map = _get_nested(config, "agents", {})
        if isinstance(agents_map, dict):
            agents = [{"name": k, **v} for k, v in agents_map.items() if isinstance(v, dict)]

    identity_config = _get_nested(config, "mcp.identity", {})
    if not isinstance(identity_config, dict):
        identity_config = {}

    if not agents and not identity_config:
        findings.append(
            "INFO: No agent identity configuration found — agents have no verifiable identity"
        )
        return {
            "ok": True,
            "severity": "INFO",
            "findings": findings,
            "finding_count": len(findings),
            "config_path": path,
            "feature": "agent_identity",
            "agent_count": 0,
        }

    # Check global identity settings
    if identity_config:
        did = identity_config.get("did", "")
        if did:
            if not _DID_PATTERN.match(did):
                findings.append(f"HIGH: Server DID '{did}' is not valid DID format")
            else:
                method = did.split(":")[0] + ":" + did.split(":")[1]
                if method not in _VALID_DID_METHODS:
                    findings.append(
                        f"INFO: Server DID method '{method}' is not a well-known method"
                    )

        verification = identity_config.get("verificationMethod", [])
        if not verification:
            findings.append(
                "MEDIUM: No verification method for server identity — "
                "cannot prove identity to peers"
            )

        signing = identity_config.get("signing", {})
        if isinstance(signing, dict):
            alg = signing.get("algorithm", "")
            if alg and alg.lower() in ("none", "hs256"):
                findings.append(
                    f"HIGH: Signing algorithm '{alg}' is weak/insecure — "
                    f"use EdDSA, ES256, or RS256+"
                )

    # Check per-agent identity
    agents_with_did = 0
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        name = agent.get("name", "unknown")
        agent_did = agent.get("did", agent.get("identity", {}).get("did", ""))

        if agent_did:
            agents_with_did += 1
            if not _DID_PATTERN.match(str(agent_did)):
                findings.append(f"HIGH: Agent '{name}' DID '{agent_did}' is not valid format")
        else:
            findings.append(
                f"MEDIUM: Agent '{name}' has no DID — "
                f"cannot participate in identity federation"
            )

        # Check signing capabilities
        agent_signing = agent.get("signing", agent.get("identity", {}).get("signing", {}))
        if not agent_signing and agent_did:
            findings.append(
                f"INFO: Agent '{name}' has DID but no signing configuration"
            )

    severity = "OK"
    if any(f.startswith("CRITICAL") for f in findings):
        severity = "CRITICAL"
    elif any(f.startswith("HIGH") for f in findings):
        severity = "HIGH"
    elif any(f.startswith("MEDIUM") for f in findings):
        severity = "MEDIUM"
    elif findings:
        severity = "INFO"

    return {
        "ok": not any(f.startswith(("CRITICAL", "HIGH")) for f in findings),
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "config_path": path,
        "feature": "agent_identity",
        "agent_count": len(agents),
        "agents_with_did": agents_with_did,
    }


# ─── M5: Multi-Model Routing Audit ───────────────────────────────────────

_KNOWN_PROVIDERS = {
    "anthropic", "openai", "google", "cohere", "mistral", "meta",
    "amazon", "azure", "ollama", "groq", "together", "fireworks",
    "deepseek", "perplexity", "huggingface",
}

_DANGEROUS_ROUTING_PATTERNS = {
    "round_robin",  # No quality differentiation
    "random",       # Unpredictable behavior
}


async def model_routing_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit multi-model routing configuration.

    Checks:
    - Routing strategy is defined (latency, cost, quality, fallback)
    - Model providers are known/supported
    - Fallback chain is configured
    - Model-specific rate limits
    - Cost caps / budget limits
    - Model capability matching (vision, code, long-context)
    - Dangerous routing patterns (random, round-robin without weights)
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    routing = _get_nested(config, "mcp.routing", {})
    if not isinstance(routing, dict):
        routing = _get_nested(config, "routing", {})
    if not isinstance(routing, dict):
        routing = {}

    models = _get_nested(config, "mcp.models", routing.get("models", []))
    if not isinstance(models, list):
        models = []

    if not routing and not models:
        findings.append(
            "INFO: No multi-model routing configuration found — single model assumed"
        )
        return {
            "ok": True,
            "severity": "INFO",
            "findings": findings,
            "finding_count": len(findings),
            "config_path": path,
            "feature": "model_routing",
            "model_count": 0,
        }

    # Check routing strategy
    strategy = routing.get("strategy", "")
    if not strategy:
        findings.append("HIGH: No routing strategy defined — requests may be misrouted")
    elif strategy.lower() in _DANGEROUS_ROUTING_PATTERNS:
        findings.append(
            f"MEDIUM: Routing strategy '{strategy}' is non-deterministic — "
            f"prefer cost-aware, latency-based, or capability-matched routing"
        )

    # Check fallback chain
    fallback = routing.get("fallback", routing.get("fallbackChain", []))
    if not fallback:
        findings.append(
            "HIGH: No fallback chain configured — "
            "single model failure = total outage"
        )
    elif isinstance(fallback, list) and len(fallback) < 2:
        findings.append(
            "MEDIUM: Fallback chain has only 1 entry — "
            "add at least one backup model"
        )

    # Check budget / cost caps
    budget = routing.get("budget", routing.get("costCap", {}))
    if not budget:
        findings.append(
            "MEDIUM: No cost cap / budget configured — unbounded spending risk"
        )
    else:
        if isinstance(budget, dict):
            if not budget.get("maxDailyCostUsd") and not budget.get("maxMonthlyCostUsd"):
                findings.append("MEDIUM: Budget configured but no daily/monthly cap set")

    # Check model definitions
    providers_seen = set()
    for model in models:
        if not isinstance(model, dict):
            continue
        provider = model.get("provider", "").lower()
        model_id = model.get("id", model.get("model", ""))

        if provider:
            providers_seen.add(provider)
            if provider not in _KNOWN_PROVIDERS:
                findings.append(
                    f"INFO: Model provider '{provider}' is not in known providers list"
                )

        # Rate limit check
        if not model.get("rateLimit") and not model.get("rateLimitRpm"):
            findings.append(
                f"MEDIUM: Model '{model_id}' ({provider}) has no rate limit configured"
            )

        # Capability declarations
        capabilities = model.get("capabilities", [])
        if not capabilities:
            findings.append(
                f"INFO: Model '{model_id}' has no capability declarations "
                f"(vision, code, long-context, etc.)"
            )

        # Context window check
        context_window = model.get("contextWindow", model.get("maxTokens"))
        if not context_window:
            findings.append(
                f"INFO: Model '{model_id}' has no context window size declared"
            )

    # Check for single provider dependency
    if len(providers_seen) == 1 and len(models) > 1:
        findings.append(
            f"MEDIUM: All models use provider '{list(providers_seen)[0]}' — "
            f"consider multi-provider for resilience"
        )

    severity = "OK"
    if any(f.startswith("CRITICAL") for f in findings):
        severity = "CRITICAL"
    elif any(f.startswith("HIGH") for f in findings):
        severity = "HIGH"
    elif any(f.startswith("MEDIUM") for f in findings):
        severity = "MEDIUM"
    elif findings:
        severity = "INFO"

    return {
        "ok": not any(f.startswith(("CRITICAL", "HIGH")) for f in findings),
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "config_path": path,
        "feature": "model_routing",
        "model_count": len(models),
        "providers": sorted(providers_seen),
    }


# ─── M6: Resource Links in Tool Results Audit ────────────────────────────

async def resource_links_audit(config_path: str | None = None) -> dict[str, Any]:
    """Audit resource link usage in tool results (MCP 2025-06-18).

    Checks:
    - Tools declare resource link output capability
    - Resource URIs follow RFC 3986 / MCP URI templates
    - MIME types are valid for linked resources
    - Resource links have proper name/description
    - No dangling resource references
    - Resource subscriptions configured
    """
    config, path = _load_config(config_path)
    findings: list[str] = []

    # Check capabilities for resources
    capabilities = _get_nested(config, "mcp.capabilities", {})
    resources_cap = capabilities.get("resources", {})

    if not resources_cap:
        findings.append(
            "HIGH: No 'resources' capability declared — "
            "resource links in tool results won't work"
        )
    else:
        if not resources_cap.get("subscribe"):
            findings.append(
                "MEDIUM: Resources capability missing 'subscribe' — "
                "clients can't watch for resource changes"
            )
        if not resources_cap.get("listChanged"):
            findings.append(
                "INFO: Resources capability missing 'listChanged' notification"
            )

    # Check resource templates
    templates = _get_nested(config, "mcp.resources.templates", [])
    if not isinstance(templates, list):
        templates = []

    resources = _get_nested(config, "mcp.resources.static", [])
    if not isinstance(resources, list):
        resources = _get_nested(config, "mcp.resources", [])
        if not isinstance(resources, list):
            resources = []

    all_resource_uris = set()
    uri_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

    for idx, res in enumerate(resources):
        if not isinstance(res, dict):
            continue
        uri = res.get("uri", "")
        if not uri:
            findings.append(f"HIGH: Resource at index {idx} has no URI")
            continue

        all_resource_uris.add(uri)

        if not uri_pattern.match(uri):
            findings.append(
                f"MEDIUM: Resource URI '{uri}' does not follow RFC 3986 scheme://..."
            )

        # Must have name
        if not res.get("name"):
            findings.append(f"MEDIUM: Resource '{uri}' has no name")

        # MIME type check
        mime = res.get("mimeType")
        if mime and "/" not in mime:
            findings.append(f"MEDIUM: Resource '{uri}' mimeType '{mime}' invalid (no /)")

    for idx, tpl in enumerate(templates):
        if not isinstance(tpl, dict):
            continue
        uri_tpl = tpl.get("uriTemplate", "")
        if not uri_tpl:
            findings.append(f"HIGH: Resource template at index {idx} has no uriTemplate")
            continue
        if not uri_pattern.match(uri_tpl.split("{")[0]):
            findings.append(
                f"MEDIUM: Resource template '{uri_tpl}' scheme does not follow RFC 3986"
            )
        if not tpl.get("name"):
            findings.append(f"MEDIUM: Resource template '{uri_tpl}' has no name")

    # Check tools for resource_link output declarations
    tools_config = _get_nested(config, "mcp.tools", [])
    if isinstance(tools_config, list):
        tools_with_resource_links = 0
        for tool in tools_config:
            if not isinstance(tool, dict):
                continue
            output_schema = tool.get("outputSchema", {})
            if isinstance(output_schema, dict):
                # Check if output references resource_link type
                out_str = json.dumps(output_schema)
                if "resource_link" in out_str or "resource" in out_str.lower():
                    tools_with_resource_links += 1
                    # Verify referenced resources exist
                    ref_uri = _get_nested(output_schema, "properties.resource.uri")
                    if ref_uri and ref_uri not in all_resource_uris and "{" not in ref_uri:
                        findings.append(
                            f"INFO: Tool '{tool.get('name', '')}' references "
                            f"resource URI '{ref_uri}' not in declared resources"
                        )

    severity = "OK"
    if any(f.startswith("CRITICAL") for f in findings):
        severity = "CRITICAL"
    elif any(f.startswith("HIGH") for f in findings):
        severity = "HIGH"
    elif any(f.startswith("MEDIUM") for f in findings):
        severity = "MEDIUM"
    elif findings:
        severity = "INFO"

    return {
        "ok": not any(f.startswith(("CRITICAL", "HIGH")) for f in findings),
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "config_path": path,
        "feature": "resource_links",
        "resource_count": len(resources),
        "template_count": len(templates),
    }


# ─── Shared output schema ─────────────────────────────────────────────────

_CONFIG_PATH_SCHEMA = {
    "type": "object",
    "properties": {
        "config_path": {
            "type": "string",
            "description": "Path to openclaw.json config file (optional, defaults to ./openclaw.json).",
        }
    },
}

_AUDIT_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "ok":            {"type": "boolean"},
        "severity":      {"type": "string"},
        "findings":      {"type": "array", "items": {"type": "string"}},
        "finding_count": {"type": "integer"},
        "config_path":   {"type": "string"},
        "feature":       {"type": "string"},
    },
    "required": ["ok", "severity", "findings", "finding_count", "config_path", "feature"],
}

# ─── Tool definitions ─────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_tool_deprecation_audit",
        "title": "Tool Deprecation Lifecycle Audit",
        "description": "Audit tool deprecation lifecycle — sunset dates, replacements, circular chains.",
        "category": "compliance_medium",
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "handler": tool_deprecation_audit,
    },
    {
        "name": "openclaw_circuit_breaker_audit",
        "title": "Circuit Breaker Pattern Audit",
        "description": "Audit circuit breaker / resilience configuration for external calls — timeouts, retries, fallback.",
        "category": "compliance_medium",
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "handler": circuit_breaker_audit,
    },
    {
        "name": "openclaw_gdpr_residency_audit",
        "title": "GDPR & Data Residency Audit",
        "description": "Audit GDPR compliance and data residency — legal basis, retention, PII fields, cross-border transfers.",
        "category": "compliance_medium",
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "handler": gdpr_residency_audit,
    },
    {
        "name": "openclaw_agent_identity_audit",
        "title": "Agent Identity / DID Audit",
        "description": "Audit agent decentralized identity (DID) — format, verification methods, signing, federation.",
        "category": "compliance_medium",
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "handler": agent_identity_audit,
    },
    {
        "name": "openclaw_model_routing_audit",
        "title": "Multi-Model Routing Audit",
        "description": "Audit multi-model routing — strategy, fallback chain, cost caps, provider diversity.",
        "category": "compliance_medium",
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "handler": model_routing_audit,
    },
    {
        "name": "openclaw_resource_links_audit",
        "title": "Resource Links Audit",
        "description": "Audit MCP resource links in tool results — URI validation, MIME types, subscriptions, templates.",
        "category": "compliance_medium",
        "inputSchema": _CONFIG_PATH_SCHEMA,
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "handler": resource_links_audit,
    },
]
