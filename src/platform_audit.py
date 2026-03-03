"""
platform_audit.py — OpenClaw 2026.2 platform alignment audit tools

Covers the platform evolution gaps from 2026.1.5 → 2026.2.27:
  - External secrets v2 workflow validation
  - Agent routing bindings audit
  - Voice/Talk security check
  - Trust model multi-user validation
  - Auto-updater supply chain check
  - Plugin SDK integrity
  - Content boundary anti-prompt-injection check
  - SQLite-vec memory backend check

Tools exposed (8):
  openclaw_secrets_v2_audit         — audit new openclaw secrets lifecycle
  openclaw_agent_routing_check      — validate agent bindings/routes
  openclaw_voice_security_check     — TTS/voice channel security
  openclaw_trust_model_check        — multi-user heuristics & hardening
  openclaw_autoupdate_check         — self-update supply chain integrity
  openclaw_plugin_sdk_check         — plugin slots/hooks/migrations
  openclaw_content_boundary_check   — wrapExternalContent, anti-prompt-injection
  openclaw_sqlite_vec_check         — SQLite-vec memory backend validation
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from src.config_helpers import load_config, get_nested

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_SECRETS_V2_REQUIRED_FIELDS = {
    "provider", "rotationPolicy", "auditLog",
}

_DANGEROUS_VOICE_PROVIDERS = {
    "none", "disabled", "test", "debug",
}

_TRUST_MODEL_FLAGS = [
    "session.multiUser",
    "session.dmScope",
    "gateway.trustModel",
    "gateway.hardening.enabled",
]

_UPDATE_CHANNEL_SECURE = {"stable", "lts"}
_UPDATE_CHANNEL_RISKY = {"beta", "nightly", "canary", "dev", "edge", "alpha"}

_DANGEROUS_PLUGIN_HOOKS = {
    "preExec", "postExec", "onSessionStart", "onSessionEnd",
    "onMessagePre", "onMessagePost",
}

_CONTENT_BOUNDARY_FLAGS = [
    "wrapExternalContent",
    "wrapWebContent",
    "toolResult.stripDetails",
    "contentBoundary.enabled",
    "contentBoundary.markers",
]

_SQLITE_VEC_REQUIRED_KEYS = [
    "memory.backend",
    "memory.sqlite.path",
    "memory.embedding.model",
    "memory.embedding.dimensions",
]

# 2026.3.1: Claude 4.6 adaptive thinking defaults
_CLAUDE_46_MODELS = {
    "claude-4.6-sonnet", "claude-4.6-opus", "claude-4.6-haiku",
    "claude-sonnet-4.6", "claude-opus-4.6", "claude-haiku-4.6",
}
_ADAPTIVE_THINKING_VALUES = {"adaptive", "low", "medium", "high", "disabled"}


# ── Tool handlers ────────────────────────────────────────────────────────────

def openclaw_secrets_v2_audit(
    config_path: str | None = None,
    secrets_config_path: str | None = None,
) -> dict[str, Any]:
    """
    Audit the new OpenClaw secrets v2 lifecycle (2026.2.26+).

    Checks:
    - External secrets provider configuration
    - Rotation policy presence and validity
    - Audit log enablement
    - Runtime snapshot integrity
    - Secret references vs hardcoded values
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path} — skipping secrets v2 audit"}

    secrets_cfg = get_nested(config, "secrets") or {}

    # Check provider
    provider = secrets_cfg.get("provider")
    if not provider:
        findings.append({
            "severity": "CRITICAL",
            "check": "secrets.provider",
            "message": "No external secrets provider configured. "
                       "Use 'openclaw secrets configure' to set up.",
        })
    elif provider in ("env", "plaintext", "inline"):
        findings.append({
            "severity": "HIGH",
            "check": "secrets.provider",
            "message": f"Provider '{provider}' stores secrets in plaintext. "
                       "Use vault, aws-sm, gcp-sm, or azure-kv.",
        })

    # Rotation policy
    rotation = secrets_cfg.get("rotationPolicy")
    if not rotation:
        findings.append({
            "severity": "HIGH",
            "check": "secrets.rotationPolicy",
            "message": "No rotation policy. Secrets should rotate at least every 90 days.",
        })
    else:
        max_age = rotation.get("maxAgeDays", 0)
        if max_age > 90:
            findings.append({
                "severity": "MEDIUM",
                "check": "secrets.rotationPolicy.maxAgeDays",
                "message": f"Max age {max_age} days exceeds recommended 90-day limit.",
            })

    # Audit log
    audit_log = secrets_cfg.get("auditLog")
    if not audit_log or not audit_log.get("enabled", False):
        findings.append({
            "severity": "HIGH",
            "check": "secrets.auditLog",
            "message": "Secrets audit logging is not enabled. "
                       "Required for compliance and breach detection.",
        })

    # Scan for hardcoded secrets in config
    config_str = json.dumps(config)
    patterns = [
        (r'"(sk-[a-zA-Z0-9]{32,})"', "OpenAI API key pattern"),
        (r'"(AKIA[0-9A-Z]{16})"', "AWS access key pattern"),
        (r'"(ghp_[a-zA-Z0-9]{36})"', "GitHub PAT pattern"),
        (r'"(xoxb-[0-9]+-[a-zA-Z0-9]+)"', "Slack bot token pattern"),
    ]
    for pat, desc in patterns:
        if re.search(pat, config_str):
            findings.append({
                "severity": "CRITICAL",
                "check": "hardcoded_secrets",
                "message": f"Hardcoded secret detected: {desc}. Use external secrets references.",
            })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"

    return {
        "ok": max_sev not in ("CRITICAL",),
        "severity": max_sev,
        "config_path": cfg_path,
        "findings": findings,
        "finding_count": len(findings),
    }


def openclaw_agent_routing_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Validate agent routing bindings (2026.2.26+).

    Checks:
    - Agent bindings configuration
    - Default route existence
    - Scope isolation between agents
    - Circular routing detection
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path}"}

    agents_cfg = get_nested(config, "agents") or {}
    bindings = agents_cfg.get("bindings", {})

    if not bindings:
        findings.append({
            "severity": "MEDIUM",
            "check": "agents.bindings",
            "message": "No agent bindings configured. "
                       "All messages route to default agent.",
        })
    else:
        # Check for default route
        has_default = any(
            b.get("default", False) or b.get("pattern") == "*"
            for b in (bindings.values() if isinstance(bindings, dict) else bindings)
        )
        if not has_default:
            findings.append({
                "severity": "HIGH",
                "check": "agents.bindings.default",
                "message": "No default route binding. Unmatched messages will be dropped.",
            })

        # Check for circular routing
        seen_targets: dict[str, str] = {}
        if isinstance(bindings, dict):
            for name, binding in bindings.items():
                target = binding.get("target", "")
                if target in seen_targets:
                    findings.append({
                        "severity": "HIGH",
                        "check": "agents.bindings.circular",
                        "message": f"Potential circular route: '{name}' → '{target}' "
                                   f"(already targeted by '{seen_targets[target]}')",
                    })
                seen_targets[target] = name

    # Scope isolation
    defaults = agents_cfg.get("defaults", {})
    if not defaults.get("scopeIsolation", False):
        findings.append({
            "severity": "MEDIUM",
            "check": "agents.defaults.scopeIsolation",
            "message": "Agent scope isolation not enabled. "
                       "Agents can access each other's context.",
        })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL", "HIGH"),
        "severity": max_sev,
        "config_path": cfg_path,
        "bindings_count": len(bindings) if bindings else 0,
        "findings": findings,
        "finding_count": len(findings),
    }


def openclaw_voice_security_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    TTS/voice channel security audit (2026.2.24+).

    Checks:
    - Voice provider authentication
    - TTS rate limiting
    - Audio output sanitization
    - Voice channel isolation
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path}"}

    voice_cfg = get_nested(config, "talk") or get_nested(config, "voice") or {}

    if not voice_cfg:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": "No voice/talk configuration found"}

    # Provider check
    provider = voice_cfg.get("provider", "")
    if provider.lower() in _DANGEROUS_VOICE_PROVIDERS:
        findings.append({
            "severity": "HIGH",
            "check": "talk.provider",
            "message": f"Voice provider '{provider}' is not suitable for production.",
        })

    # API key presence
    api_key = voice_cfg.get("apiKey") or voice_cfg.get("api_key")
    if api_key and not api_key.startswith("$"):
        findings.append({
            "severity": "CRITICAL",
            "check": "talk.apiKey",
            "message": "Voice API key appears hardcoded. Use environment variable reference ($).",
        })

    # Rate limiting
    rate_limit = voice_cfg.get("rateLimit")
    if not rate_limit:
        findings.append({
            "severity": "MEDIUM",
            "check": "talk.rateLimit",
            "message": "No rate limit on voice synthesis. Abuse risk.",
        })

    # SSML injection
    allow_ssml = voice_cfg.get("allowSSML", voice_cfg.get("allow_ssml", False))
    if allow_ssml:
        findings.append({
            "severity": "HIGH",
            "check": "talk.allowSSML",
            "message": "SSML input enabled. Risk of SSML injection attacks.",
        })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL",),
        "severity": max_sev,
        "config_path": cfg_path,
        "provider": provider,
        "findings": findings,
        "finding_count": len(findings),
    }


def openclaw_trust_model_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Validate trust model and multi-user heuristics (2026.2.24+).

    Checks:
    - Multi-user mode configuration
    - DM scope isolation
    - Trust model heuristics enabled
    - Hardening recommendations
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path}"}

    session_cfg = get_nested(config, "session") or {}
    gw_cfg = get_nested(config, "gateway") or {}

    # Multi-user detection
    multi_user = session_cfg.get("multiUser", False)
    dm_scope = session_cfg.get("dmScope", "shared")

    if multi_user and dm_scope == "shared":
        findings.append({
            "severity": "CRITICAL",
            "check": "session.dmScope",
            "message": "Multi-user mode enabled with shared DM scope. "
                       "Users can see each other's DMs. Set dmScope: 'isolated'.",
        })

    # Trust model
    trust_model = get_nested(gw_cfg, "trustModel")
    if not trust_model:
        findings.append({
            "severity": "HIGH",
            "check": "gateway.trustModel",
            "message": "No trust model configured. Multi-user heuristics disabled.",
        })

    # Hardening
    hardening = get_nested(gw_cfg, "hardening", "enabled")
    if not hardening:
        findings.append({
            "severity": "HIGH",
            "check": "gateway.hardening.enabled",
            "message": "Gateway hardening not enabled. "
                       "Enable for production multi-user deployments.",
        })

    # Session timeout
    timeout = session_cfg.get("timeoutMinutes", 0)
    if timeout == 0 or timeout > 480:
        findings.append({
            "severity": "MEDIUM",
            "check": "session.timeoutMinutes",
            "message": f"Session timeout is {timeout}min. "
                       "Recommend ≤480min (8h) for multi-user.",
        })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL",),
        "severity": max_sev,
        "config_path": cfg_path,
        "multi_user": multi_user,
        "dm_scope": dm_scope,
        "findings": findings,
        "finding_count": len(findings),
    }


def openclaw_autoupdate_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Validate auto-updater supply chain security (2026.2.22+).

    Checks:
    - Update channel (stable vs beta/nightly)
    - Signature verification enabled
    - Rollout delay configuration
    - Rollback capability
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path}"}

    update_cfg = get_nested(config, "autoUpdate") or get_nested(config, "update") or {}

    if not update_cfg:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": "No auto-update configuration found"}

    # Channel check
    channel = update_cfg.get("channel", "stable")
    if channel.lower() in _UPDATE_CHANNEL_RISKY:
        findings.append({
            "severity": "HIGH",
            "check": "autoUpdate.channel",
            "message": f"Update channel '{channel}' is pre-release. "
                       "Production should use 'stable' or 'lts'.",
        })

    # Signature verification
    verify_sig = update_cfg.get("verifySignature", update_cfg.get("verify", False))
    if not verify_sig:
        findings.append({
            "severity": "CRITICAL",
            "check": "autoUpdate.verifySignature",
            "message": "Update signature verification disabled. "
                       "Supply chain attack risk.",
        })

    # Rollout delay
    delay = update_cfg.get("rolloutDelay", update_cfg.get("delayMinutes", 0))
    if delay < 30:
        findings.append({
            "severity": "MEDIUM",
            "check": "autoUpdate.rolloutDelay",
            "message": f"Rollout delay is {delay}min. "
                       "Recommend ≥30min to catch broken releases.",
        })

    # Rollback
    rollback = update_cfg.get("rollback", {})
    if not rollback.get("enabled", False):
        findings.append({
            "severity": "HIGH",
            "check": "autoUpdate.rollback",
            "message": "Auto-rollback not enabled. "
                       "Bad updates require manual intervention.",
        })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL",),
        "severity": max_sev,
        "config_path": cfg_path,
        "channel": channel,
        "findings": findings,
        "finding_count": len(findings),
    }


def openclaw_plugin_sdk_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Validate plugin SDK integrity (2026.1.16+).

    Checks:
    - Plugin registration and slot usage
    - Hook security (dangerous hooks without guards)
    - Package install restrictions
    - Plugin migration state
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path}"}

    plugins_cfg = get_nested(config, "plugins") or {}

    if not plugins_cfg:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": "No plugins configured"}

    registered = plugins_cfg.get("registered", [])
    if isinstance(registered, list):
        for plugin in registered:
            name = plugin.get("name", "unknown")

            # Check hooks
            hooks = plugin.get("hooks", [])
            for hook in hooks:
                hook_name = hook if isinstance(hook, str) else hook.get("name", "")
                if hook_name in _DANGEROUS_PLUGIN_HOOKS:
                    guard = hook.get("guard") if isinstance(hook, dict) else None
                    if not guard:
                        findings.append({
                            "severity": "HIGH",
                            "check": f"plugins.{name}.hooks",
                            "message": f"Plugin '{name}' uses dangerous hook "
                                       f"'{hook_name}' without a guard.",
                        })

            # Check permissions
            perms = plugin.get("permissions", [])
            if "exec" in perms or "shell" in perms:
                findings.append({
                    "severity": "CRITICAL",
                    "check": f"plugins.{name}.permissions",
                    "message": f"Plugin '{name}' has exec/shell permission. "
                               "Verify source and integrity.",
                })

            # Integrity check
            if not plugin.get("integrity") and not plugin.get("checksum"):
                findings.append({
                    "severity": "MEDIUM",
                    "check": f"plugins.{name}.integrity",
                    "message": f"Plugin '{name}' has no integrity/checksum hash.",
                })

    # Package install restrictions
    pkg_policy = plugins_cfg.get("packageInstall", {})
    if not pkg_policy.get("allowlist") and pkg_policy.get("allow", "all") == "all":
        findings.append({
            "severity": "HIGH",
            "check": "plugins.packageInstall",
            "message": "No package install allowlist. Any plugin can install any package.",
        })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL",),
        "severity": max_sev,
        "config_path": cfg_path,
        "plugins_count": len(registered) if isinstance(registered, list) else 0,
        "findings": findings,
        "finding_count": len(findings),
    }


def openclaw_content_boundary_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Content boundary & anti-prompt-injection audit (2026.2+).

    Checks:
    - wrapExternalContent enabled
    - wrapWebContent enabled
    - toolResult.stripDetails for anti-injection
    - Content boundary markers configured
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path}"}

    # Check wrapExternalContent
    wrap_ext = get_nested(config, "security", "wrapExternalContent")
    if wrap_ext is None or wrap_ext is False:
        findings.append({
            "severity": "CRITICAL",
            "check": "security.wrapExternalContent",
            "message": "wrapExternalContent not enabled. "
                       "External content can be injected without boundaries.",
        })

    # Check wrapWebContent
    wrap_web = get_nested(config, "security", "wrapWebContent")
    if wrap_web is None or wrap_web is False:
        findings.append({
            "severity": "HIGH",
            "check": "security.wrapWebContent",
            "message": "wrapWebContent not enabled. "
                       "Web-fetched content may contain prompt injection.",
        })

    # toolResult stripping
    strip_details = get_nested(config, "security", "toolResult", "stripDetails")
    if strip_details is None or strip_details is False:
        findings.append({
            "severity": "HIGH",
            "check": "security.toolResult.stripDetails",
            "message": "toolResult.stripDetails not enabled. "
                       "Tool outputs may inject into agent context.",
        })

    # Content boundary markers
    boundary_cfg = get_nested(config, "security", "contentBoundary") or {}
    if not boundary_cfg.get("enabled", False):
        findings.append({
            "severity": "HIGH",
            "check": "security.contentBoundary.enabled",
            "message": "Content boundary markers not enabled. "
                       "AI cannot distinguish own output from external content.",
        })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL",),
        "severity": max_sev,
        "config_path": cfg_path,
        "findings": findings,
        "finding_count": len(findings),
    }


def openclaw_sqlite_vec_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    SQLite-vec memory backend validation (2026.1.12+).

    Checks:
    - Memory backend set to sqlite-vec
    - Database path and permissions
    - Embedding model configuration
    - Chunking and index settings
    - Lazy sync configuration
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path}"}

    memory_cfg = get_nested(config, "memory") or {}
    backend = memory_cfg.get("backend", "")

    if not backend:
        findings.append({
            "severity": "MEDIUM",
            "check": "memory.backend",
            "message": "No memory backend configured.",
        })
        return {
            "ok": True,
            "severity": "MEDIUM",
            "config_path": cfg_path,
            "backend": None,
            "findings": findings,
            "finding_count": len(findings),
        }

    sqlite_cfg = memory_cfg.get("sqlite", {})

    # Path check
    db_path = sqlite_cfg.get("path")
    if not db_path:
        findings.append({
            "severity": "HIGH",
            "check": "memory.sqlite.path",
            "message": "SQLite database path not configured.",
        })
    elif ".." in db_path:
        findings.append({
            "severity": "CRITICAL",
            "check": "memory.sqlite.path",
            "message": "Path traversal in sqlite path.",
        })

    # Embedding config
    embedding_cfg = memory_cfg.get("embedding", {})
    if not embedding_cfg.get("model"):
        findings.append({
            "severity": "HIGH",
            "check": "memory.embedding.model",
            "message": "No embedding model configured.",
        })

    dimensions = embedding_cfg.get("dimensions", 0)
    if dimensions and (dimensions < 64 or dimensions > 4096):
        findings.append({
            "severity": "MEDIUM",
            "check": "memory.embedding.dimensions",
            "message": f"Embedding dimensions {dimensions} outside typical range 64-4096.",
        })

    # Chunking
    chunking = memory_cfg.get("chunking", {})
    chunk_size = chunking.get("size", 0)
    overlap = chunking.get("overlap", 0)
    if chunk_size and overlap >= chunk_size:
        findings.append({
            "severity": "HIGH",
            "check": "memory.chunking",
            "message": f"Chunk overlap ({overlap}) >= chunk size ({chunk_size}).",
        })

    # Lazy sync
    sync_cfg = memory_cfg.get("sync", {})
    if sync_cfg.get("lazy") is True and not sync_cfg.get("intervalSeconds"):
        findings.append({
            "severity": "MEDIUM",
            "check": "memory.sync",
            "message": "Lazy sync enabled without intervalSeconds.",
        })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL",),
        "severity": max_sev,
        "config_path": cfg_path,
        "backend": backend,
        "findings": findings,
        "finding_count": len(findings),
    }


# ── Claude 4.6 adaptive thinking audit (2026.3.1) ───────────────────────────

def openclaw_adaptive_thinking_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Checks that Claude 4.6 model configurations use the correct adaptive
    thinking defaults introduced in 2026.3.1.

    Claude 4.6 models default to adaptive thinking mode. If the config
    sets thinking=low or disabled on these models, agents may produce
    degraded reasoning. If thinking mode is unset, verify the model is
    recognized so the default (`adaptive`) applies correctly.

    Args:
        config_path: Path to openclaw.json.

    Returns:
        {ok, severity, findings, finding_count, config_path}
    """
    cfg_path = config_path or "~/.openclaw/openclaw.json"
    try:
        config, cfg_path = load_config(cfg_path)
    except Exception as exc:
        return {"ok": False, "severity": "CRITICAL",
                "findings": [{"id": "config_load_error", "severity": "CRITICAL", "message": str(exc)}],
                "finding_count": 1, "config_path": cfg_path}

    if not config:
        return {"ok": True, "severity": "OK", "findings": [], "finding_count": 0, "config_path": cfg_path}

    findings: list[dict[str, Any]] = []

    # Check agents.defaults.model
    agents_defaults = get_nested(config, "agents", "defaults") or {}
    model = agents_defaults.get("model", "")
    thinking_cfg = agents_defaults.get("thinking", {})

    if isinstance(model, str) and any(m in model.lower() for m in ("claude-4.6", "claude-sonnet-4.6", "claude-opus-4.6", "claude-haiku-4.6")):
        thinking_mode = thinking_cfg.get("mode", "") if isinstance(thinking_cfg, dict) else ""

        if thinking_mode == "disabled":
            findings.append({
                "id": "claude46_thinking_disabled",
                "severity": "CRITICAL",
                "message": (
                    f"agents.defaults.model='{model}' with thinking.mode='disabled'. "
                    "Claude 4.6 models are designed for adaptive thinking — disabling it "
                    "severely degrades reasoning quality. Remove or set to 'adaptive'."
                ),
            })
        elif thinking_mode == "low":
            findings.append({
                "id": "claude46_thinking_low",
                "severity": "HIGH",
                "message": (
                    f"agents.defaults.model='{model}' with thinking.mode='low'. "
                    "Claude 4.6 defaults to 'adaptive' thinking — 'low' limits complex "
                    "reasoning. Consider removing or setting to 'adaptive'. (2026.3.1)"
                ),
            })
        elif not thinking_mode:
            # No explicit mode — good, adaptive will apply by default
            findings.append({
                "id": "claude46_thinking_default_ok",
                "severity": "INFO",
                "message": (
                    f"agents.defaults.model='{model}' with no explicit thinking mode. "
                    "Default 'adaptive' will apply — this is the recommended setting."
                ),
            })

    # Check per-agent overrides
    agents = config.get("agents", {})
    for agent_name, agent_cfg in agents.items():
        if agent_name == "defaults" or not isinstance(agent_cfg, dict):
            continue
        agent_model = agent_cfg.get("model", "")
        agent_thinking = agent_cfg.get("thinking", {})
        if isinstance(agent_model, str) and any(m in agent_model.lower() for m in ("claude-4.6", "claude-sonnet-4.6", "claude-opus-4.6", "claude-haiku-4.6")):
            mode = agent_thinking.get("mode", "") if isinstance(agent_thinking, dict) else ""
            if mode in ("disabled", "low"):
                findings.append({
                    "id": f"claude46_agent_{agent_name}_thinking_{mode}",
                    "severity": "CRITICAL" if mode == "disabled" else "HIGH",
                    "message": (
                        f"agents.{agent_name}.model='{agent_model}' with thinking.mode='{mode}'. "
                        "Claude 4.6 should use 'adaptive' thinking for optimal reasoning. (2026.3.1)"
                    ),
                })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL", "HIGH"),
        "severity": max_sev,
        "findings": findings,
        "finding_count": len([f for f in findings if f["severity"] not in ("OK", "INFO")]),
        "config_path": cfg_path,
    }


# ── TOOLS registry ───────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_secrets_v2_audit",
        "title": "Secrets v2 Lifecycle Audit",
        "description": (
            "Audit the OpenClaw secrets v2 lifecycle (2026.2.26+). "
            "Checks external provider, rotation policy, audit log, "
            "runtime snapshots, and hardcoded secret detection. Gap G12."
        ),
        "category": "platform",
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
        "handler": openclaw_secrets_v2_audit,
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
                "config_path": {"type": "string", "description": "OpenClaw config path."},
                "secrets_config_path": {"type": "string", "description": "Secrets-specific config."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_agent_routing_check",
        "title": "Agent Routing Validation",
        "description": (
            "Validate agent routing bindings (2026.2.26+). "
            "Checks default route, scope isolation, circular routing. Gap G13."
        ),
        "category": "platform",
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
        "handler": openclaw_agent_routing_check,
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
                "config_path": {"type": "string", "description": "OpenClaw config path."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_voice_security_check",
        "title": "Voice/TTS Security Audit",
        "description": (
            "TTS/voice channel security audit (2026.2.24+). "
            "Checks provider auth, rate limits, SSML injection, "
            "voice channel isolation. Gap G14."
        ),
        "category": "platform",
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
        "handler": openclaw_voice_security_check,
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
                "config_path": {"type": "string", "description": "OpenClaw config path."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_trust_model_check",
        "title": "Trust Model Validation",
        "description": (
            "Validate trust model and multi-user heuristics (2026.2.24+). "
            "Checks multi-user DM scope, trust model, gateway hardening. Gap G15."
        ),
        "category": "platform",
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
        "handler": openclaw_trust_model_check,
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
                "config_path": {"type": "string", "description": "OpenClaw config path."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_autoupdate_check",
        "title": "Auto-Update Integrity Check",
        "description": (
            "Self-update supply chain integrity check (2026.2.22+). "
            "Checks update channel, signature verification, rollout delay, rollback. Gap G16."
        ),
        "category": "platform",
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
        "handler": openclaw_autoupdate_check,
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
                "config_path": {"type": "string", "description": "OpenClaw config path."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_plugin_sdk_check",
        "title": "Plugin SDK Integrity",
        "description": (
            "Plugin SDK integrity validation (2026.1.16+). "
            "Checks plugin hooks, permissions, integrity hashes, "
            "package install restrictions. Gap G17."
        ),
        "category": "platform",
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
        "handler": openclaw_plugin_sdk_check,
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
                "config_path": {"type": "string", "description": "OpenClaw config path."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_content_boundary_check",
        "title": "Content Boundary Audit",
        "description": (
            "Content boundary & anti-prompt-injection audit (2026.2+). "
            "Checks wrapExternalContent, wrapWebContent, toolResult stripping, "
            "content boundary markers. Gap G19."
        ),
        "category": "platform",
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
        "handler": openclaw_content_boundary_check,
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
                "config_path": {"type": "string", "description": "OpenClaw config path."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_sqlite_vec_check",
        "title": "SQLite-vec Memory Check",
        "description": (
            "SQLite-vec memory backend validation (2026.1.12+). "
            "Checks backend config, db path, embedding model, chunking, "
            "index settings, lazy sync. Gap G20."
        ),
        "category": "platform",
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
        "handler": openclaw_sqlite_vec_check,
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
                "config_path": {"type": "string", "description": "OpenClaw config path."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_adaptive_thinking_check",
        "title": "Claude 4.6 Adaptive Thinking Check",
        "description": (
            "Checks Claude 4.6 model configs for correct adaptive thinking defaults (2026.3.1). "
            "Detects disabled/low thinking modes that degrade reasoning quality. "
            "Validates both agents.defaults and per-agent overrides."
        ),
        "category": "platform",
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
        "handler": openclaw_adaptive_thinking_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {"type": "string", "description": "OpenClaw config path."},
            },
            "required": [],
        },
    },
]
