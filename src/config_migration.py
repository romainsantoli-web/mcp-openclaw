"""
config_migration.py — OpenClaw configuration migration & runtime hardening (Phase 4, Part 2)

Comble les gaps identifiés dans openclaw/openclaw (CHANGELOG ≤ 2026.2.27) :
  H17 — Shell environment sanitization (SHELL/HOME/ZDOTDIR + LD_*/DYLD_*)
  H18 — Plugin install integrity/pin + drift warnings
  H19 — hooks.token ≠ gateway.auth.token (token separation)
  M17 — OTEL secret redaction in diagnostics export
  M21 — Control-plane RPC rate limiting config

Tools exposed:
  openclaw_shell_env_check          — vérifie l'assainissement shell env (H17)
  openclaw_plugin_integrity_check   — vérifie l'intégrité des plugins (H18)
  openclaw_token_separation_check   — vérifie la séparation des tokens (H19)
  openclaw_otel_redaction_check     — vérifie la rédaction OTEL (M17)
  openclaw_rpc_rate_limit_check     — vérifie le rate limiting RPC (M21)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from src.config_helpers import load_config as _load_config_base, get_nested as _get_nested  # noqa: E402

logger = logging.getLogger(__name__)

# ── Default paths (overridable via env) ──────────────────────────────────────

_OPENCLAW_DIR = Path(os.getenv("OPENCLAW_DIR", Path.home() / ".openclaw"))
_CONFIG_PATH = Path(os.getenv("OPENCLAW_CONFIG", _OPENCLAW_DIR / "openclaw.json"))

# ── Dangerous env vars that must be sanitized ────────────────────────────────

_DANGEROUS_ENV_PREFIXES = ("LD_", "DYLD_", "LD_PRELOAD", "LD_LIBRARY_PATH")
_SHELL_VARS = {"SHELL", "HOME", "ZDOTDIR", "XDG_CONFIG_HOME"}

# ── OTEL sensitive key patterns ──────────────────────────────────────────────

_OTEL_SENSITIVE_KEYS = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|authorization|credential|bearer)",
)

# ── Plugin integrity directory ───────────────────────────────────────────────

_PLUGINS_DIR = _OPENCLAW_DIR / "plugins"
_PLUGIN_MANIFEST = _OPENCLAW_DIR / "plugin-manifest.json"


# ════════════════════════════════════════════════════════════════════════════
# Helper — delegates to shared config_helpers
# ════════════════════════════════════════════════════════════════════════════

def _load_config(config_path: str | None) -> tuple[dict[str, Any], str]:
    """Load config — delegates to config_helpers.load_config."""
    return _load_config_base(config_path)



# ════════════════════════════════════════════════════════════════════════════
# Tool 1 — H17: Shell environment sanitization
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_shell_env_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H17 — Vérifie l'assainissement des variables d'environnement shell.

    Fix 2026.2.22 : sanitize SHELL, HOME, ZDOTDIR dans les forks.
    Fix 2026.2.12 (breaking) : reject LD_PRELOAD, DYLD_LIBRARY_PATH dans
    l'env hérité par les agents.

    Vérifie:
      - agents.defaults.env ne contient pas LD_*/DYLD_* dangereux
      - tools.exec.env est assaini
      - hooks.env est assaini

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

    # All env configuration locations to check
    env_locations = [
        ("agents.defaults.env", _get_nested(config, "agents", "defaults", "env", default={})),
        ("tools.exec.env", _get_nested(config, "tools", "exec", "env", default={})),
        ("hooks.env", _get_nested(config, "hooks", "env", default={})),
    ]

    for location, env_dict in env_locations:
        if not isinstance(env_dict, dict):
            continue
        for var_name in env_dict:
            # Check 1: LD_*/DYLD_* prefixes
            for prefix in _DANGEROUS_ENV_PREFIXES:
                if var_name.startswith(prefix) or var_name == prefix:
                    findings.append({
                        "id": f"dangerous_env_{location}_{var_name}",
                        "severity": "HIGH",
                        "message": (
                            f"{location} sets '{var_name}' — this is a dangerous "
                            "dynamic linker variable that can inject shared libraries. "
                            f"Remove from {location}. (Breaking 2026.2.12, Fix 2026.2.22)"
                        ),
                    })
                    break

    # Check 2: shell env override in fork config
    fork_cfg = _get_nested(config, "agents", "defaults", "fork", default={})
    if isinstance(fork_cfg, dict):
        passed_env = fork_cfg.get("env", {})
        if isinstance(passed_env, dict):
            for var_name in _SHELL_VARS:
                if var_name in passed_env:
                    findings.append({
                        "id": f"shell_env_override_{var_name}",
                        "severity": "MEDIUM",
                        "message": (
                            f"agents.defaults.fork.env overrides '{var_name}'. "
                            "Shell environment overrides in fork config can redirect "
                            "shell initialization. Verify this is intentional. (Fix 2026.2.22)"
                        ),
                    })

    # Check 3: ZDOTDIR unset or pointing to untrusted dir
    zdotdir_cfg = _get_nested(config, "agents", "defaults", "env", "ZDOTDIR")
    if zdotdir_cfg and isinstance(zdotdir_cfg, str):
        zd_path = Path(zdotdir_cfg)
        if not zd_path.is_absolute():
            findings.append({
                "id": "zdotdir_relative",
                "severity": "HIGH",
                "message": (
                    f"ZDOTDIR set to relative path '{zdotdir_cfg}'. "
                    "This is workspace-dependent and can resolve to attacker-controlled "
                    "directories. Use an absolute path or remove the override. (Fix 2026.2.22)"
                ),
            })

    return {
        "status": "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "medium" if any(f["severity"] == "MEDIUM" for f in findings)
                  else "ok",
        "config_path": resolved,
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 2 — H18: Plugin install integrity/pin
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_plugin_integrity_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H18 — Vérifie l'intégrité et le pin des plugins installés.

    Fix 2026.2.26 : plugin install integrity tracking + drift warnings.
    Vérifie que les plugins sont pinnés à une version/hash concrète, et que
    les fichiers installés n'ont pas dérivé du manifest.

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

    # Check 1: plugin entries configuration
    plugins_cfg = config.get("plugins", {})
    plugin_entries = plugins_cfg.get("entries", {}) if isinstance(plugins_cfg, dict) else {}

    if not isinstance(plugin_entries, dict) or not plugin_entries:
        return {"status": "ok", "config_path": resolved, "findings": [
            {"id": "no_plugins", "severity": "INFO",
             "message": "No plugins configured — nothing to check."}
        ]}

    # Check pinning for each plugin
    for pid, pcfg in plugin_entries.items():
        if not isinstance(pcfg, dict):
            continue

        version = pcfg.get("version")
        pin = pcfg.get("pin") or pcfg.get("integrity")
        source = pcfg.get("source", "npm")

        # No version pinning
        if not version:
            findings.append({
                "id": f"plugin_no_version_{pid}",
                "severity": "HIGH",
                "message": (
                    f"Plugin '{pid}' has no version pin. Without version pinning, "
                    "auto-update can install untrusted code. Specify a concrete version. "
                    "(Plugin integrity tracking 2026.2.26+)"
                ),
            })
        elif version.startswith("^") or version.startswith("~") or version == "*" or version == "latest":
            findings.append({
                "id": f"plugin_loose_version_{pid}",
                "severity": "HIGH",
                "message": (
                    f"Plugin '{pid}' uses range version '{version}'. "
                    "Range versions allow unreviewed updates. "
                    "Pin to an exact version (e.g., '1.2.3'). (2026.2.26+)"
                ),
            })

        # No integrity hash
        if not pin and source in ("npm", "git", "url"):
            findings.append({
                "id": f"plugin_no_integrity_{pid}",
                "severity": "MEDIUM",
                "message": (
                    f"Plugin '{pid}' (source: {source}) has no integrity/pin hash. "
                    "Enable integrity tracking with `openclaw plugin pin {pid}` "
                    "to detect post-install modifications. (2026.2.26+)"
                ),
            })

    # Check 2: manifest vs installed files drift
    if _PLUGIN_MANIFEST.exists():
        try:
            with _PLUGIN_MANIFEST.open("r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            if isinstance(manifest, dict):
                for pid, m_entry in manifest.items():
                    if not isinstance(m_entry, dict):
                        continue
                    expected_hash = m_entry.get("sha256")
                    main_file = m_entry.get("main")
                    if not expected_hash or not main_file:
                        continue
                    full_path = _PLUGINS_DIR / pid / main_file
                    if full_path.exists():
                        actual_hash = hashlib.sha256(full_path.read_bytes()).hexdigest()
                        if actual_hash != expected_hash:
                            findings.append({
                                "id": f"plugin_drift_{pid}",
                                "severity": "CRITICAL",
                                "message": (
                                    f"Plugin '{pid}' main file '{main_file}' has drifted "
                                    f"from manifest. Expected sha256={expected_hash[:16]}…, "
                                    f"got {actual_hash[:16]}…. Possible tampering. "
                                    "Reinstall with `openclaw plugin install --verify {pid}`. "
                                    "(Drift warning 2026.2.26+)"
                                ),
                            })
        except (json.JSONDecodeError, OSError):
            findings.append({
                "id": "manifest_read_error",
                "severity": "MEDIUM",
                "message": (
                    f"Could not read plugin manifest at {_PLUGIN_MANIFEST}. "
                    "Integrity checks unavailable."
                ),
            })

    return {
        "status": "critical" if any(f["severity"] == "CRITICAL" for f in findings)
                  else "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "medium" if any(f["severity"] == "MEDIUM" for f in findings)
                  else "ok",
        "config_path": resolved,
        "plugin_count": len(plugin_entries),
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 3 — H19: Token separation check
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_token_separation_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H19 — Vérifie que hooks.token ≠ gateway.auth.token.

    Si le même token est réutilisé, un attaquant qui capture le webhook token
    obtient un accès complet au control plane Gateway. Les tokens doivent être
    distincts et de longueur suffisante.

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

    hooks_token = _get_nested(config, "hooks", "token")
    gateway_token = _get_nested(config, "gateway", "auth", "token")
    gateway_password = _get_nested(config, "gateway", "auth", "password")

    # Check 1: hooks.token == gateway.auth.token
    if hooks_token and gateway_token and hooks_token == gateway_token:
        findings.append({
            "id": "token_reuse_hooks_gateway",
            "severity": "HIGH",
            "message": (
                "hooks.token is identical to gateway.auth.token. "
                "If the webhook token is leaked, the attacker gains full "
                "Gateway Control UI access. Use separate tokens. "
                "(Security best practice)"
            ),
        })

    # Check 2: hooks.token == gateway.auth.password
    if hooks_token and gateway_password and hooks_token == gateway_password:
        findings.append({
            "id": "token_reuse_hooks_password",
            "severity": "HIGH",
            "message": (
                "hooks.token is identical to gateway.auth.password. "
                "Token reuse across security boundaries increases blast radius. "
                "Generate separate credentials."
            ),
        })

    # Check 3: token length
    _MIN_TOKEN_LEN = 32
    for token_name, token_val in [("hooks.token", hooks_token), ("gateway.auth.token", gateway_token)]:
        if token_val and isinstance(token_val, str) and len(token_val) < _MIN_TOKEN_LEN:
            findings.append({
                "id": f"short_token_{token_name.replace('.', '_')}",
                "severity": "MEDIUM",
                "message": (
                    f"{token_name} is only {len(token_val)} chars (recommended ≥{_MIN_TOKEN_LEN}). "
                    "Short tokens are brute-forceable. Use `openssl rand -hex 32` to generate."
                ),
            })

    # Check 4: webhook token is a placeholder / template variable
    if hooks_token and isinstance(hooks_token, str):
        if hooks_token.startswith("$") or hooks_token.startswith("{{"):
            # Template variable — OK, skip length check
            pass
        elif hooks_token in ("changeme", "test", "token", "secret", "webhook"):
            findings.append({
                "id": "hooks_token_placeholder",
                "severity": "HIGH",
                "message": (
                    f"hooks.token appears to be a placeholder value: '{hooks_token}'. "
                    "Replace with a strong random token."
                ),
            })

    return {
        "status": "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "medium" if any(f["severity"] == "MEDIUM" for f in findings)
                  else "ok",
        "config_path": resolved,
        "hooks_token_set": bool(hooks_token),
        "gateway_token_set": bool(gateway_token),
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 4 — M17: OTEL secret redaction
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_otel_redaction_check(config_path: str | None = None) -> dict[str, Any]:
    """
    M17 — Vérifie la rédaction des secrets dans l'export OTEL/diagnostics.

    Fix 2026.2.27 : diagnostics export doit masquer les clés sensibles
    (api_key, token, secret, password, authorization, credential).
    Ce tool vérifie la config OTEL et les attributs de span personnalisés.

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

    otel_cfg = config.get("otel", config.get("telemetry", config.get("diagnostics", {})))
    if not isinstance(otel_cfg, dict):
        return {"status": "ok", "config_path": resolved, "findings": [
            {"id": "no_otel_config", "severity": "INFO",
             "message": "No OTEL/telemetry/diagnostics config found — skipping."}
        ]}

    # Check 1: OTEL exporter endpoint contains inline credentials
    endpoint = otel_cfg.get("endpoint") or otel_cfg.get("collectorEndpoint")
    if endpoint and isinstance(endpoint, str):
        # Check for embedded auth in URL
        if "@" in endpoint and "://" in endpoint:
            findings.append({
                "id": "otel_endpoint_inline_auth",
                "severity": "HIGH",
                "message": (
                    "OTEL exporter endpoint contains inline credentials (user:pass@host). "
                    "Use OTEL_EXPORTER_OTLP_HEADERS env var or otel.headers config instead. "
                    "(Redaction fix 2026.2.27)"
                ),
            })

    # Check 2: OTEL headers may contain unredacted secrets
    headers = otel_cfg.get("headers", {})
    if isinstance(headers, dict):
        for hdr_name, hdr_val in headers.items():
            if _OTEL_SENSITIVE_KEYS.search(hdr_name):
                if isinstance(hdr_val, str) and not hdr_val.startswith("$") and not hdr_val.startswith("{{"):
                    findings.append({
                        "id": f"otel_header_inline_{hdr_name}",
                        "severity": "MEDIUM",
                        "message": (
                            f"OTEL header '{hdr_name}' contains inline secret value. "
                            "Use environment variable reference ($ENV_VAR) instead "
                            "to prevent leakage in diagnostics export. (Fix 2026.2.27)"
                        ),
                    })

    # Check 3: custom span attributes with sensitive names
    custom_attrs = otel_cfg.get("spanAttributes", otel_cfg.get("customAttributes", {}))
    if isinstance(custom_attrs, dict):
        for attr_name in custom_attrs:
            if _OTEL_SENSITIVE_KEYS.search(attr_name):
                findings.append({
                    "id": f"otel_span_attr_sensitive_{attr_name}",
                    "severity": "MEDIUM",
                    "message": (
                        f"Custom OTEL span attribute '{attr_name}' matches sensitive key pattern. "
                        "Span attributes are exported in traces. Ensure this attribute is redacted "
                        "or uses a scrubbed reference. (Fix 2026.2.27)"
                    ),
                })

    # Check 4: redaction config
    redaction = otel_cfg.get("redaction", {})
    if isinstance(redaction, dict):
        if redaction.get("enabled") is False:
            findings.append({
                "id": "otel_redaction_disabled",
                "severity": "HIGH",
                "message": (
                    "OTEL redaction is explicitly disabled (otel.redaction.enabled=false). "
                    "Secrets will appear in raw traces/metrics/logs. "
                    "Enable redaction. (Fix 2026.2.27)"
                ),
            })
    elif otel_cfg.get("enabled", False) or endpoint:
        # OTEL is active but no redaction config
        findings.append({
            "id": "otel_no_redaction_config",
            "severity": "MEDIUM",
            "message": (
                "OTEL export is active but no otel.redaction config found. "
                "Add otel.redaction.enabled=true to ensure sensitive attributes "
                "are scrubbed. (Best practice 2026.2.27)"
            ),
        })

    return {
        "status": "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "medium" if any(f["severity"] == "MEDIUM" for f in findings)
                  else "ok",
        "config_path": resolved,
        "otel_enabled": bool(otel_cfg.get("enabled") or endpoint),
        "redaction_configured": bool(redaction) if isinstance(redaction, dict) else False,
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 5 — M21: Control-plane RPC rate limiting
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_rpc_rate_limit_check(config_path: str | None = None) -> dict[str, Any]:
    """
    M21 — Vérifie la configuration du rate limiting pour le control-plane RPC.

    Sans rate limiting, un client malveillant peut DoS le Gateway via des
    appels RPC répétés (tools/list, tools/call, resources/list, etc.).
    Vérifie que gateway.rateLimit est configuré avec des seuils raisonnables.

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

    bind = _get_nested(config, "gateway", "bind", default="loopback")
    is_remote = bind not in ("loopback", "127.0.0.1", "::1")

    rate_limit = _get_nested(config, "gateway", "rateLimit", default={})
    if not isinstance(rate_limit, dict):
        rate_limit = {}

    # Check 1: no rate limit on remote deployment
    if is_remote and not rate_limit:
        findings.append({
            "id": "no_rate_limit_remote",
            "severity": "HIGH",
            "message": (
                f"Gateway is remote-accessible (bind='{bind}') but "
                "gateway.rateLimit is not configured. Add rate limiting "
                "to prevent DoS via RPC flooding. Example: "
                "{ \"maxRequestsPerMinute\": 120, \"maxConcurrent\": 10 }"
            ),
        })
    elif is_remote:
        # Check thresholds
        max_rpm = rate_limit.get("maxRequestsPerMinute", rate_limit.get("rpm"))
        max_concurrent = rate_limit.get("maxConcurrent")

        if max_rpm and max_rpm > 600:
            findings.append({
                "id": "rate_limit_too_high",
                "severity": "MEDIUM",
                "message": (
                    f"gateway.rateLimit.maxRequestsPerMinute={max_rpm} is very high. "
                    "Consider ≤300 RPM for production deployments to prevent abuse."
                ),
            })

        if not max_concurrent:
            findings.append({
                "id": "no_concurrent_limit",
                "severity": "MEDIUM",
                "message": (
                    "gateway.rateLimit.maxConcurrent is not set. "
                    "Without concurrent request limiting, a slow-loris attack "
                    "can exhaust connection slots. Set to ≤20 for production."
                ),
            })

    # Check 2: hooks rate limit (separate from gateway)
    hooks_rate = _get_nested(config, "hooks", "rateLimit", default={})
    has_hooks = bool(config.get("hooks", {}).get("mappings") or
                     config.get("hooks", {}).get("transformsDir") if isinstance(config.get("hooks"), dict) else False)
    if has_hooks and not hooks_rate:
        findings.append({
            "id": "hooks_no_rate_limit",
            "severity": "MEDIUM",
            "message": (
                "Hooks are configured but hooks.rateLimit is not set. "
                "Unauthenticated webhook endpoints are vulnerable to flooding. "
                "Add hooks.rateLimit with per-IP throttling."
            ),
        })

    # Check 3: loopback — informational only
    if not is_remote and not rate_limit:
        findings.append({
            "id": "loopback_no_rate_limit",
            "severity": "INFO",
            "message": (
                "Gateway on loopback without rate limiting — acceptable for "
                "local development. Add rate limiting before exposing remotely."
            ),
        })

    return {
        "status": "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "medium" if any(f["severity"] == "MEDIUM" for f in findings)
                  else "ok",
        "config_path": resolved,
        "bind": bind,
        "is_remote": is_remote,
        "rate_limit_configured": bool(rate_limit),
        "hooks_rate_limit_configured": bool(hooks_rate),
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# MCP Tool Registry
# ════════════════════════════════════════════════════════════════════════════

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_shell_env_check",
        "title": "Shell Env Sanitization Check",
        "description": (
            "H17 — Vérifie l'assainissement des variables d'environnement shell. "
            "Détecte LD_PRELOAD / DYLD_LIBRARY_PATH dans les configs agents, "
            "exec et hooks. (Fix 2026.2.22 + Breaking 2026.2.12)"
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
        "handler": openclaw_shell_env_check,
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
        "name": "openclaw_plugin_integrity_check",
        "title": "Plugin Integrity Check",
        "description": (
            "H18 — Vérifie l'intégrité et le pin des plugins installés. "
            "Détecte les versions non pinnées, les hash manquants, et les "
            "drifts post-install. (Plugin integrity tracking 2026.2.26+)"
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
        "handler": openclaw_plugin_integrity_check,
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
        "name": "openclaw_token_separation_check",
        "title": "Token Separation Check",
        "description": (
            "H19 — Vérifie que hooks.token ≠ gateway.auth.token. "
            "La réutilisation de token entre webhook et gateway "
            "élargit la surface d'attaque. (Security best practice)"
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
        "handler": openclaw_token_separation_check,
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
        "name": "openclaw_otel_redaction_check",
        "title": "OTEL Redaction Check",
        "description": (
            "M17 — Vérifie la rédaction des secrets dans l'export OTEL/diagnostics. "
            "Détecte les credentials inline dans endpoints, headers et span "
            "attributes. (Fix 2026.2.27)"
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
        "handler": openclaw_otel_redaction_check,
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
        "name": "openclaw_rpc_rate_limit_check",
        "title": "RPC Rate Limit Check",
        "description": (
            "M21 — Vérifie la configuration du rate limiting pour le control-plane "
            "RPC. Détecte l'absence de rate limit sur les déploiements remote "
            "et les webhooks sans throttling."
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
        "handler": openclaw_rpc_rate_limit_check,
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
