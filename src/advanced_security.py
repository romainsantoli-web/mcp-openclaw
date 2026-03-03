"""
advanced_security.py — OpenClaw advanced security audits (Phase 4, Part 1)

Comble les gaps identifiés dans openclaw/openclaw (CHANGELOG ≤ 2026.2.27) :
  C7  — External Secrets workflow non validé (`openclaw secrets` lifecycle)
  C8  — Plugin channel HTTP auth bypass (path canonicalization)
  C9  — Exec approval plan mutabilité (symlink cwd rebind)
  H12 — Hook session-key routing non durci
  H13 — Config $include hardlink escape + file-size guardrails
  H14 — Prototype pollution dans config merge (__proto__, constructor, prototype)
  H15 — SafeBins sans profil explicite = interpréteur non restreint
  H16 — Group policy default silencieux (channels.<provider> absent)

Tools exposed:
  openclaw_secrets_lifecycle_check       — vérifie le lifecycle secrets (C7)
  openclaw_channel_auth_canon_check      — vérifie la canonicalisation auth (C8)
  openclaw_exec_approval_freeze_check    — vérifie l'immutabilité exec plans (C9)
  openclaw_hook_session_routing_check    — vérifie le routing hooks session (H12)
  openclaw_config_include_check          — vérifie $include hardlink/size (H13)
  openclaw_config_prototype_check        — vérifie prototype pollution (H14)
  openclaw_safe_bins_profile_check       — vérifie safeBins profils (H15)
  openclaw_group_policy_default_check    — vérifie group policy defaults (H16)
"""

from __future__ import annotations

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

# ── Prototype pollution keys ─────────────────────────────────────────────────

_PROTOTYPE_KEYS = {"__proto__", "constructor", "prototype"}

# ── Channels with group policy support ───────────────────────────────────────

_GROUP_POLICY_CHANNELS = [
    "slack", "discord", "telegram", "whatsapp", "signal",
    "imessage", "line", "matrix", "mattermost", "google-chat",
    "irc", "nextcloud-talk", "feishu", "zalo",
]

# ── Dangerous safeBins with interpreter-like behavior ────────────────────────

_INTERPRETER_BINS = {
    "python", "python3", "ruby", "perl", "node", "deno", "bun",
    "lua", "php", "bash", "sh", "zsh", "fish", "powershell", "pwsh",
}

# ── Path canonicalization bypass patterns ────────────────────────────────────

_ENCODED_TRAVERSAL_PATTERNS = [
    re.compile(r"%2[eE]%2[eE]"),         # %2e%2e / %2E%2E
    re.compile(r"%2[fF]"),                # %2f / %2F
    re.compile(r"\\\\"),                  # backslash
    re.compile(r"%5[cC]"),                # %5c / %5C
    re.compile(r"\.\./"),                 # ../
    re.compile(r"/\.\./"),                # /../
]


# ════════════════════════════════════════════════════════════════════════════
# Helper — delegates to shared config_helpers
# ════════════════════════════════════════════════════════════════════════════

def _load_config(config_path: str | None) -> tuple[dict[str, Any], str]:
    """Load config — delegates to config_helpers.load_config."""
    return _load_config_base(config_path)



def _scan_proto_keys(
    d: Any,
    path: str = "",
    hits: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Recursively scan for prototype pollution keys."""
    if hits is None:
        hits = []
    if isinstance(d, dict):
        for k, v in d.items():
            full_path = f"{path}.{k}" if path else k
            if k in _PROTOTYPE_KEYS:
                hits.append({
                    "path": full_path,
                    "severity": "CRITICAL",
                    "message": (
                        f"Prototype pollution key '{k}' found at '{full_path}'. "
                        "This can inject properties into Object.prototype during "
                        "config merge. Remove this key immediately. (Fix 2026.2.22)"
                    ),
                })
            _scan_proto_keys(v, full_path, hits)
    elif isinstance(d, list):
        for i, item in enumerate(d):
            _scan_proto_keys(item, f"{path}[{i}]", hits)
    return hits


# ════════════════════════════════════════════════════════════════════════════
# Tool 1 — C7: External Secrets lifecycle check
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_secrets_lifecycle_check(config_path: str | None = None) -> dict[str, Any]:
    """
    C7 — Vérifie le lifecycle complet du workflow External Secrets.

    La version 2026.2.26 introduit `openclaw secrets` (audit/configure/apply/reload)
    avec strict target-path validation, migration scrubbing, et ref-only auth-profile
    support. Ce tool vérifie que la migration est effective.

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

    # Check 1: secrets.managed should exist if any auth profiles use inline secrets
    secrets_cfg = config.get("secrets", {})
    has_secrets_managed = bool(secrets_cfg.get("managed"))
    has_secrets_backend = bool(secrets_cfg.get("backend"))

    # Check 2: scan auth profiles for inline API keys
    auth_profiles = _get_nested(config, "auth", "profiles", default={})
    inline_creds = []
    if isinstance(auth_profiles, dict):
        for profile_name, profile in auth_profiles.items():
            if not isinstance(profile, dict):
                continue
            for key in ("apiKey", "token", "password", "secret"):
                val = profile.get(key)
                if isinstance(val, str) and val and not val.startswith("$") and not val.startswith("{{"):
                    inline_creds.append(f"auth.profiles.{profile_name}.{key}")

    if inline_creds:
        findings.append({
            "id": "inline_auth_credentials",
            "severity": "CRITICAL",
            "message": (
                f"Found {len(inline_creds)} inline credential(s) in auth.profiles: "
                f"{inline_creds[:5]}{'...' if len(inline_creds) > 5 else ''}. "
                "Migrate to ref-only auth profiles using "
                "`openclaw secrets configure` (2026.2.26+). "
                "Use `openclaw secrets audit` to identify all inline secrets."
            ),
        })

    # Check 3: secrets apply target-path validation
    secrets_apply = _get_nested(config, "secrets", "apply", default={})
    if isinstance(secrets_apply, dict):
        target_path = secrets_apply.get("targetPath")
        if target_path and ".." in str(target_path):
            findings.append({
                "id": "secrets_apply_traversal",
                "severity": "CRITICAL",
                "message": (
                    f"secrets.apply.targetPath contains path traversal: {target_path!r}. "
                    "This violates strict target-path validation added in 2026.2.26."
                ),
            })

    # Check 4: verify secrets snapshot is activated if secrets are configured
    if has_secrets_managed and not secrets_cfg.get("snapshotActivated", False):
        findings.append({
            "id": "secrets_snapshot_not_activated",
            "severity": "HIGH",
            "message": (
                "secrets.managed is configured but snapshotActivated is false. "
                "Run `openclaw secrets apply` to activate the runtime snapshot. "
                "Without activation, managed secrets are not loaded at runtime."
            ),
        })

    # Check 5: if no secrets config but inline creds exist
    if not has_secrets_managed and not has_secrets_backend and inline_creds:
        findings.append({
            "id": "no_secrets_workflow",
            "severity": "HIGH",
            "message": (
                "No External Secrets workflow configured (secrets.managed / secrets.backend). "
                "Inline credentials detected — migrate to `openclaw secrets configure`. "
                "See External Secrets Management docs (2026.2.26+)."
            ),
        })

    return {
        "status": "critical" if any(f["severity"] == "CRITICAL" for f in findings)
                  else "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "ok",
        "config_path": resolved,
        "has_secrets_managed": has_secrets_managed,
        "has_secrets_backend": has_secrets_backend,
        "inline_credential_count": len(inline_creds),
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 2 — C8: Plugin channel HTTP auth canonicalization
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_channel_auth_canon_check(config_path: str | None = None) -> dict[str, Any]:
    """
    C8 — Vérifie la canonicalisation des chemins auth pour les channels plugins.

    Fix 2026.2.26 : normalise /api/channels avec case + percent-decoding +
    slash normalization. Sans canonicalisation, encoded dot-segment traversal
    (%2e%2e) peut contourner la gateway auth.

    Vérifie:
      - auth.mode configuré (pas "none" sur non-loopback)
      - channels configurés avec plugin entries
      - routes /api/channels protégées
      - pas de URLs custom non canonicalisées

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
    auth_mode = _get_nested(config, "gateway", "auth", "mode", default="token")
    bind = _get_nested(config, "gateway", "bind", default="loopback")
    is_remote = bind not in ("loopback", "127.0.0.1", "::1")

    # Check 1: auth mode "none" on non-loopback
    if auth_mode == "none" and is_remote:
        findings.append({
            "id": "auth_none_remote",
            "severity": "CRITICAL",
            "message": (
                "gateway.auth.mode='none' on non-loopback deployment (bind={!r}). "
                "/api/channels and all plugin HTTP routes are unprotected. "
                "Set auth.mode to 'token' or 'password'. "
                "(Fix 2026.2.26 canonicalization + 2026.2.24 /api/channels auth)"
            ).format(bind),
        })

    # Check 2: plugin entries with custom HTTP paths
    plugins = config.get("plugins", {})
    if not isinstance(plugins, dict):
        plugins = {}
    plugin_entries = plugins.get("entries", {})
    if isinstance(plugin_entries, dict):
        for pid, pcfg in plugin_entries.items():
            if not isinstance(pcfg, dict):
                continue
            # Check for custom webhook/HTTP paths that might bypass canonicalization
            http_path = pcfg.get("httpPath") or pcfg.get("webhookPath")
            if http_path:
                for pattern in _ENCODED_TRAVERSAL_PATTERNS:
                    if pattern.search(http_path):
                        findings.append({
                            "id": f"plugin_path_traversal_{pid}",
                            "severity": "CRITICAL",
                            "message": (
                                f"Plugin '{pid}' has HTTP path with encoded traversal: "
                                f"{http_path!r}. This may bypass /api/channels auth "
                                "canonicalization. Remove encoded chars. (Fix 2026.2.26)"
                            ),
                        })

    # Check 3: controlUi base path interaction
    base_path = _get_nested(config, "gateway", "controlUi", "basePath")
    if base_path and (".." in base_path or "%2" in base_path.lower()):
        findings.append({
            "id": "controlui_basepath_traversal",
            "severity": "HIGH",
            "message": (
                f"gateway.controlUi.basePath contains suspicious chars: {base_path!r}. "
                "Ensure path is properly canonicalized. (Fix 2026.2.26)"
            ),
        })

    # Check 4: hooks paths interaction with auth
    hooks_cfg = config.get("hooks", {})
    if isinstance(hooks_cfg, dict):
        transforms_dir = hooks_cfg.get("transformsDir")
        if transforms_dir and ".." in str(transforms_dir):
            findings.append({
                "id": "hooks_transforms_dir_traversal",
                "severity": "HIGH",
                "message": (
                    f"hooks.transformsDir contains path traversal: {transforms_dir!r}. "
                    "Webhook transform modules must be contained. (Fix 2026.2.22 symlink safe)"
                ),
            })

    return {
        "status": "critical" if any(f["severity"] == "CRITICAL" for f in findings)
                  else "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "ok",
        "config_path": resolved,
        "auth_mode": auth_mode,
        "bind": bind,
        "is_remote": is_remote,
        "plugin_count": len(plugin_entries) if isinstance(plugin_entries, dict) else 0,
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 3 — C9: Exec approval plan immutability
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_exec_approval_freeze_check(config_path: str | None = None) -> dict[str, Any]:
    """
    C9 — Vérifie les conditions d'immutabilité des plans d'exécution.

    Fix 2026.2.26 : freeze immutable approval-time execution plans
    (argv/cwd/agentId/sessionKey) via system.run.prepare. Reject mutable
    parent-symlink cwd paths.

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

    # Check 1: exec approvals configuration
    exec_cfg = _get_nested(config, "tools", "exec", default={})
    exec_cfg.get("approvalsMode") if isinstance(exec_cfg, dict) else None
    safe_bins = exec_cfg.get("safeBins", []) if isinstance(exec_cfg, dict) else []
    host_setting = exec_cfg.get("host", "sandbox") if isinstance(exec_cfg, dict) else "sandbox"

    # Check 2: sandbox mode interaction
    sandbox_mode = _get_nested(config, "agents", "defaults", "sandbox", "mode", default="off")

    if host_setting != "sandbox" and sandbox_mode == "off":
        findings.append({
            "id": "exec_host_no_sandbox",
            "severity": "HIGH",
            "message": (
                f"tools.exec.host='{host_setting}' with sandbox.mode='off'. "
                "Exec runs directly on gateway host without sandboxing. "
                "Symlink cwd rebind between approval and execution is possible. "
                "Enable sandbox mode or set tools.exec.host='sandbox'. (Fix 2026.2.26)"
            ),
        })

    # Check 3: allow-always patterns with shell wrappers
    # Fix 2026.2.22: allow-always persists inner executable patterns, not wrapper shells
    approval_store_path = _OPENCLAW_DIR / "exec-approvals.json"
    if approval_store_path.exists():
        try:
            with approval_store_path.open("r", encoding="utf-8") as fh:
                approvals = json.load(fh)
            shell_wrappers = {"/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/env"}
            if isinstance(approvals, dict):
                for pattern_key, pattern_data in approvals.items():
                    if not isinstance(pattern_data, dict):
                        continue
                    exe = pattern_data.get("executable", "")
                    if exe in shell_wrappers:
                        findings.append({
                            "id": f"approval_shell_wrapper_{Path(exe).name}",
                            "severity": "CRITICAL",
                            "message": (
                                f"exec-approvals.json has allow-always for shell wrapper "
                                f"'{exe}' (pattern: {pattern_key!r}). This allows arbitrary "
                                "shell execution. Fix 2026.2.22 persists inner executable "
                                "patterns instead. Remove this entry and re-approve."
                            ),
                        })
        except (json.JSONDecodeError, OSError):
            pass  # No approval store or corrupted — not a finding

    # Check 4: applyPatch workspaceOnly
    apply_patch = _get_nested(config, "tools", "exec", "applyPatch", default={})
    workspace_only = apply_patch.get("workspaceOnly", True) if isinstance(apply_patch, dict) else True
    if not workspace_only:
        findings.append({
            "id": "apply_patch_not_workspace_only",
            "severity": "HIGH",
            "message": (
                "tools.exec.applyPatch.workspaceOnly=false — apply_patch can write "
                "outside the workspace directory. Combined with symlink cwd attack, "
                "this expands the attack surface. Set to true. (SECURITY.md guidance)"
            ),
        })

    # Check 5 (2026.3.1 BREAKING): Node exec approval payloads require systemRunPlan
    # host=node approval requests without that plan are now rejected.
    node_exec = _get_nested(config, "tools", "exec", default={})
    node_host = node_exec.get("host", "sandbox") if isinstance(node_exec, dict) else "sandbox"
    if node_host == "node":
        # When host=node, systemRunPlan must be present in approval flow
        approvals_cfg = _get_nested(config, "tools", "exec", "approvalsMode", default="auto")
        if approvals_cfg not in ("never", False):
            findings.append({
                "id": "system_run_plan_required",
                "severity": "CRITICAL",
                "message": (
                    "tools.exec.host='node' with approval mode active. "
                    "BREAKING in 2026.3.1: Node exec approval payloads now require "
                    "'systemRunPlan'. Payloads without it are REJECTED. "
                    "Ensure your approval hooks/integrations include systemRunPlan "
                    "in approval request payloads. Update to OpenClaw ≥2026.3.1."
                ),
            })

    return {
        "status": "critical" if any(f["severity"] == "CRITICAL" for f in findings)
                  else "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "ok",
        "config_path": resolved,
        "exec_host": host_setting,
        "sandbox_mode": sandbox_mode,
        "safe_bins_count": len(safe_bins),
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 4 — H12: Hook session-key routing hardening
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_hook_session_routing_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H12 — Vérifie le durcissement du routing session-key pour les hooks.

    Breaking change 2026.2.12 : POST /hooks/agent rejette les overrides
    sessionKey par défaut. hooks.defaultSessionKey + hooks.allowedSessionKeyPrefixes
    doivent être configurés pour le routing sécurisé.

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
    hooks_cfg = config.get("hooks", {})
    if not isinstance(hooks_cfg, dict):
        hooks_cfg = {}

    allow_request_session_key = hooks_cfg.get("allowRequestSessionKey", False)
    default_session_key = hooks_cfg.get("defaultSessionKey")
    allowed_prefixes = hooks_cfg.get("allowedSessionKeyPrefixes", [])

    # Check 1: legacy behavior enabled without safeguards
    if allow_request_session_key:
        if not allowed_prefixes:
            findings.append({
                "id": "hook_session_key_unrestricted",
                "severity": "HIGH",
                "message": (
                    "hooks.allowRequestSessionKey=true without "
                    "hooks.allowedSessionKeyPrefixes. External webhooks can route "
                    "to arbitrary sessions. Add prefix restrictions like "
                    "['hook:'] or disable allowRequestSessionKey. (Breaking 2026.2.12)"
                ),
            })
        else:
            findings.append({
                "id": "hook_session_key_with_prefixes",
                "severity": "INFO",
                "message": (
                    f"hooks.allowRequestSessionKey=true with prefixes: {allowed_prefixes}. "
                    "Verify these prefixes are intentional and scoped."
                ),
            })

    # Check 2: no default session key when hooks are configured
    has_hooks = bool(hooks_cfg.get("mappings") or hooks_cfg.get("transformsDir"))
    if has_hooks and not default_session_key:
        findings.append({
            "id": "hook_no_default_session_key",
            "severity": "MEDIUM",
            "message": (
                "Hooks configured but hooks.defaultSessionKey not set. "
                "Recommended: set to a fixed key (e.g., 'hook:default') "
                "to prevent hook context pollution. (Guide 2026.2.12)"
            ),
        })

    # Check 3: hooks token auth
    hooks_token = hooks_cfg.get("token")
    if has_hooks and not hooks_token:
        findings.append({
            "id": "hook_no_token",
            "severity": "HIGH",
            "message": (
                "Hooks configured without hooks.token — webhook endpoints "
                "are unauthenticated. Set hooks.token and use "
                "`Authorization: Bearer <token>` for webhook requests. "
                "(Security audit 2026.2.12)"
            ),
        })

    return {
        "status": "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "medium" if any(f["severity"] == "MEDIUM" for f in findings)
                  else "ok",
        "config_path": resolved,
        "allow_request_session_key": allow_request_session_key,
        "default_session_key": default_session_key,
        "allowed_prefixes": allowed_prefixes,
        "has_hooks": has_hooks,
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 5 — H13: Config $include hardlink/size check
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_config_include_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H13 — Vérifie les guardrails $include dans la config.

    Fix 2026.2.26 : harden $include loading with verified-open reads,
    reject hardlinked include aliases, enforce include file-size guardrails.
    Config includes must remain bounded to trusted in-root files.

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
    config_dir = Path(resolved).parent

    # Scan for $include directives in the config
    include_files = _find_includes(config)

    _MAX_INCLUDE_SIZE = 1 * 1024 * 1024  # 1 MB guardrail

    for inc_path_str in include_files:
        inc_path = Path(inc_path_str)
        if not inc_path.is_absolute():
            inc_path = config_dir / inc_path

        # Check 1: path traversal
        if ".." in str(inc_path_str):
            findings.append({
                "id": f"include_traversal_{inc_path.name}",
                "severity": "CRITICAL",
                "message": (
                    f"$include path contains traversal: {inc_path_str!r}. "
                    "Config includes must be confined to the config directory. "
                    "(Fix 2026.2.26 + 2026.2.17)"
                ),
            })
            continue

        if not inc_path.exists():
            findings.append({
                "id": f"include_missing_{inc_path.name}",
                "severity": "MEDIUM",
                "message": f"$include target does not exist: {inc_path_str!r}.",
            })
            continue

        # Check 2: hardlink detection
        try:
            stat = inc_path.stat()
            if stat.st_nlink > 1:
                findings.append({
                    "id": f"include_hardlink_{inc_path.name}",
                    "severity": "HIGH",
                    "message": (
                        f"$include target '{inc_path.name}' has {stat.st_nlink} hard links. "
                        "Hardlinked include aliases are rejected since 2026.2.26. "
                        "Ensure include targets are unique files."
                    ),
                })

            # Check 3: file-size guardrail
            if stat.st_size > _MAX_INCLUDE_SIZE:
                size_mb = stat.st_size / (1024 * 1024)
                findings.append({
                    "id": f"include_oversized_{inc_path.name}",
                    "severity": "HIGH",
                    "message": (
                        f"$include target '{inc_path.name}' is {size_mb:.1f} MB "
                        f"(max: {_MAX_INCLUDE_SIZE // (1024*1024)} MB). "
                        "Include file-size guardrails enforced since 2026.2.26."
                    ),
                })

            # Check 4: resolved path out of config root
            try:
                real_path = inc_path.resolve(strict=True)
                real_config_dir = config_dir.resolve(strict=True)
                if not str(real_path).startswith(str(real_config_dir)):
                    findings.append({
                        "id": f"include_out_of_root_{inc_path.name}",
                        "severity": "CRITICAL",
                        "message": (
                            f"$include target '{inc_path.name}' resolves outside config "
                            f"directory ({real_path} not under {real_config_dir}). "
                            "Include resolution must be bounded to trusted in-root files. "
                            "(Fix 2026.2.26)"
                        ),
                    })
            except OSError:
                pass

        except OSError as exc:
            findings.append({
                "id": f"include_stat_error_{inc_path.name}",
                "severity": "MEDIUM",
                "message": f"Cannot stat $include target '{inc_path.name}': {exc}",
            })

    return {
        "status": "critical" if any(f["severity"] == "CRITICAL" for f in findings)
                  else "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "ok",
        "config_path": resolved,
        "include_count": len(include_files),
        "findings": findings,
    }


def _find_includes(d: Any, results: list[str] | None = None) -> list[str]:
    """Recursively find $include directive values."""
    if results is None:
        results = []
    if isinstance(d, dict):
        for k, v in d.items():
            if k == "$include" and isinstance(v, str):
                results.append(v)
            else:
                _find_includes(v, results)
    elif isinstance(d, list):
        for item in d:
            _find_includes(item, results)
    return results


# ════════════════════════════════════════════════════════════════════════════
# Tool 6 — H14: Prototype pollution config check
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_config_prototype_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H14 — Détecte les clés de prototype pollution dans la config.

    Fix 2026.2.22 : bloque __proto__, constructor, prototype dans les helpers
    de merge patch de config et de migration legacy. Ce tool scanne la config
    complète pour ces clés dangereuses.

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

    hits = _scan_proto_keys(config)

    return {
        "status": "critical" if hits else "ok",
        "config_path": resolved,
        "prototype_key_count": len(hits),
        "findings": hits,
        "remediation": (
            "Remove all __proto__, constructor, and prototype keys from "
            "openclaw.json immediately. These can inject properties into "
            "Object.prototype during config merge/migration. (Fix 2026.2.22)"
        ) if hits else None,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 7 — H15: SafeBins profile enforcement
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_safe_bins_profile_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H15 — Vérifie que les safeBins ont des profils explicites.

    Fix 2026.2.22 : les entrées tools.exec.safeBins sans profil dans
    tools.exec.safeBinProfiles sont traitées comme interpréteurs non restreints.
    Un profil explicite est requis pour chaque safe bin entry.

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
    exec_cfg = _get_nested(config, "tools", "exec", default={})
    if not isinstance(exec_cfg, dict):
        return {"status": "ok", "config_path": resolved, "findings": findings}

    safe_bins = exec_cfg.get("safeBins", [])
    safe_bin_profiles = exec_cfg.get("safeBinProfiles", {})

    if not safe_bins:
        return {"status": "ok", "config_path": resolved, "findings": [
            {"id": "no_safe_bins", "severity": "INFO",
             "message": "No tools.exec.safeBins configured — nothing to check."}
        ]}

    for entry in safe_bins:
        bin_name = entry if isinstance(entry, str) else (entry.get("name") if isinstance(entry, dict) else None)
        if not bin_name:
            continue

        base_name = Path(bin_name).name.lower()

        # Check 1: missing profile
        has_profile = bin_name in safe_bin_profiles or base_name in safe_bin_profiles
        if not has_profile:
            severity = "CRITICAL" if base_name in _INTERPRETER_BINS else "HIGH"
            findings.append({
                "id": f"safe_bin_no_profile_{base_name}",
                "severity": severity,
                "message": (
                    f"safeBins entry '{bin_name}' has no matching safeBinProfiles entry. "
                    f"{'This is an interpreter-style binary — stdin-safe treatment is dangerous. ' if base_name in _INTERPRETER_BINS else ''}"
                    "Add an explicit profile in tools.exec.safeBinProfiles. (Fix 2026.2.22)"
                ),
            })

        # Check 2: interpreter without restriction
        if base_name in _INTERPRETER_BINS and has_profile:
            profile = safe_bin_profiles.get(bin_name) or safe_bin_profiles.get(base_name, {})
            if isinstance(profile, dict) and profile.get("stdinSafe", True) is not False:
                findings.append({
                    "id": f"safe_bin_interpreter_stdin_{base_name}",
                    "severity": "HIGH",
                    "message": (
                        f"safeBins '{bin_name}' is an interpreter with stdin-safe profile. "
                        "Interpreter-style entries can execute arbitrary stdin input. "
                        "Set stdinSafe: false in the profile. (Fix 2026.2.22)"
                    ),
                })

    return {
        "status": "critical" if any(f["severity"] == "CRITICAL" for f in findings)
                  else "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "ok",
        "config_path": resolved,
        "safe_bins_count": len(safe_bins),
        "safe_bin_profiles_count": len(safe_bin_profiles),
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# Tool 8 — H16: Group policy default check
# ════════════════════════════════════════════════════════════════════════════

async def openclaw_group_policy_default_check(config_path: str | None = None) -> dict[str, Any]:
    """
    H16 — Vérifie que le default group policy est fail-closed.

    Fix 2026.2.22 : quand channels.<provider> est absent, le runtime
    defaultait à channels.defaults.groupPolicy au lieu de 'allowlist'
    (fail-closed). Ce tool vérifie que chaque canal a un groupPolicy explicite.

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
    channels_config = config.get("channels", {})
    if not isinstance(channels_config, dict):
        channels_config = {}

    defaults_group_policy = _get_nested(config, "channels", "defaults", "groupPolicy")

    # Check 1: channels.defaults.groupPolicy not set to allowlist
    if defaults_group_policy and defaults_group_policy != "allowlist":
        findings.append({
            "id": "defaults_group_policy_not_allowlist",
            "severity": "HIGH",
            "message": (
                f"channels.defaults.groupPolicy='{defaults_group_policy}' "
                "(not 'allowlist'). Channels without explicit groupPolicy inherit "
                "this permissive default. Set to 'allowlist' for fail-closed. "
                "(Fix 2026.2.22)"
            ),
        })

    # Check 2: per-channel config missing
    missing_channels = []
    for channel in _GROUP_POLICY_CHANNELS:
        chan_cfg = channels_config.get(channel, {})
        if not isinstance(chan_cfg, dict):
            continue
        # Channel is configured but has no groupPolicy
        if chan_cfg and not chan_cfg.get("groupPolicy"):
            missing_channels.append(channel)

    if missing_channels:
        findings.append({
            "id": "channels_missing_group_policy",
            "severity": "MEDIUM",
            "message": (
                f"Channels configured without explicit groupPolicy: {missing_channels}. "
                "These inherit channels.defaults.groupPolicy or the runtime default. "
                "Since 2026.2.22, missing provider config defaults to 'allowlist' at runtime. "
                "Add explicit groupPolicy for clarity."
            ),
        })

    return {
        "status": "high" if any(f["severity"] == "HIGH" for f in findings)
                  else "medium" if any(f["severity"] == "MEDIUM" for f in findings)
                  else "ok",
        "config_path": resolved,
        "defaults_group_policy": defaults_group_policy,
        "channels_checked": _GROUP_POLICY_CHANNELS,
        "missing_channels": missing_channels,
        "findings": findings,
    }


# ════════════════════════════════════════════════════════════════════════════
# MCP Tool Registry
# ════════════════════════════════════════════════════════════════════════════

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_secrets_lifecycle_check",
        "title": "Secrets Lifecycle Check",
        "description": (
            "C7 — Vérifie le lifecycle complet du workflow External Secrets "
            "(audit/configure/apply/reload). Détecte les inline credentials, "
            "les snapshots non activées, et la migration incomplète. (2026.2.26+)"
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
        "handler": openclaw_secrets_lifecycle_check,
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
        "name": "openclaw_channel_auth_canon_check",
        "title": "Channel Auth Path Check",
        "description": (
            "C8 — Vérifie la canonicalisation des chemins auth pour les channel plugins. "
            "Détecte les encoded dot-segment traversal (%2e%2e) qui peuvent "
            "contourner la gateway auth sur /api/channels. (Fix 2026.2.26)"
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
        "handler": openclaw_channel_auth_canon_check,
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
        "name": "openclaw_exec_approval_freeze_check",
        "title": "Exec Plan Freeze Check",
        "description": (
            "C9 — Vérifie l'immutabilité des plans d'exécution (argv/cwd/agentId/sessionKey). "
            "Détecte les shell-wrapper allow-always patterns et les configs "
            "sans sandboxing. (Fix 2026.2.26 + 2026.2.22)"
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
        "handler": openclaw_exec_approval_freeze_check,
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
        "name": "openclaw_hook_session_routing_check",
        "title": "Hook Session Routing Check",
        "description": (
            "H12 — Vérifie le durcissement du routing session-key pour les hooks. "
            "Détecte allowRequestSessionKey sans prefix gates et les hooks "
            "sans token auth. (Breaking 2026.2.12)"
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
        "handler": openclaw_hook_session_routing_check,
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
        "name": "openclaw_config_include_check",
        "title": "Config Include Guards",
        "description": (
            "H13 — Vérifie les guardrails $include dans la config. "
            "Détecte les hardlinks, les fichiers oversized, et les targets "
            "hors de la racine config. (Fix 2026.2.26 + 2026.2.17)"
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
        "handler": openclaw_config_include_check,
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
        "name": "openclaw_config_prototype_check",
        "title": "Prototype Pollution Check",
        "description": (
            "H14 — Détecte les clés de prototype pollution (__proto__, constructor, "
            "prototype) dans openclaw.json. Bloquées dans config merge/patch "
            "depuis 2026.2.22."
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
        "handler": openclaw_config_prototype_check,
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
        "name": "openclaw_safe_bins_profile_check",
        "title": "SafeBins Profile Check",
        "description": (
            "H15 — Vérifie que les safeBins ont des profils explicites dans "
            "safeBinProfiles. Détecte les interpréteurs sans restriction. "
            "(Fix 2026.2.22)"
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
        "handler": openclaw_safe_bins_profile_check,
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
        "name": "openclaw_group_policy_default_check",
        "title": "Group Policy Default Check",
        "description": (
            "H16 — Vérifie que le group policy par défaut est fail-closed (allowlist). "
            "Détecte les canaux sans groupPolicy explicite. (Fix 2026.2.22)"
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
        "handler": openclaw_group_policy_default_check,
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
