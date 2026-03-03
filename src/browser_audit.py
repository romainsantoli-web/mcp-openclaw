"""
browser_audit.py — OpenClaw browser automation context checker

Tools:
  openclaw_browser_context_check  — validates Playwright/Puppeteer headless config for agents

Gap T10: Browser Automation is the #4 trending MCP category (25k+ stars).
Ensures agents running headless browsers have correct security/performance settings.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

# Dangerous browser launch args that should trigger warnings
_DANGEROUS_ARGS: dict[str, str] = {
    "--disable-web-security": "Disables same-origin policy — XSS attacks possible",
    "--disable-setuid-sandbox": "Weakens sandbox isolation",
    "--no-sandbox": "Completely disables browser sandbox — CRITICAL in production",
    "--disable-gpu-sandbox": "Disables GPU process sandbox",
    "--allow-running-insecure-content": "Allows mixed HTTP content on HTTPS pages",
    "--disable-extensions-except": "May load untrusted extensions",
    "--load-extension": "Loads browser extension — must be trusted",
    "--remote-debugging-port": "Exposes debug port — RCE risk if publicly accessible",
    "--remote-debugging-address=0.0.0.0": "Debug port on all interfaces — CRITICAL",
}

# Required security practices for headless browser agents
_BEST_PRACTICES = {
    "headless": "Browser should run in headless mode for agents",
    "user_data_dir": "Should use isolated profile (--user-data-dir or userDataDir)",
    "timeout": "Should set navigation timeout (not unlimited)",
    "viewport": "Should set explicit viewport size for consistent rendering",
}

# Config file patterns to search for
_CONFIG_PATTERNS = [
    "playwright.config.*",
    ".puppeteerrc.*",
    "puppeteer.config.*",
    "browser.config.*",
    ".browserrc",
]

# Known frameworks and their config patterns
_FRAMEWORKS: dict[str, dict[str, Any]] = {
    "playwright": {
        "config_files": ["playwright.config.ts", "playwright.config.js", "playwright.config.mjs"],
        "launch_key": "launchOptions",
        "headless_key": "headless",
        "args_key": "args",
        "import_pattern": re.compile(r"(from\s+['\"]@?playwright|require\(['\"]@?playwright)", re.I),
    },
    "puppeteer": {
        "config_files": [".puppeteerrc.cjs", ".puppeteerrc.js", ".puppeteerrc.json", "puppeteer.config.js"],
        "launch_key": "launch",
        "headless_key": "headless",
        "args_key": "args",
        "import_pattern": re.compile(r"(from\s+['\"]puppeteer|require\(['\"]puppeteer)", re.I),
    },
}


# ── Tool: openclaw_browser_context_check ─────────────────────────────────────

async def openclaw_browser_context_check(
    workspace_path: str,
    config_override: dict[str, Any] | None = None,
    check_deps: bool = True,
) -> dict[str, Any]:
    """
    Validate Playwright/Puppeteer headless browser configuration for agent use.

    Scans the workspace for browser automation config files, checks launch
    arguments for security issues, validates headless mode, timeouts, and
    isolation settings.

    Args:
        workspace_path: Root of the workspace to scan.
        config_override: Optional config dict to validate directly (skip file scan).
        check_deps: Whether to check package.json for browser deps. Default: True.

    Returns:
        dict with keys: ok, framework, findings[], severity, recommendations[].
    """
    ws = Path(workspace_path)
    if not ws.exists():
        return {"ok": False, "error": f"Workspace not found: {workspace_path}"}

    findings: list[dict[str, Any]] = []
    recommendations: list[str] = []
    detected_framework: str | None = None
    severity = "INFO"

    def _escalate(new_sev: str) -> None:
        nonlocal severity
        levels = {"INFO": 0, "WARNING": 1, "HIGH": 2, "CRITICAL": 3}
        if levels.get(new_sev, 0) > levels.get(severity, 0):
            severity = new_sev

    # ── Step 1: Detect framework from package.json ───────────────────────────
    if check_deps:
        pkg_json = ws / "package.json"
        if pkg_json.exists():
            try:
                pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
                all_deps = {
                    **pkg.get("dependencies", {}),
                    **pkg.get("devDependencies", {}),
                }
                for fw_name, fw_info in _FRAMEWORKS.items():
                    if any(fw_name in dep for dep in all_deps):
                        detected_framework = fw_name
                        findings.append({
                            "check": "dependency_detected",
                            "framework": fw_name,
                            "severity": "INFO",
                            "message": f"{fw_name} found in package.json dependencies",
                        })
                        break
            except (json.JSONDecodeError, OSError):
                pass

    # ── Step 2: Scan for config files ────────────────────────────────────────
    config_found = False
    config_data: dict[str, Any] | None = config_override

    if config_data is None:
        for fw_name, fw_info in _FRAMEWORKS.items():
            for cfg_file in fw_info["config_files"]:
                cfg_path = ws / cfg_file
                if cfg_path.exists():
                    config_found = True
                    detected_framework = detected_framework or fw_name
                    findings.append({
                        "check": "config_file_found",
                        "file": str(cfg_path.relative_to(ws)),
                        "severity": "INFO",
                        "message": f"Found {fw_name} config: {cfg_file}",
                    })

                    # Try to parse JSON config
                    if cfg_path.suffix == ".json":
                        try:
                            config_data = json.loads(cfg_path.read_text(encoding="utf-8"))
                        except (json.JSONDecodeError, OSError):
                            findings.append({
                                "check": "config_parse_error",
                                "file": cfg_file,
                                "severity": "WARNING",
                                "message": f"Could not parse {cfg_file}",
                            })
                            _escalate("WARNING")

                    # For JS/TS configs, scan for dangerous patterns
                    elif cfg_path.suffix in (".js", ".ts", ".mjs", ".cjs"):
                        try:
                            content = cfg_path.read_text(encoding="utf-8")
                            _scan_js_config(content, cfg_file, findings, recommendations)
                        except OSError:
                            pass
                    break

        if not config_found and not config_override:
            findings.append({
                "check": "no_config_found",
                "severity": "WARNING",
                "message": "No browser automation config files found",
            })
            _escalate("WARNING")
            recommendations.append(
                "Create a browser config file (playwright.config.ts or .puppeteerrc.json) "
                "to ensure consistent, secure browser settings"
            )
    else:
        config_found = True

    # ── Step 3: Validate config data ─────────────────────────────────────────
    if config_data and isinstance(config_data, dict):
        _validate_browser_config(config_data, findings, recommendations)

    # ── Step 4: Check launch args for security issues ────────────────────────
    args = _extract_launch_args(config_data) if config_data else []
    if args:
        for arg in args:
            arg_lower = arg.lower().strip()
            for dangerous_arg, reason in _DANGEROUS_ARGS.items():
                if arg_lower.startswith(dangerous_arg.lower()):
                    sev = "CRITICAL" if "no-sandbox" in arg_lower or "0.0.0.0" in arg_lower else "HIGH"
                    findings.append({
                        "check": "dangerous_launch_arg",
                        "arg": arg,
                        "severity": sev,
                        "message": reason,
                    })
                    _escalate(sev)

    # ── Compute severity from findings ───────────────────────────────────────
    for f in findings:
        _escalate(f.get("severity", "INFO"))

    # ── Standard recommendations ─────────────────────────────────────────────
    if not any("headless" in r.lower() for r in recommendations):
        check_names = [f.get("check") for f in findings]
        if "headless_disabled" in check_names:
            recommendations.append("Enable headless mode for agent browser contexts")

    if not any("timeout" in r.lower() for r in recommendations):
        if not any(f.get("check") == "timeout_configured" for f in findings):
            recommendations.append(
                "Set explicit navigation timeout (e.g., 30s) to prevent agent hangs"
            )

    return {
        "ok": severity not in ("CRITICAL", "HIGH"),
        "framework": detected_framework,
        "config_found": config_found,
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "recommendations": recommendations,
    }


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_launch_args(config: dict[str, Any]) -> list[str]:
    """Extract browser launch args from config dict (nested search)."""
    args: list[str] = []

    def _search(obj: Any, depth: int = 0) -> None:
        if depth > 10:
            return
        if isinstance(obj, dict):
            if "args" in obj and isinstance(obj["args"], list):
                args.extend(str(a) for a in obj["args"])
            for v in obj.values():
                _search(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                _search(item, depth + 1)

    _search(config)
    return args


def _validate_browser_config(
    config: dict[str, Any],
    findings: list[dict[str, Any]],
    recommendations: list[str],
) -> None:
    """Validate browser config fields for best practices."""

    # Check headless mode
    headless = _deep_get(config, "headless")
    if headless is False:
        findings.append({
            "check": "headless_disabled",
            "severity": "WARNING",
            "message": "Browser is NOT in headless mode — should be headless for agent use",
        })
        recommendations.append("Set headless: true (or 'new') for agent browser contexts")
    elif headless is True or headless == "new":
        findings.append({
            "check": "headless_enabled",
            "severity": "INFO",
            "message": "Headless mode is enabled",
        })

    # Check timeout
    timeout = _deep_get(config, "timeout") or _deep_get(config, "navigationTimeout")
    if timeout is not None:
        findings.append({
            "check": "timeout_configured",
            "severity": "INFO",
            "message": f"Navigation timeout set to {timeout}ms",
        })
        if isinstance(timeout, (int, float)) and timeout > 120_000:
            findings.append({
                "check": "timeout_too_high",
                "severity": "WARNING",
                "message": f"Timeout {timeout}ms is very high (>2min) — may cause agent hangs",
            })
    else:
        recommendations.append("Set explicit navigationTimeout to prevent indefinite waits")

    # Check viewport
    viewport = _deep_get(config, "viewport")
    if viewport and isinstance(viewport, dict):
        findings.append({
            "check": "viewport_configured",
            "severity": "INFO",
            "message": f"Viewport: {viewport.get('width', '?')}x{viewport.get('height', '?')}",
        })

    # Check user data dir isolation
    user_data = _deep_get(config, "userDataDir") or _deep_get(config, "user-data-dir")
    if user_data:
        findings.append({
            "check": "isolated_profile",
            "severity": "INFO",
            "message": f"Using isolated user data dir: {user_data}",
        })
    else:
        recommendations.append(
            "Set userDataDir to an isolated path — prevents cross-session data leaks"
        )


def _deep_get(obj: Any, key: str, depth: int = 0) -> Any:
    """Recursively search for a key in nested dicts."""
    if depth > 10:
        return None
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            result = _deep_get(v, key, depth + 1)
            if result is not None:
                return result
    return None


def _scan_js_config(
    content: str,
    filename: str,
    findings: list[dict[str, Any]],
    recommendations: list[str],
) -> None:
    """Scan JS/TS config file content for dangerous patterns."""
    # Check for --no-sandbox
    if "--no-sandbox" in content:
        findings.append({
            "check": "dangerous_launch_arg",
            "arg": "--no-sandbox",
            "severity": "CRITICAL",
            "message": "Found --no-sandbox in config — disables browser sandbox entirely",
        })

    # Check for remote debugging
    if re.search(r"remote-debugging-(port|address)", content):
        findings.append({
            "check": "remote_debugging",
            "file": filename,
            "severity": "HIGH",
            "message": "Remote debugging enabled in config — ensure port is not exposed",
        })

    # Check headless mode
    headless_match = re.search(r"headless\s*:\s*(false|true|['\"]new['\"])", content)
    if headless_match:
        val = headless_match.group(1)
        if val == "false":
            findings.append({
                "check": "headless_disabled",
                "severity": "WARNING",
                "message": "headless: false found in config",
            })


# ── TOOLS registry ───────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_browser_context_check",
        "title": "Browser Headless Config Check",
        "description": (
            "Validates Playwright/Puppeteer headless browser configuration for agent use. "
            "Scans for dangerous launch args (--no-sandbox, remote debugging), checks headless "
            "mode, timeouts, viewport, and user data isolation. Gap T10: browser automation audit."
        ),
        "category": "browser_automation",
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
        "handler": openclaw_browser_context_check,
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
                "workspace_path": {
                    "type": "string",
                    "description": "Root of the workspace to scan.",
                },
                "config_override": {
                    "type": "object",
                    "description": "Optional config dict to validate directly (skip file scan).",
                },
                "check_deps": {
                    "type": "boolean",
                    "description": "Whether to check package.json for browser deps. Default: true.",
                    "default": True,
                },
            },
            "required": ["workspace_path"],
        },
    },
]
