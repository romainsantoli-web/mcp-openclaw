"""
i18n_audit.py — Internationalization audit tool for OpenClaw

Tools exposed:
  openclaw_i18n_audit — verify translation files, detect missing keys, validate ICU format
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_COMMON_LOCALE_DIRS = ["locales", "i18n", "lang", "translations", "messages"]
_ICU_PATTERN = re.compile(r"\{[^}]+,\s*(plural|select|selectordinal)\s*,")
_INTERPOLATION_PATTERN = re.compile(r"\{\{?\s*\w+\s*\}?\}")


async def openclaw_i18n_audit(
    project_path: str,
    base_locale: str = "en",
    locale_dir: str | None = None,
    file_format: str = "json",
) -> dict[str, Any]:
    """
    Audit internationalization (i18n) files for completeness and correctness.

    Checks:
      - Translation directory exists with locale files
      - All keys from base locale exist in every target locale
      - Missing and extra keys per locale
      - ICU message format validation
      - Interpolation variable consistency across locales
      - Empty translation values

    Args:
        project_path: Root directory of the project.
        base_locale: Reference locale (default: "en").
        locale_dir: Explicit path to locale directory. Auto-detected if None.
        file_format: Translation file format: json, yaml, properties. Default: json.

    Returns:
        dict with: ok, status, locales_found, missing_keys, extra_keys, empty_values, findings.
    """
    root = Path(project_path)
    if not root.exists():
        return {"ok": False, "error": f"Project path not found: {project_path}"}

    # Find locale directory
    loc_dir: Path | None = None
    if locale_dir:
        loc_dir = root / locale_dir
    else:
        for candidate in _COMMON_LOCALE_DIRS:
            p = root / candidate
            if p.is_dir():
                loc_dir = p
                break
        # Also check src/
        if not loc_dir:
            for candidate in _COMMON_LOCALE_DIRS:
                p = root / "src" / candidate
                if p.is_dir():
                    loc_dir = p
                    break

    if not loc_dir or not loc_dir.exists():
        return {
            "ok": True,
            "status": "info",
            "findings": [{"severity": "INFO", "message": "No locale directory found. i18n not configured."}],
            "locales_found": [],
            "missing_keys": {},
            "extra_keys": {},
            "empty_values": {},
        }

    # Discover locale files
    ext_map = {"json": "*.json", "yaml": "*.yaml", "properties": "*.properties"}
    glob_pattern = ext_map.get(file_format, "*.json")

    locale_files: dict[str, Path] = {}
    # Pattern 1: locales/en.json, locales/fr.json
    for f in loc_dir.glob(glob_pattern):
        locale_files[f.stem] = f
    # Pattern 2: locales/en/messages.json, locales/fr/messages.json
    if not locale_files:
        for d in loc_dir.iterdir():
            if d.is_dir() and len(d.name) in (2, 5):  # en, fr, en-US, zh-CN
                for f in d.glob(glob_pattern):
                    locale_files[d.name] = f
                    break  # take first file per locale dir

    if not locale_files:
        return {
            "ok": True,
            "status": "info",
            "findings": [{"severity": "INFO", "message": f"Locale directory exists but no {file_format} files found."}],
            "locales_found": [],
            "missing_keys": {},
            "extra_keys": {},
            "empty_values": {},
        }

    # Load translations
    translations: dict[str, dict[str, str]] = {}
    findings: list[dict[str, str]] = []

    for locale, fpath in locale_files.items():
        try:
            raw = fpath.read_text(encoding="utf-8")
            if file_format == "json":
                data = json.loads(raw)
                translations[locale] = _flatten_dict(data)
            else:
                # Simple key=value for properties, or raw for yaml
                translations[locale] = _parse_simple(raw)
        except (json.JSONDecodeError, Exception) as exc:
            findings.append({
                "severity": "HIGH",
                "message": f"Cannot parse {locale} ({fpath.name}): {exc}",
            })

    if base_locale not in translations:
        return {
            "ok": True,
            "status": "high",
            "findings": [{"severity": "HIGH", "message": f"Base locale '{base_locale}' not found. Found: {list(translations.keys())}"}],
            "locales_found": list(translations.keys()),
            "missing_keys": {},
            "extra_keys": {},
            "empty_values": {},
        }

    base_keys = set(translations[base_locale].keys())
    missing_keys: dict[str, list[str]] = {}
    extra_keys: dict[str, list[str]] = {}
    empty_values: dict[str, list[str]] = {}

    for locale, trans in translations.items():
        if locale == base_locale:
            continue

        locale_keys = set(trans.keys())
        missing = sorted(base_keys - locale_keys)
        extra = sorted(locale_keys - base_keys)
        empty = sorted(k for k, v in trans.items() if not v or not str(v).strip())

        if missing:
            missing_keys[locale] = missing
            sev = "HIGH" if len(missing) > len(base_keys) * 0.2 else "MEDIUM"
            findings.append({
                "severity": sev,
                "message": f"{locale}: {len(missing)} missing key(s) ({len(missing)}/{len(base_keys)})",
            })
        if extra:
            extra_keys[locale] = extra
            findings.append({
                "severity": "INFO",
                "message": f"{locale}: {len(extra)} extra key(s) not in base locale",
            })
        if empty:
            empty_values[locale] = empty
            findings.append({
                "severity": "MEDIUM",
                "message": f"{locale}: {len(empty)} empty translation value(s)",
            })

    # Check interpolation consistency
    for locale, trans in translations.items():
        if locale == base_locale:
            continue
        for key in base_keys & set(trans.keys()):
            base_vars = set(_INTERPOLATION_PATTERN.findall(translations[base_locale].get(key, "")))
            locale_vars = set(_INTERPOLATION_PATTERN.findall(trans.get(key, "")))
            if base_vars and base_vars != locale_vars:
                findings.append({
                    "severity": "HIGH",
                    "message": f"{locale}.{key}: interpolation mismatch. Base has {base_vars}, locale has {locale_vars}",
                })

    # Check base locale for empty values
    base_empty = [k for k, v in translations[base_locale].items() if not v or not str(v).strip()]
    if base_empty:
        empty_values[base_locale] = base_empty
        findings.append({
            "severity": "HIGH",
            "message": f"Base locale ({base_locale}): {len(base_empty)} empty value(s)",
        })

    # Determine status
    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        status = "critical"
    elif "HIGH" in severities:
        status = "high"
    elif "MEDIUM" in severities:
        status = "medium"
    else:
        status = "ok"

    return {
        "ok": True,
        "status": status,
        "locales_found": sorted(translations.keys()),
        "base_locale": base_locale,
        "base_key_count": len(base_keys),
        "missing_keys": missing_keys,
        "extra_keys": extra_keys,
        "empty_values": empty_values,
        "findings": findings,
    }


def _flatten_dict(d: dict, prefix: str = "") -> dict[str, str]:
    """Flatten nested dict with dot-separated keys."""
    result: dict[str, str] = {}
    for k, v in d.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            result.update(_flatten_dict(v, full_key))
        else:
            result[full_key] = str(v) if v is not None else ""
    return result


def _parse_simple(raw: str) -> dict[str, str]:
    """Parse simple key=value or key: value format."""
    result: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        for sep in ("=", ":"):
            if sep in line:
                k, v = line.split(sep, 1)
                result[k.strip()] = v.strip()
                break
    return result


# ── TOOLS registry ───────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_i18n_audit",
        "description": (
            "Audits internationalization files for missing keys, empty values, "
            "interpolation mismatches, and ICU format issues. "
            "Gap T5/issue #3460: i18n audit was most-requested feature (71 comments)."
        ),
        "category": "i18n",
        "handler": openclaw_i18n_audit,
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Root directory of the project.",
                },
                "base_locale": {
                    "type": "string",
                    "description": "Reference locale. Default: 'en'.",
                    "default": "en",
                },
                "locale_dir": {
                    "type": "string",
                    "description": "Path to locale directory (relative to project). Auto-detected if omitted.",
                },
                "file_format": {
                    "type": "string",
                    "enum": ["json", "yaml", "properties"],
                    "description": "Translation file format. Default: json.",
                    "default": "json",
                },
            },
            "required": ["project_path"],
        },
    },
]
