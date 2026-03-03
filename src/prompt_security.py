"""
prompt_security.py — Prompt injection detection and defense tools.

Covers gap H2: Prompt injection / jailbreak detection patterns.

Provides static analysis of prompts and tool inputs for injection
patterns, multi-language jailbreak signatures, and payload obfuscation.
"""

from __future__ import annotations

import re
from typing import Any


# ─── Injection Pattern Database ────────────────────────────────────────────

_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, severity, description)
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", "CRITICAL",
     "Classic instruction override"),
    (r"you\s+are\s+now\s+(a|an|in)\s+", "HIGH",
     "Role reassignment attempt"),
    (r"(system|admin|root)\s*:\s*", "HIGH",
     "System prompt injection via role prefix"),
    (r"forget\s+(everything|all|your)\s+(you|instructions?|rules?)", "CRITICAL",
     "Memory reset injection"),
    (r"\]\s*\}\s*\{.*system", "CRITICAL",
     "JSON escape / prompt boundary break"),
    (r"<\|im_start\|>|<\|im_end\|>|<\|system\|>", "CRITICAL",
     "ChatML injection tokens"),
    (r"</?(system|user|assistant|tool)\s*>", "HIGH",
     "XML role tag injection"),
    (r"IMPORTANT:\s*(ignore|disregard|override)", "HIGH",
     "Urgency-based override"),
    (r"in\s+base64\s*:", "MEDIUM",
     "Base64 encoding evasion attempt"),
    (r"translate.*to\s+(python|javascript|code)", "MEDIUM",
     "Code execution via translation"),
    (r"repeat\s+(after|back|everything)", "MEDIUM",
     "Exfiltration via repetition"),
    (r"do\s+not\s+(follow|obey)\s+(any|the)\s+(rules?|instructions?|guidelines?)", "CRITICAL",
     "Direct rule violation request"),
    (r"(jailbreak|DAN|do\s+anything\s+now)", "CRITICAL",
     "Known jailbreak keyword"),
    (r"pretend\s+(you|that)\s+(are|have)\s+no\s+(rules?|restrictions?|limits?)", "HIGH",
     "Restriction bypass via pretend"),
    (r"output\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions?|message)", "HIGH",
     "System prompt exfiltration"),
    (r"(?:hex|octal|unicode)\s*(?:encoded?|decode)", "MEDIUM",
     "Encoding-based obfuscation"),
]

_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), sev, desc) for p, sev, desc in _INJECTION_PATTERNS]


def _scan_text(text: str) -> list[dict[str, str]]:
    """Scan a text string for injection patterns."""
    hits: list[dict[str, str]] = []
    for pattern, severity, description in _COMPILED_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            hits.append({
                "severity": severity,
                "description": description,
                "match_count": str(len(matches)),
                "sample": matches[0] if isinstance(matches[0], str) else str(matches[0]),
            })
    return hits


# ─── H2: Prompt Injection Check ───────────────────────────────────────────

async def prompt_injection_check(text: str = "", context: str = "user_input") -> dict[str, Any]:
    """Scan text inputs for prompt injection and jailbreak patterns.

    Checks:
    - 16 injection/jailbreak pattern families
    - ChatML/XML role tag injection
    - Encoding evasion (base64, hex, unicode)
    - Role reassignment and memory reset
    - System prompt exfiltration attempts
    - JSON boundary escape
    """
    # text and context are now direct kwargs

    if not text:
        return {
            "ok": True,
            "severity": "OK",
            "findings": [],
            "finding_count": 0,
            "injection_detected": False,
            "patterns_checked": len(_COMPILED_PATTERNS),
            "context": context,
        }

    hits = _scan_text(text)

    severity = "OK"
    if any(h["severity"] == "CRITICAL" for h in hits):
        severity = "CRITICAL"
    elif any(h["severity"] == "HIGH" for h in hits):
        severity = "HIGH"
    elif any(h["severity"] == "MEDIUM" for h in hits):
        severity = "MEDIUM"

    findings = [
        f"{h['severity']}: {h['description']} (matched {h['match_count']}x)"
        for h in hits
    ]

    return {
        "ok": len(hits) == 0,
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "injection_detected": len(hits) > 0,
        "patterns_checked": len(_COMPILED_PATTERNS),
        "context": context,
        "hits": hits,
    }


# ─── Batch Scan ────────────────────────────────────────────────────────────

async def prompt_injection_batch(items: list | None = None) -> dict[str, Any]:
    """Batch scan multiple text inputs for injection patterns.

    Accepts a list of {id, text} objects and returns per-item results.
    """
    items = items or []
    if not isinstance(items, list):
        return {"ok": False, "severity": "HIGH", "findings": ["Invalid items: expected list"], "finding_count": 1}

    results: list[dict[str, Any]] = []
    total_hits = 0

    for item in items:
        if not isinstance(item, dict):
            continue
        item_id = item.get("id", "unknown")
        text = item.get("text", "")
        hits = _scan_text(text)
        total_hits += len(hits)
        results.append({
            "id": item_id,
            "injection_detected": len(hits) > 0,
            "hit_count": len(hits),
            "max_severity": (
                "CRITICAL" if any(h["severity"] == "CRITICAL" for h in hits) else
                "HIGH" if any(h["severity"] == "HIGH" for h in hits) else
                "MEDIUM" if any(h["severity"] == "MEDIUM" for h in hits) else
                "OK"
            ),
        })

    severity = "OK"
    if any(r["max_severity"] == "CRITICAL" for r in results):
        severity = "CRITICAL"
    elif any(r["max_severity"] == "HIGH" for r in results):
        severity = "HIGH"
    elif any(r["max_severity"] == "MEDIUM" for r in results):
        severity = "MEDIUM"

    return {
        "ok": total_hits == 0,
        "severity": severity,
        "findings": [f"{r['id']}: {r['max_severity']} ({r['hit_count']} hits)" for r in results if r["hit_count"] > 0],
        "finding_count": total_hits,
        "items_scanned": len(results),
        "items_flagged": sum(1 for r in results if r["injection_detected"]),
        "results": results,
    }


# ─── TOOLS Registration ───────────────────────────────────────────────────

_AUDIT_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean"},
        "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
        "findings": {"type": "array", "items": {"type": "string"}},
        "finding_count": {"type": "integer"},
        "injection_detected": {"type": "boolean"},
        "patterns_checked": {"type": "integer"},
    },
    "required": ["ok", "severity", "findings", "finding_count"],
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "firm_prompt_injection_check",
        "title": "Prompt Injection Detection",
        "description": (
            "Scan text for prompt injection and jailbreak patterns. "
            "Detects 16 pattern families including ChatML injection, role "
            "reassignment, memory reset, system prompt exfiltration, "
            "encoding evasion, and JSON boundary escape."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to scan for injection patterns"},
                "context": {
                    "type": "string",
                    "description": "Where the text comes from (user_input, tool_output, etc.)",
                    "default": "user_input",
                },
            },
            "required": ["text"],
        },
        "handler": prompt_injection_check,
        "category": "prompt_security",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
    {
        "name": "firm_prompt_injection_batch",
        "title": "Batch Prompt Injection Scan",
        "description": (
            "Batch scan multiple text inputs for injection patterns. "
            "Accepts a list of {id, text} objects and returns per-item "
            "results with severity and hit counts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "description": "List of {id, text} objects to scan",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "text": {"type": "string"},
                        },
                        "required": ["id", "text"],
                    },
                },
            },
            "required": ["items"],
        },
        "handler": prompt_injection_batch,
        "category": "prompt_security",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": _AUDIT_OUTPUT_SCHEMA,
    },
]
