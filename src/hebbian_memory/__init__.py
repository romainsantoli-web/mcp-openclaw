"""
hebbian_memory — Adaptive Hebbian memory system for OpenClaw (package).

Split from a 1560-line monolith into 4 submodules:
  _helpers.py    — constants, PII patterns, utility functions
  _runtime.py    — harvest + weight_update tools
  _analysis.py   — analyze + status tools
  _validation.py — layer_validate, pii_check, decay_config_check, drift_check

Public API is unchanged: ``from src.hebbian_memory import TOOLS``.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

from typing import Any

# Re-export all public tool functions
from ._runtime import (  # noqa: F401
    openclaw_hebbian_harvest,
    openclaw_hebbian_weight_update,
    _compute_hebbian_weights,
    _apply_weight_changes,
)
from ._analysis import (  # noqa: F401
    openclaw_hebbian_analyze,
    openclaw_hebbian_status,
)
from ._validation import (  # noqa: F401
    openclaw_hebbian_layer_validate,
    openclaw_hebbian_pii_check,
    openclaw_hebbian_decay_config_check,
    openclaw_hebbian_drift_check,
)
from ._helpers import (  # noqa: F401
    _init_db,
    _validate_hebbian_path,
)

# ════════════════════════════════════════════════════════════════════════════════
# TOOLS registry — identical to the old monolithic version
# ════════════════════════════════════════════════════════════════════════════════

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_hebbian_harvest",
        "title": "Hebbian Session Harvest",
        "description": (
            "Ingest JSONL session logs into the local Hebbian SQLite database. "
            "PII/secrets are stripped before storage (CDC §5.2). "
            "Supports session summary, tags, quality score, rule activations."
        ),
        "category": "hebbian_memory",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "handler": openclaw_hebbian_harvest,
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_jsonl_path": {"type": "string", "description": "Path to JSONL file with session data."},
                "claude_md_path": {"type": "string", "description": "Optional Claude.md path for rule activation matching."},
                "db_path": {"type": "string", "description": "SQLite database path. Default: ~/.openclaw/hebbian.db."},
                "max_lines": {"type": "integer", "description": "Max lines to ingest. Default: 50000."},
            },
            "required": ["session_jsonl_path"],
        },
    },
    {
        "name": "openclaw_hebbian_weight_update",
        "title": "Hebbian Weight Update",
        "description": (
            "Compute or apply Hebbian weight updates on Layer 2 rules in Claude.md. "
            "Uses the formula: new = old + (lr × activation) - (decay × (1-activation)). "
            "Default dry_run=True (simulation only). CDC §4.3 + §4.4."
        ),
        "category": "hebbian_memory",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "handler": openclaw_hebbian_weight_update,
        "inputSchema": {
            "type": "object",
            "properties": {
                "claude_md_path": {"type": "string", "description": "Path to Claude.md file."},
                "db_path": {"type": "string", "description": "SQLite database path."},
                "learning_rate": {"type": "number", "description": "Reinforcement rate. Default: 0.05."},
                "decay": {"type": "number", "description": "Atrophy rate. Default: 0.02."},
                "dry_run": {"type": "boolean", "description": "Simulate only (true) or write changes (false). Default: true."},
            },
            "required": ["claude_md_path"],
        },
    },
    {
        "name": "openclaw_hebbian_analyze",
        "title": "Hebbian Co-Activation Analysis",
        "description": (
            "Analyze co-activation patterns from harvested sessions. "
            "Uses Jaccard similarity for tag co-occurrence and rule co-activation. "
            "Returns top pattern candidates. CDC §4.3 clustering."
        ),
        "category": "hebbian_memory",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "handler": openclaw_hebbian_analyze,
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_path": {"type": "string", "description": "SQLite database path."},
                "since_days": {"type": "integer", "description": "Look back N days. Default: 90."},
                "min_cluster_size": {"type": "integer", "description": "Min sessions to form a pattern. Default: 5."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_hebbian_status",
        "title": "Hebbian Memory Dashboard",
        "description": (
            "Dashboard: total sessions, Layer 2 rule weights, atrophy/promotion candidates, "
            "last harvest timestamp, weight update history. CDC §7 monitoring."
        ),
        "category": "hebbian_memory",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "handler": openclaw_hebbian_status,
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_path": {"type": "string", "description": "SQLite database path."},
                "claude_md_path": {"type": "string", "description": "Claude.md path for reading current weights."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_hebbian_layer_validate",
        "title": "Hebbian Layer Validation",
        "description": (
            "Validate the 4-layer structure of a Hebbian-augmented Claude.md: "
            "CORE (L1), CONSOLIDATED PATTERNS (L2), EPISODIC INDEX (L3), META (L4). CDC §3.3."
        ),
        "category": "hebbian_memory",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"}, "severity": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "string"}},
                "finding_count": {"type": "integer"},
            },
            "required": ["ok", "severity", "findings", "finding_count"],
        },
        "handler": openclaw_hebbian_layer_validate,
        "inputSchema": {
            "type": "object",
            "properties": {
                "claude_md_path": {"type": "string", "description": "Path to Claude.md file."},
            },
            "required": ["claude_md_path"],
        },
    },
    {
        "name": "openclaw_hebbian_pii_check",
        "title": "Hebbian PII Stripping Check",
        "description": (
            "Audit PII stripping configuration: regex patterns (email, phone, IP, API keys), "
            "secret detection, embedding rotation policy, access restriction. CDC §5.2."
        ),
        "category": "hebbian_memory",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"}, "severity": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "string"}},
                "finding_count": {"type": "integer"},
            },
            "required": ["ok", "severity", "findings", "finding_count"],
        },
        "handler": openclaw_hebbian_pii_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {"type": "string", "description": "Path to OpenClaw config JSON."},
                "config_data": {"type": "object", "description": "Inline config dict (for testing)."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_hebbian_decay_config_check",
        "title": "Hebbian Decay Config Check",
        "description": (
            "Validate Hebbian parameters: learning_rate, decay, poids_min/max, "
            "consolidation thresholds (episodic→emergent, emergent→strong). CDC §4.3."
        ),
        "category": "hebbian_memory",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"}, "severity": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "string"}},
                "finding_count": {"type": "integer"},
            },
            "required": ["ok", "severity", "findings", "finding_count"],
        },
        "handler": openclaw_hebbian_decay_config_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {"type": "string", "description": "Path to OpenClaw config JSON."},
                "config_data": {"type": "object", "description": "Inline config dict (for testing)."},
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_hebbian_drift_check",
        "title": "Hebbian Semantic Drift Check",
        "description": (
            "Detect Claude.md semantic drift vs a baseline using TF-IDF cosine similarity. "
            "Alerts if similarity drops below threshold (default 0.7). CDC §5.1 anti-dérive."
        ),
        "category": "hebbian_memory",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"}, "severity": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "string"}},
                "finding_count": {"type": "integer"},
            },
            "required": ["ok", "severity", "findings", "finding_count"],
        },
        "handler": openclaw_hebbian_drift_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "claude_md_path": {"type": "string", "description": "Path to current Claude.md."},
                "baseline_path": {"type": "string", "description": "Path to baseline Claude.md."},
                "threshold": {"type": "number", "description": "Alert if similarity < threshold. Default: 0.7."},
            },
            "required": ["claude_md_path"],
        },
    },
]
