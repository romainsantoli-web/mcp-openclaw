"""
Shared constants, PII patterns, and utility functions for the Hebbian memory package.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

from src.config_helpers import load_config, get_nested, mask_secret  # noqa: F401 — re-exported

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_DEFAULT_DB_PATH = os.path.expanduser("~/.openclaw/hebbian.db")

_DEFAULT_ALLOWED_DIRS: list[str] = [
    os.path.expanduser("~"),
    "/tmp",
    "/private/tmp",
    "/private/var/folders",
    "/var/folders",
]


def _get_allowed_dirs() -> list[str]:
    env = os.environ.get("HEBBIAN_ALLOWED_DIRS")
    if env:
        return [os.path.realpath(d) for d in env.split(":") if d.strip()]
    return [os.path.realpath(d) for d in _DEFAULT_ALLOWED_DIRS]


def _validate_hebbian_path(path_str: str, label: str = "path") -> str:
    resolved = os.path.realpath(os.path.abspath(path_str))
    allowed = _get_allowed_dirs()
    for d in allowed:
        if resolved.startswith(d + os.sep) or resolved == d:
            return path_str
    raise ValueError(
        f"{label} '{path_str}' resolves to '{resolved}' which is outside "
        f"allowed directories: {allowed}. Set HEBBIAN_ALLOWED_DIRS to extend."
    )


# CDC §4.3 — Hebbian parameters
_DEFAULT_LEARNING_RATE = 0.05
_DEFAULT_DECAY = 0.02
_WEIGHT_MIN = 0.0
_WEIGHT_MAX = 0.95

# CDC §3.3 — Consolidation thresholds
_THRESHOLD_EPISODIC_TO_EMERGENT = 5
_THRESHOLD_EMERGENT_TO_STRONG = 0.8
_THRESHOLD_STRONG_TO_CORE = 0.95
_THRESHOLD_ATROPHY = 0.10

# CDC §3.3 — Layer markers (regex patterns)
_LAYER_MARKERS = {
    1: re.compile(r"^#\s*[═]+\s*\n#\s*LAYER\s*1\b", re.MULTILINE | re.IGNORECASE),
    2: re.compile(r"^#\s*[═]+\s*\n#\s*LAYER\s*2\b", re.MULTILINE | re.IGNORECASE),
    3: re.compile(r"^#\s*[═]+\s*\n#\s*LAYER\s*3\b", re.MULTILINE | re.IGNORECASE),
    4: re.compile(r"^#\s*[═]+\s*\n#\s*LAYER\s*4\b", re.MULTILINE | re.IGNORECASE),
}

_LAYER_HEADERS_SIMPLE = {
    1: re.compile(r"LAYER\s*1\s*[\—\-–]+\s*CORE", re.IGNORECASE),
    2: re.compile(r"LAYER\s*2\s*[\—\-–]+\s*CONSOLIDATED", re.IGNORECASE),
    3: re.compile(r"LAYER\s*3\s*[\—\-–]+\s*EPISODIC", re.IGNORECASE),
    4: re.compile(r"LAYER\s*4\s*[\—\-–]+\s*META", re.IGNORECASE),
}

_WEIGHT_PATTERN = re.compile(r"^\s*-\s*\[(\d+\.\d+)\]\s+(.+)$", re.MULTILINE)

# ── PII stripping patterns (CDC §5.2) ───────────────────────────────────────

_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("email", re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")),
    ("api_key_sk", re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b")),
    ("api_key_pk", re.compile(r"\bpk-[a-zA-Z0-9]{20,}\b")),
    ("api_key_generic", re.compile(
        r"\b(?:api[_-]?key|token|secret|password|bearer)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?",
        re.IGNORECASE,
    )),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("phone", re.compile(r"\b(?:\+?1?\s*[-.]?\s*)?(?:\(\d{3}\)|\d{3})\s*[-.]?\s*\d{3}\s*[-.]?\s*\d{4}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("jwt", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")),
    ("unix_home_path", re.compile(
        r"(?:/home/[a-zA-Z0-9._-]+|/Users/[a-zA-Z0-9._-]+|/root)"
        r"(?:/[a-zA-Z0-9._@:~-]+){1,10}"
    )),
]


def _strip_pii(text: str) -> str:
    """Remove PII/secrets from text before storage. CDC §5.2 compliance."""
    result = text
    for label, pattern in _PII_PATTERNS:
        result = pattern.sub(f"[REDACTED_{label.upper()}]", result)
    return result


# ── SQLite schema ────────────────────────────────────────────────────────────

_CREATE_SESSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS hebbian_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    summary TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    quality_score REAL CHECK (quality_score BETWEEN 0.0 AND 1.0),
    rules_activated TEXT NOT NULL DEFAULT '[]',
    git_diff_hash TEXT,
    archived INTEGER NOT NULL DEFAULT 0
)
"""

_CREATE_WEIGHT_HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS hebbian_weight_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    old_weight REAL NOT NULL,
    new_weight REAL NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"""


def _init_db(db_path: str) -> sqlite3.Connection:
    db_dir = Path(db_path).parent
    db_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(_CREATE_SESSIONS_TABLE)
    conn.execute(_CREATE_WEIGHT_HISTORY_TABLE)
    conn.commit()
    return conn


# ── TF-IDF cosine similarity (CDC §5.1) ─────────────────────────────────────

def _tokenize(text: str) -> list[str]:
    return re.findall(r"\b\w+\b", text.lower())


def _cosine_similarity(text_a: str, text_b: str) -> float:
    tokens_a = Counter(_tokenize(text_a))
    tokens_b = Counter(_tokenize(text_b))
    if not tokens_a or not tokens_b:
        return 0.0
    common_keys = set(tokens_a.keys()) & set(tokens_b.keys())
    dot = sum(tokens_a[k] * tokens_b[k] for k in common_keys)
    mag_a = math.sqrt(sum(v * v for v in tokens_a.values()))
    mag_b = math.sqrt(sum(v * v for v in tokens_b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


# ── Layer parsing helpers ────────────────────────────────────────────────────

def _detect_layers(content: str) -> dict[int, bool]:
    found = {}
    for layer_num in (1, 2, 3, 4):
        primary = _LAYER_MARKERS[layer_num].search(content)
        fallback = _LAYER_HEADERS_SIMPLE[layer_num].search(content)
        found[layer_num] = bool(primary or fallback)
    return found


def _extract_layer2_rules(content: str) -> list[dict[str, Any]]:
    rules = []
    for match in _WEIGHT_PATTERN.finditer(content):
        weight = float(match.group(1))
        text = match.group(2).strip()
        rule_id = re.sub(r"[^a-z0-9]+", "-", text.lower())[:60].strip("-")
        rules.append({"rule_id": rule_id, "weight": weight, "text": text})
    return rules
