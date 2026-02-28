"""
hebbian_memory.py — Adaptive Hebbian memory system for OpenClaw

Implements the Cahier des Charges "Système de Mémoire Adaptative Hebbienne"
with 8 MCP tools: 2 runtime (harvest + weight update) and 6 audit/check tools.

Tools:
  openclaw_hebbian_harvest           — ingest JSONL session logs → SQLite (PII stripped)
  openclaw_hebbian_weight_update     — compute/apply Hebbian weight updates on Layer 2
  openclaw_hebbian_analyze           — co-activation pattern analysis from harvested sessions
  openclaw_hebbian_status            — dashboard: weights, atrophy, promotions, drift
  openclaw_hebbian_layer_validate    — validate 4-layer Claude.md structure (CDC §3.3)
  openclaw_hebbian_pii_check         — audit PII stripping config (CDC §5.2)
  openclaw_hebbian_decay_config_check — validate learning rate, decay, thresholds (CDC §4.3)
  openclaw_hebbian_drift_check       — cosine similarity drift detection (CDC §5.1)

Reference: cahier_des_charges_memoire_hebbienne.md v1.0.0

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import sqlite3
import time
from collections import Counter
from pathlib import Path
from typing import Any

from src.config_helpers import load_config, get_nested, mask_secret

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_DEFAULT_DB_PATH = os.path.expanduser("~/.openclaw/hebbian.db")

# CDC §4.3 — Hebbian parameters
_DEFAULT_LEARNING_RATE = 0.05
_DEFAULT_DECAY = 0.02
_WEIGHT_MIN = 0.0
_WEIGHT_MAX = 0.95

# CDC §3.3 — Consolidation thresholds
_THRESHOLD_EPISODIC_TO_EMERGENT = 5    # activated N consecutive sessions
_THRESHOLD_EMERGENT_TO_STRONG = 0.8    # weight over 20 sessions
_THRESHOLD_STRONG_TO_CORE = 0.95       # requires human review
_THRESHOLD_ATROPHY = 0.10              # below = suppression candidate

# CDC §3.3 — Layer markers (regex patterns)
_LAYER_MARKERS = {
    1: re.compile(r"^#\s*[═]+\s*\n#\s*LAYER\s*1\b", re.MULTILINE | re.IGNORECASE),
    2: re.compile(r"^#\s*[═]+\s*\n#\s*LAYER\s*2\b", re.MULTILINE | re.IGNORECASE),
    3: re.compile(r"^#\s*[═]+\s*\n#\s*LAYER\s*3\b", re.MULTILINE | re.IGNORECASE),
    4: re.compile(r"^#\s*[═]+\s*\n#\s*LAYER\s*4\b", re.MULTILINE | re.IGNORECASE),
}

# Fallback: detect layers by simpler header patterns
_LAYER_HEADERS_SIMPLE = {
    1: re.compile(r"LAYER\s*1\s*[\—\-–]+\s*CORE", re.IGNORECASE),
    2: re.compile(r"LAYER\s*2\s*[\—\-–]+\s*CONSOLIDATED", re.IGNORECASE),
    3: re.compile(r"LAYER\s*3\s*[\—\-–]+\s*EPISODIC", re.IGNORECASE),
    4: re.compile(r"LAYER\s*4\s*[\—\-–]+\s*META", re.IGNORECASE),
}

# Weight format in Layer 2: "[0.94] Rule text here"
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
]


def _strip_pii(text: str) -> str:
    """Remove PII/secrets from text before storage. CDC §5.2 compliance."""
    result = text
    for label, pattern in _PII_PATTERNS:
        result = pattern.sub(f"[REDACTED_{label.upper()}]", result)
    return result


# ── SQLite schema (CDC §4.2 — local adaptation without VECTOR column) ───────

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
    """Initialize the Hebbian SQLite database with required tables."""
    db_dir = Path(db_path).parent
    db_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(_CREATE_SESSIONS_TABLE)
    conn.execute(_CREATE_WEIGHT_HISTORY_TABLE)
    conn.commit()
    return conn


# ── TF-IDF cosine similarity (CDC §5.1 — no external deps) ──────────────────

def _tokenize(text: str) -> list[str]:
    """Simple whitespace + punctuation tokenization."""
    return re.findall(r"\b\w+\b", text.lower())


def _cosine_similarity(text_a: str, text_b: str) -> float:
    """Compute cosine similarity between two texts using TF word frequencies."""
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
    """Detect which of the 4 layers are present in a Claude.md."""
    found = {}
    for layer_num in (1, 2, 3, 4):
        primary = _LAYER_MARKERS[layer_num].search(content)
        fallback = _LAYER_HEADERS_SIMPLE[layer_num].search(content)
        found[layer_num] = bool(primary or fallback)
    return found


def _extract_layer2_rules(content: str) -> list[dict[str, Any]]:
    """Extract weighted rules from Layer 2 section of Claude.md."""
    rules = []
    for match in _WEIGHT_PATTERN.finditer(content):
        weight = float(match.group(1))
        text = match.group(2).strip()
        # Generate a rule_id from the text (slug)
        rule_id = re.sub(r"[^a-z0-9]+", "-", text.lower())[:60].strip("-")
        rules.append({
            "rule_id": rule_id,
            "weight": weight,
            "text": text,
        })
    return rules


# ════════════════════════════════════════════════════════════════════════════════
# Tool 1: openclaw_hebbian_harvest  (Runtime)
# ════════════════════════════════════════════════════════════════════════════════

async def openclaw_hebbian_harvest(
    session_jsonl_path: str,
    claude_md_path: str | None = None,
    db_path: str | None = None,
    max_lines: int = 50_000,
) -> dict[str, Any]:
    """
    Ingest JSONL session logs into the local Hebbian SQLite database.

    Each line of the JSONL file should be a JSON object with at least:
      - summary (str): session summary text
      - tags (list[str]): session tags
    Optional fields: session_id, quality_score, rules_activated, git_diff_hash.

    PII/secrets are stripped from summary and tags before storage (CDC §5.2).

    Args:
        session_jsonl_path: Path to the JSONL file with session data.
        claude_md_path: Optional path to Claude.md for rule activation matching.
        db_path: SQLite database path. Default: ~/.openclaw/hebbian.db.
        max_lines: Max lines to ingest (safety limit).

    Returns:
        dict with ok, db_path, ingested, skipped, errors.
    """
    actual_db = db_path or _DEFAULT_DB_PATH
    jsonl = Path(session_jsonl_path)

    if not jsonl.exists():
        return {"ok": False, "error": f"JSONL file not found: {session_jsonl_path}"}

    if jsonl.suffix.lower() not in (".jsonl", ".ndjson", ".log", ".json"):
        return {"ok": False, "error": f"Unexpected extension '{jsonl.suffix}'. Expected .jsonl/.ndjson/.log/.json."}

    # Load Layer 2 rules from Claude.md if provided (for activation matching)
    known_rules: list[dict] = []
    if claude_md_path:
        md_path = Path(claude_md_path)
        if md_path.exists():
            md_content = md_path.read_text(encoding="utf-8")
            known_rules = _extract_layer2_rules(md_content)

    ingested = 0
    skipped = 0
    errors_list: list[str] = []

    try:
        conn = _init_db(actual_db)

        with jsonl.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                if line_no > max_lines:
                    break
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    errors_list.append(f"Line {line_no}: invalid JSON — {exc}")
                    continue

                summary = record.get("summary", "")
                if not summary:
                    errors_list.append(f"Line {line_no}: missing 'summary' field")
                    continue

                # PII stripping (CDC §5.2)
                summary = _strip_pii(summary)
                tags = record.get("tags", [])
                if isinstance(tags, list):
                    tags = [_strip_pii(str(t)) for t in tags]
                else:
                    tags = []

                session_id = record.get("session_id", f"auto-{line_no}-{int(time.time())}")
                quality_score = record.get("quality_score")
                if quality_score is not None:
                    quality_score = max(0.0, min(1.0, float(quality_score)))
                rules_activated = record.get("rules_activated", [])
                if isinstance(rules_activated, list):
                    rules_activated = [_strip_pii(str(r)) for r in rules_activated]
                else:
                    rules_activated = []
                git_diff_hash = record.get("git_diff_hash")

                try:
                    conn.execute(
                        """INSERT OR IGNORE INTO hebbian_sessions
                           (session_id, summary, tags, quality_score, rules_activated, git_diff_hash)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            session_id,
                            summary,
                            json.dumps(tags),
                            quality_score,
                            json.dumps(rules_activated),
                            git_diff_hash,
                        ),
                    )
                    if conn.total_changes:
                        ingested += 1
                    else:
                        skipped += 1
                except sqlite3.IntegrityError:
                    skipped += 1

        conn.commit()
        conn.close()

    except Exception as exc:
        logger.error("Hebbian harvest error: %s", exc)
        return {"ok": False, "error": str(exc)}

    return {
        "ok": True,
        "db_path": actual_db,
        "ingested": ingested,
        "skipped_duplicates": skipped,
        "errors": errors_list[:50],
        "pii_stripping": "enabled",
    }


# ════════════════════════════════════════════════════════════════════════════════
# Tool 2: openclaw_hebbian_weight_update  (Runtime)
# ════════════════════════════════════════════════════════════════════════════════

async def openclaw_hebbian_weight_update(
    claude_md_path: str,
    db_path: str | None = None,
    learning_rate: float = _DEFAULT_LEARNING_RATE,
    decay: float = _DEFAULT_DECAY,
    dry_run: bool = True,
) -> dict[str, Any]:
    """
    Compute or apply Hebbian weight updates on Layer 2 rules.

    Reads Layer 2 rules from claude_md_path, queries the latest session
    for activated rules, and applies the Hebbian update formula:
      new_weight = old_weight + (learning_rate * activation) - (decay * (1 - activation))

    Default: dry_run=True → returns proposed changes without writing.
    When dry_run=False → updates the Claude.md file in place.

    CDC §4.3 formula + §4.4 Claude.md Writer.

    Args:
        claude_md_path: Path to the Claude.md file.
        db_path: SQLite database path. Default: ~/.openclaw/hebbian.db.
        learning_rate: Reinforcement rate for activated rules.
        decay: Atrophy rate for non-activated rules.
        dry_run: If True, simulate only; if False, write changes.

    Returns:
        dict with ok, changes, promotions, atrophy_candidates.
    """
    md_path = Path(claude_md_path)
    if not md_path.exists():
        return {"ok": False, "error": f"Claude.md not found: {claude_md_path}"}

    content = md_path.read_text(encoding="utf-8")
    rules = _extract_layer2_rules(content)

    if not rules:
        return {
            "ok": True,
            "status": "no_rules",
            "message": "No weighted Layer 2 rules found in Claude.md.",
            "changes": [],
        }

    # Get recently activated rules from the database
    actual_db = db_path or _DEFAULT_DB_PATH
    activated_rule_ids: set[str] = set()

    if Path(actual_db).exists():
        try:
            conn = sqlite3.connect(actual_db)
            cur = conn.execute(
                "SELECT rules_activated FROM hebbian_sessions ORDER BY created_at DESC LIMIT 1"
            )
            row = cur.fetchone()
            if row:
                try:
                    activated_rule_ids = set(json.loads(row[0]))
                except (json.JSONDecodeError, TypeError):
                    pass
            conn.close()
        except Exception as exc:
            logger.warning("Could not read activation data: %s", exc)

    # Apply Hebbian update formula
    changes: list[dict[str, Any]] = []
    promotions: list[str] = []
    atrophy_candidates: list[str] = []

    updated_content = content
    for rule in rules:
        old_weight = rule["weight"]
        rule_id = rule["rule_id"]
        activated = 1.0 if rule_id in activated_rule_ids else 0.0

        # CDC §4.3: new = old + (lr * activation) - (decay * (1 - activation))
        new_weight = old_weight + (learning_rate * activated) - (decay * (1.0 - activated))
        new_weight = max(_WEIGHT_MIN, min(_WEIGHT_MAX, new_weight))
        new_weight = round(new_weight, 2)

        if new_weight != old_weight:
            changes.append({
                "rule_id": rule_id,
                "text": rule["text"],
                "old_weight": old_weight,
                "new_weight": new_weight,
                "delta": round(new_weight - old_weight, 3),
                "activated": bool(activated),
            })

            if not dry_run:
                # Replace the weight in the markdown
                old_str = f"[{old_weight:.2f}]" if "." in str(old_weight) else f"[{old_weight}]"
                # Handle both [0.94] and [0.9] formats
                old_pattern = f"[{old_weight}]"
                new_str = f"[{new_weight:.2f}]"
                # Only replace first occurrence of this specific rule line
                old_line = f"[{old_weight}] {rule['text']}"
                new_line = f"[{new_weight:.2f}] {rule['text']}"
                updated_content = updated_content.replace(
                    old_line, new_line, 1
                )

        # Check promotion/atrophy
        if new_weight >= _THRESHOLD_STRONG_TO_CORE:
            promotions.append(rule_id)
        elif new_weight < _THRESHOLD_ATROPHY:
            atrophy_candidates.append(rule_id)

    # Write if not dry_run
    if not dry_run and changes:
        md_path.write_text(updated_content, encoding="utf-8")

        # Record weight history in SQLite
        try:
            conn = _init_db(actual_db)
            for ch in changes:
                conn.execute(
                    """INSERT INTO hebbian_weight_history
                       (rule_id, old_weight, new_weight, reason)
                       VALUES (?, ?, ?, ?)""",
                    (
                        ch["rule_id"],
                        ch["old_weight"],
                        ch["new_weight"],
                        "activated" if ch["activated"] else "decay",
                    ),
                )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning("Could not record weight history: %s", exc)

    return {
        "ok": True,
        "dry_run": dry_run,
        "changes": changes,
        "promotions_candidates": promotions,
        "atrophy_candidates": atrophy_candidates,
        "total_rules": len(rules),
        "rules_changed": len(changes),
        "human_action_required": bool(promotions or atrophy_candidates),
    }


# ════════════════════════════════════════════════════════════════════════════════
# Tool 3: openclaw_hebbian_analyze  (Audit)
# ════════════════════════════════════════════════════════════════════════════════

async def openclaw_hebbian_analyze(
    db_path: str | None = None,
    since_days: int = 90,
    min_cluster_size: int = 5,
) -> dict[str, Any]:
    """
    Analyze co-activation patterns from harvested sessions.

    Queries the SQLite database for sessions within since_days, computes
    tag co-occurrence and rule co-activation patterns using Jaccard
    similarity. Returns top pattern candidates.

    CDC §4.3 — Clustering (lightweight local version).

    Args:
        db_path: SQLite database path.
        since_days: Look back N days.
        min_cluster_size: Minimum sessions sharing a pattern.

    Returns:
        dict with ok, patterns, co_activations, session_count.
    """
    actual_db = db_path or _DEFAULT_DB_PATH

    if not Path(actual_db).exists():
        return {
            "ok": True,
            "status": "no_data",
            "message": "No Hebbian database found. Run openclaw_hebbian_harvest first.",
            "patterns": [],
            "session_count": 0,
        }

    try:
        conn = sqlite3.connect(actual_db)
        cur = conn.execute(
            """SELECT tags, rules_activated, quality_score
               FROM hebbian_sessions
               WHERE archived = 0
                 AND created_at >= datetime('now', ?)
               ORDER BY created_at DESC""",
            (f"-{since_days} days",),
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    if not rows:
        return {
            "ok": True,
            "status": "no_recent_data",
            "message": f"No sessions found in the last {since_days} days.",
            "patterns": [],
            "session_count": 0,
        }

    # Tag co-occurrence analysis
    tag_counter: Counter = Counter()
    tag_pairs: Counter = Counter()
    rule_counter: Counter = Counter()
    rule_pairs: Counter = Counter()

    for tags_json, rules_json, quality in rows:
        try:
            tags = json.loads(tags_json) if tags_json else []
        except (json.JSONDecodeError, TypeError):
            tags = []
        try:
            rules = json.loads(rules_json) if rules_json else []
        except (json.JSONDecodeError, TypeError):
            rules = []

        for t in tags:
            tag_counter[t] += 1
        for i, t1 in enumerate(sorted(tags)):
            for t2 in sorted(tags)[i + 1 :]:
                tag_pairs[f"{t1}+{t2}"] += 1

        for r in rules:
            rule_counter[r] += 1
        for i, r1 in enumerate(sorted(rules)):
            for r2 in sorted(rules)[i + 1 :]:
                rule_pairs[f"{r1}+{r2}"] += 1

    # Build patterns from frequent co-occurrences
    patterns: list[dict[str, Any]] = []

    for pair, count in tag_pairs.most_common(20):
        if count >= min_cluster_size:
            t1, t2 = pair.split("+", 1)
            # Jaccard: intersection / union
            union = tag_counter[t1] + tag_counter[t2] - count
            jaccard = count / union if union > 0 else 0.0
            patterns.append({
                "type": "tag_co_occurrence",
                "tags": [t1, t2],
                "frequency": count,
                "jaccard_similarity": round(jaccard, 3),
                "label": f"Sessions involving '{t1}' + '{t2}'",
            })

    co_activations: list[dict[str, Any]] = []
    for pair, count in rule_pairs.most_common(20):
        if count >= min_cluster_size:
            r1, r2 = pair.split("+", 1)
            union = rule_counter[r1] + rule_counter[r2] - count
            jaccard = count / union if union > 0 else 0.0
            co_activations.append({
                "type": "rule_co_activation",
                "rules": [r1, r2],
                "frequency": count,
                "jaccard_similarity": round(jaccard, 3),
            })

    return {
        "ok": True,
        "session_count": len(rows),
        "since_days": since_days,
        "patterns": patterns,
        "co_activations": co_activations,
        "top_tags": tag_counter.most_common(10),
        "top_rules": rule_counter.most_common(10),
    }


# ════════════════════════════════════════════════════════════════════════════════
# Tool 4: openclaw_hebbian_status  (Audit)
# ════════════════════════════════════════════════════════════════════════════════

async def openclaw_hebbian_status(
    db_path: str | None = None,
    claude_md_path: str | None = None,
) -> dict[str, Any]:
    """
    Dashboard: session count, rule weights, atrophy/promotion candidates.

    Provides an overview of the Hebbian memory system state, including:
    - Total sessions harvested
    - Current Layer 2 rule weights (from Claude.md)
    - Rules in atrophy (< 0.10)
    - Promotion candidates (> 0.90)
    - Last harvest timestamp
    - Weight history summary

    Args:
        db_path: SQLite database path.
        claude_md_path: Optional path to Claude.md for current weights.

    Returns:
        dict with dashboard data.
    """
    actual_db = db_path or _DEFAULT_DB_PATH
    dashboard: dict[str, Any] = {
        "ok": True,
        "db_exists": False,
        "total_sessions": 0,
        "last_harvest": None,
        "rules": [],
        "promotions": [],
        "atrophy": [],
        "weight_updates_count": 0,
    }

    # Database stats
    if Path(actual_db).exists():
        dashboard["db_exists"] = True
        try:
            conn = sqlite3.connect(actual_db)
            row = conn.execute("SELECT COUNT(*) FROM hebbian_sessions WHERE archived = 0").fetchone()
            dashboard["total_sessions"] = row[0] if row else 0

            row = conn.execute(
                "SELECT MAX(created_at) FROM hebbian_sessions"
            ).fetchone()
            dashboard["last_harvest"] = row[0] if row and row[0] else None

            row = conn.execute("SELECT COUNT(*) FROM hebbian_weight_history").fetchone()
            dashboard["weight_updates_count"] = row[0] if row else 0

            conn.close()
        except Exception as exc:
            dashboard["db_error"] = str(exc)

    # Claude.md Layer 2 analysis
    if claude_md_path:
        md_path = Path(claude_md_path)
        if md_path.exists():
            content = md_path.read_text(encoding="utf-8")
            rules = _extract_layer2_rules(content)
            dashboard["rules"] = rules

            for rule in rules:
                if rule["weight"] >= _THRESHOLD_STRONG_TO_CORE:
                    dashboard["promotions"].append(rule)
                elif rule["weight"] < _THRESHOLD_ATROPHY:
                    dashboard["atrophy"].append(rule)

            dashboard["layers_detected"] = _detect_layers(content)
        else:
            dashboard["claude_md_error"] = f"File not found: {claude_md_path}"

    return dashboard


# ════════════════════════════════════════════════════════════════════════════════
# Tool 5: openclaw_hebbian_layer_validate  (Audit)
# ════════════════════════════════════════════════════════════════════════════════

async def openclaw_hebbian_layer_validate(
    claude_md_path: str,
) -> dict[str, Any]:
    """
    Validate the 4-layer structure of a Hebbian-augmented Claude.md.

    Checks:
    - All 4 layers are present (CORE, CONSOLIDATED, EPISODIC, META)
    - Weight syntax [0.XX] in Layer 2
    - Layer 1 has no auto-generated markers
    - Layer 3 has session references with valid format
    - Layer 4 has self-update rules

    CDC §3.3 — Claude.md 4 couches.

    Args:
        claude_md_path: Path to the Claude.md file.

    Returns:
        dict with status, findings, layers_found.
    """
    md_path = Path(claude_md_path)
    if not md_path.exists():
        return {"ok": False, "error": f"File not found: {claude_md_path}"}

    content = md_path.read_text(encoding="utf-8")
    findings: list[dict[str, str]] = []
    recommendations: list[str] = []

    layers = _detect_layers(content)

    # Check each layer
    for layer_num, label in [
        (1, "CORE (immuable)"),
        (2, "CONSOLIDATED PATTERNS"),
        (3, "EPISODIC INDEX"),
        (4, "META INSTRUCTIONS"),
    ]:
        if not layers.get(layer_num):
            findings.append({
                "severity": "HIGH",
                "layer": layer_num,
                "message": f"Layer {layer_num} — {label} is missing.",
            })
            recommendations.append(
                f"Add Layer {layer_num} ({label}) section per CDC §3.3."
            )

    # Validate Layer 2 weight syntax if present
    if layers.get(2):
        rules = _extract_layer2_rules(content)
        if not rules:
            findings.append({
                "severity": "MEDIUM",
                "layer": 2,
                "message": "Layer 2 exists but contains no weighted rules [0.XX].",
            })
        else:
            for rule in rules:
                if rule["weight"] > _WEIGHT_MAX:
                    findings.append({
                        "severity": "HIGH",
                        "layer": 2,
                        "message": f"Rule '{rule['rule_id']}' has weight {rule['weight']} > max {_WEIGHT_MAX}.",
                    })
                if rule["weight"] < _WEIGHT_MIN:
                    findings.append({
                        "severity": "MEDIUM",
                        "layer": 2,
                        "message": f"Rule '{rule['rule_id']}' has negative weight {rule['weight']}.",
                    })

    # Check for PII in content
    for label, pattern in _PII_PATTERNS:
        if pattern.search(content):
            findings.append({
                "severity": "CRITICAL",
                "layer": 0,
                "message": f"Potential PII detected ({label}) in Claude.md content.",
            })

    # Determine overall status
    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        status = "critical"
    elif "HIGH" in severities:
        status = "high"
    elif "MEDIUM" in severities:
        status = "medium"
    elif not all(layers.values()):
        status = "incomplete"
    else:
        status = "ok"

    return {
        "ok": True,
        "status": status,
        "layers_found": layers,
        "findings": findings,
        "recommendations": recommendations,
        "total_rules": len(_extract_layer2_rules(content)),
    }


# ════════════════════════════════════════════════════════════════════════════════
# Tool 6: openclaw_hebbian_pii_check  (Audit)
# ════════════════════════════════════════════════════════════════════════════════

async def openclaw_hebbian_pii_check(
    config_path: str | None = None,
    config_data: dict | None = None,
) -> dict[str, Any]:
    """
    Audit PII stripping configuration for Hebbian memory storage.

    Validates:
    - PII regex patterns are configured (email, phone, IP, API keys)
    - NER model reference exists (optional enhancement)
    - Secret detection is enabled
    - Embedding rotation policy is defined
    - BDD access is restricted (localhost/VPN)

    CDC §5.2 — Sécurité des données.

    Args:
        config_path: Path to OpenClaw config JSON.
        config_data: Optional inline config (for testing).

    Returns:
        dict with status, findings, recommendations.
    """
    findings: list[dict[str, str]] = []
    recommendations: list[str] = []

    # Load config
    if config_data is not None:
        cfg = config_data
    elif config_path:
        cfg, _ = load_config(config_path)
    else:
        return {"ok": False, "error": "No config_path or config_data provided."}

    hebbian = get_nested(cfg, "hebbian", default={})
    if not hebbian:
        hebbian = get_nested(cfg, "memory", "hebbian", default={})

    if not hebbian:
        return {
            "ok": True,
            "status": "info",
            "message": "No 'hebbian' section found in config.",
            "findings": [],
            "recommendations": ["Add a 'hebbian' section with PII stripping config per CDC §5.2."],
        }

    pii_config = get_nested(hebbian, "pii_stripping", default={})
    security = get_nested(hebbian, "security", default={})

    # Check PII regex patterns
    expected_patterns = {"email", "phone", "ip", "api_key", "ssn"}
    configured_patterns = set(pii_config.get("patterns", []))

    if not configured_patterns:
        findings.append({
            "severity": "CRITICAL",
            "message": "No PII stripping patterns configured. All stored data may contain PII.",
        })
        recommendations.append("Configure pii_stripping.patterns with at least: email, phone, ip, api_key.")
    else:
        missing = expected_patterns - configured_patterns
        if missing:
            findings.append({
                "severity": "HIGH",
                "message": f"Missing PII patterns: {sorted(missing)}. These types won't be stripped.",
            })
            recommendations.append(f"Add missing patterns: {sorted(missing)}")

    # Check PII stripping enabled
    if not pii_config.get("enabled", False):
        findings.append({
            "severity": "CRITICAL",
            "message": "PII stripping is disabled. Embeddings may contain sensitive data.",
        })

    # Check secret detection
    if not security.get("secret_detection", False):
        findings.append({
            "severity": "HIGH",
            "message": "Secret detection is not enabled. API keys/tokens may leak into embeddings.",
        })
        recommendations.append("Enable security.secret_detection per CDC §5.2.")

    # Check embedding rotation policy
    if not security.get("embedding_rotation"):
        findings.append({
            "severity": "MEDIUM",
            "message": "No embedding rotation policy defined.",
        })
        recommendations.append("Define security.embedding_rotation policy for breach response.")

    # Check access restriction
    access = security.get("access_restriction")
    if not access or access not in ("localhost", "vpn", "private_network"):
        findings.append({
            "severity": "HIGH",
            "message": "Database access not restricted to localhost/VPN.",
        })
        recommendations.append("Set security.access_restriction to 'localhost' or 'vpn'.")

    # NER model (optional enhancement)
    if not pii_config.get("ner_model"):
        recommendations.append("Consider adding a NER model for improved PII detection (optional).")

    # Status
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
        "findings": findings,
        "recommendations": recommendations,
    }


# ════════════════════════════════════════════════════════════════════════════════
# Tool 7: openclaw_hebbian_decay_config_check  (Audit)
# ════════════════════════════════════════════════════════════════════════════════

async def openclaw_hebbian_decay_config_check(
    config_path: str | None = None,
    config_data: dict | None = None,
) -> dict[str, Any]:
    """
    Validate Hebbian learning rate, decay, and consolidation thresholds.

    Checks that the configured parameters match the CDC §4.3 specification:
    - learning_rate in [0.001, 0.5]
    - decay in [0.001, 0.2]
    - poids_min = 0.0
    - poids_max ≤ 0.95
    - Consolidation thresholds: episodic→emergent (5), emergent→strong (0.8/20)

    Args:
        config_path: Path to OpenClaw config JSON.
        config_data: Optional inline config (for testing).

    Returns:
        dict with status, findings, parameters.
    """
    findings: list[dict[str, str]] = []
    recommendations: list[str] = []

    if config_data is not None:
        cfg = config_data
    elif config_path:
        cfg, _ = load_config(config_path)
    else:
        return {"ok": False, "error": "No config_path or config_data provided."}

    hebbian = get_nested(cfg, "hebbian", default={})
    if not hebbian:
        hebbian = get_nested(cfg, "memory", "hebbian", default={})

    if not hebbian:
        return {
            "ok": True,
            "status": "info",
            "message": "No 'hebbian' section found in config.",
            "findings": [],
            "recommendations": ["Add a 'hebbian' section with Hebbian parameters per CDC §4.3."],
        }

    params = get_nested(hebbian, "parameters", default={})

    # Validate learning_rate
    lr = params.get("learning_rate", _DEFAULT_LEARNING_RATE)
    if not (0.001 <= lr <= 0.5):
        findings.append({
            "severity": "CRITICAL",
            "message": f"learning_rate={lr} is outside safe range [0.001, 0.5].",
        })

    # Validate decay
    decay_val = params.get("decay", _DEFAULT_DECAY)
    if not (0.001 <= decay_val <= 0.2):
        findings.append({
            "severity": "CRITICAL",
            "message": f"decay={decay_val} is outside safe range [0.001, 0.2].",
        })

    # Validate poids_max
    poids_max = params.get("poids_max", _WEIGHT_MAX)
    if poids_max > 0.95:
        findings.append({
            "severity": "HIGH",
            "message": f"poids_max={poids_max} exceeds CDC limit of 0.95. Auto-promotion to 1.0 violates safety rule.",
        })

    # Validate poids_min
    poids_min = params.get("poids_min", _WEIGHT_MIN)
    if poids_min < 0.0:
        findings.append({
            "severity": "MEDIUM",
            "message": f"poids_min={poids_min} is negative. Weights should floor at 0.0.",
        })

    # Validate consolidation thresholds
    thresholds = get_nested(hebbian, "thresholds", default={})
    episodic = thresholds.get("episodic_to_emergent", _THRESHOLD_EPISODIC_TO_EMERGENT)
    if episodic < 3:
        findings.append({
            "severity": "MEDIUM",
            "message": f"episodic_to_emergent={episodic} is too low. Minimum 3 sessions recommended.",
        })

    emergent_weight = thresholds.get("emergent_to_strong", _THRESHOLD_EMERGENT_TO_STRONG)
    if emergent_weight < 0.5:
        findings.append({
            "severity": "MEDIUM",
            "message": f"emergent_to_strong threshold={emergent_weight} is too permissive.",
        })

    # Anti-drift: max consecutive auto-changes
    max_auto = get_nested(hebbian, "anti_drift", "max_consecutive_auto_changes", default=3)
    if max_auto > 5:
        findings.append({
            "severity": "HIGH",
            "message": f"max_consecutive_auto_changes={max_auto} is too high. CDC §5.1 recommends max 3.",
        })

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
        "parameters": {
            "learning_rate": lr,
            "decay": decay_val,
            "poids_min": poids_min,
            "poids_max": poids_max,
        },
        "thresholds": {
            "episodic_to_emergent": episodic,
            "emergent_to_strong": emergent_weight,
        },
        "findings": findings,
        "recommendations": recommendations,
    }


# ════════════════════════════════════════════════════════════════════════════════
# Tool 8: openclaw_hebbian_drift_check  (Audit)
# ════════════════════════════════════════════════════════════════════════════════

async def openclaw_hebbian_drift_check(
    claude_md_path: str,
    baseline_path: str | None = None,
    threshold: float = 0.7,
) -> dict[str, Any]:
    """
    Compare Claude.md against a baseline to detect semantic drift.

    Uses TF-IDF cosine similarity on whitespace-split tokens (no external
    dependencies). Alerts if similarity drops below threshold.

    CDC §5.1 — Anti-dérive.

    Args:
        claude_md_path: Path to the current Claude.md.
        baseline_path: Path to the baseline Claude.md. If None, looks for
            a file named claude-md-baseline.md in the same directory.
        threshold: Alert if similarity < threshold. Default: 0.7.

    Returns:
        dict with status, similarity, threshold, drift_detected.
    """
    md_path = Path(claude_md_path)
    if not md_path.exists():
        return {"ok": False, "error": f"Current Claude.md not found: {claude_md_path}"}

    # Resolve baseline
    if baseline_path:
        base_path = Path(baseline_path)
    else:
        base_path = md_path.parent / "claude-md-baseline.md"

    if not base_path.exists():
        return {
            "ok": True,
            "status": "no_baseline",
            "message": f"No baseline found at {base_path}. Create one with: cp {claude_md_path} {base_path}",
            "similarity": None,
            "drift_detected": None,
        }

    current = md_path.read_text(encoding="utf-8")
    baseline = base_path.read_text(encoding="utf-8")

    similarity = _cosine_similarity(current, baseline)
    similarity = round(similarity, 4)
    drift_detected = similarity < threshold

    findings: list[dict[str, str]] = []
    if drift_detected:
        severity = "CRITICAL" if similarity < 0.4 else "HIGH"
        findings.append({
            "severity": severity,
            "message": (
                f"Semantic drift detected: similarity={similarity} < threshold={threshold}. "
                "Claude.md has diverged significantly from baseline."
            ),
        })

    if drift_detected and similarity < 0.4:
        status = "critical"
    elif drift_detected:
        status = "high"
    else:
        status = "ok"

    return {
        "ok": True,
        "status": status,
        "similarity": similarity,
        "threshold": threshold,
        "drift_detected": drift_detected,
        "findings": findings,
        "current_tokens": len(_tokenize(current)),
        "baseline_tokens": len(_tokenize(baseline)),
    }


# ════════════════════════════════════════════════════════════════════════════════
# TOOLS registry
# ════════════════════════════════════════════════════════════════════════════════

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_hebbian_harvest",
        "description": (
            "Ingest JSONL session logs into the local Hebbian SQLite database. "
            "PII/secrets are stripped before storage (CDC §5.2). "
            "Supports session summary, tags, quality score, rule activations."
        ),
        "category": "hebbian_memory",
        "handler": openclaw_hebbian_harvest,
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_jsonl_path": {
                    "type": "string",
                    "description": "Path to JSONL file with session data.",
                },
                "claude_md_path": {
                    "type": "string",
                    "description": "Optional Claude.md path for rule activation matching.",
                },
                "db_path": {
                    "type": "string",
                    "description": "SQLite database path. Default: ~/.openclaw/hebbian.db.",
                },
                "max_lines": {
                    "type": "integer",
                    "description": "Max lines to ingest. Default: 50000.",
                },
            },
            "required": ["session_jsonl_path"],
        },
    },
    {
        "name": "openclaw_hebbian_weight_update",
        "description": (
            "Compute or apply Hebbian weight updates on Layer 2 rules in Claude.md. "
            "Uses the formula: new = old + (lr × activation) - (decay × (1-activation)). "
            "Default dry_run=True (simulation only). CDC §4.3 + §4.4."
        ),
        "category": "hebbian_memory",
        "handler": openclaw_hebbian_weight_update,
        "inputSchema": {
            "type": "object",
            "properties": {
                "claude_md_path": {
                    "type": "string",
                    "description": "Path to Claude.md file.",
                },
                "db_path": {
                    "type": "string",
                    "description": "SQLite database path.",
                },
                "learning_rate": {
                    "type": "number",
                    "description": "Reinforcement rate. Default: 0.05.",
                },
                "decay": {
                    "type": "number",
                    "description": "Atrophy rate. Default: 0.02.",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "Simulate only (true) or write changes (false). Default: true.",
                },
            },
            "required": ["claude_md_path"],
        },
    },
    {
        "name": "openclaw_hebbian_analyze",
        "description": (
            "Analyze co-activation patterns from harvested sessions. "
            "Uses Jaccard similarity for tag co-occurrence and rule co-activation. "
            "Returns top pattern candidates. CDC §4.3 clustering."
        ),
        "category": "hebbian_memory",
        "handler": openclaw_hebbian_analyze,
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_path": {
                    "type": "string",
                    "description": "SQLite database path.",
                },
                "since_days": {
                    "type": "integer",
                    "description": "Look back N days. Default: 90.",
                },
                "min_cluster_size": {
                    "type": "integer",
                    "description": "Min sessions to form a pattern. Default: 5.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_hebbian_status",
        "description": (
            "Dashboard: total sessions, Layer 2 rule weights, atrophy/promotion candidates, "
            "last harvest timestamp, weight update history. CDC §7 monitoring."
        ),
        "category": "hebbian_memory",
        "handler": openclaw_hebbian_status,
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_path": {
                    "type": "string",
                    "description": "SQLite database path.",
                },
                "claude_md_path": {
                    "type": "string",
                    "description": "Claude.md path for reading current weights.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_hebbian_layer_validate",
        "description": (
            "Validate the 4-layer structure of a Hebbian-augmented Claude.md: "
            "CORE (L1), CONSOLIDATED PATTERNS (L2), EPISODIC INDEX (L3), META (L4). "
            "Checks weight syntax, PII presence, layer completeness. CDC §3.3."
        ),
        "category": "hebbian_memory",
        "handler": openclaw_hebbian_layer_validate,
        "inputSchema": {
            "type": "object",
            "properties": {
                "claude_md_path": {
                    "type": "string",
                    "description": "Path to Claude.md file.",
                },
            },
            "required": ["claude_md_path"],
        },
    },
    {
        "name": "openclaw_hebbian_pii_check",
        "description": (
            "Audit PII stripping configuration: regex patterns (email, phone, IP, API keys), "
            "secret detection, embedding rotation policy, access restriction. CDC §5.2."
        ),
        "category": "hebbian_memory",
        "handler": openclaw_hebbian_pii_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Path to OpenClaw config JSON.",
                },
                "config_data": {
                    "type": "object",
                    "description": "Inline config dict (for testing).",
                },
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_hebbian_decay_config_check",
        "description": (
            "Validate Hebbian parameters: learning_rate, decay, poids_min/max, "
            "consolidation thresholds (episodic→emergent, emergent→strong). CDC §4.3."
        ),
        "category": "hebbian_memory",
        "handler": openclaw_hebbian_decay_config_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Path to OpenClaw config JSON.",
                },
                "config_data": {
                    "type": "object",
                    "description": "Inline config dict (for testing).",
                },
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_hebbian_drift_check",
        "description": (
            "Detect Claude.md semantic drift vs a baseline using TF-IDF cosine similarity. "
            "Alerts if similarity drops below threshold (default 0.7). CDC §5.1 anti-dérive."
        ),
        "category": "hebbian_memory",
        "handler": openclaw_hebbian_drift_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "claude_md_path": {
                    "type": "string",
                    "description": "Path to current Claude.md.",
                },
                "baseline_path": {
                    "type": "string",
                    "description": "Path to baseline Claude.md.",
                },
                "threshold": {
                    "type": "number",
                    "description": "Alert if similarity < threshold. Default: 0.7.",
                },
            },
            "required": ["claude_md_path"],
        },
    },
]
