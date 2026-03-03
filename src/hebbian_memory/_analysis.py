"""
Analysis tools: analyze + status.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

from ._helpers import (
    _DEFAULT_DB_PATH,
    _THRESHOLD_ATROPHY,
    _THRESHOLD_STRONG_TO_CORE,
    _detect_layers,
    _extract_layer2_rules,
)

logger = logging.getLogger(__name__)


async def firm_hebbian_analyze(
    db_path: str | None = None,
    since_days: int = 90,
    min_cluster_size: int = 5,
) -> dict[str, Any]:
    """Analyze co-activation patterns from harvested sessions."""
    actual_db = db_path or _DEFAULT_DB_PATH

    if not Path(actual_db).exists():
        return {
            "ok": True, "status": "no_data",
            "message": "No Hebbian database found. Run firm_hebbian_harvest first.",
            "patterns": [], "session_count": 0,
        }

    try:
        conn = sqlite3.connect(actual_db)
        cur = conn.execute(
            """SELECT tags, rules_activated, quality_score
               FROM hebbian_sessions
               WHERE archived = 0 AND created_at >= datetime('now', ?)
               ORDER BY created_at DESC""",
            (f"-{since_days} days",),
        )
        rows = cur.fetchall()
        conn.close()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    if not rows:
        return {
            "ok": True, "status": "no_recent_data",
            "message": f"No sessions found in the last {since_days} days.",
            "patterns": [], "session_count": 0,
        }

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
            for t2 in sorted(tags)[i + 1:]:
                tag_pairs[f"{t1}+{t2}"] += 1

        for r in rules:
            rule_counter[r] += 1
        for i, r1 in enumerate(sorted(rules)):
            for r2 in sorted(rules)[i + 1:]:
                rule_pairs[f"{r1}+{r2}"] += 1

    patterns: list[dict[str, Any]] = []
    for pair, count in tag_pairs.most_common(20):
        if count >= min_cluster_size:
            t1, t2 = pair.split("+", 1)
            union = tag_counter[t1] + tag_counter[t2] - count
            jaccard = count / union if union > 0 else 0.0
            patterns.append({
                "type": "tag_co_occurrence", "tags": [t1, t2],
                "frequency": count, "jaccard_similarity": round(jaccard, 3),
                "label": f"Sessions involving '{t1}' + '{t2}'",
            })

    co_activations: list[dict[str, Any]] = []
    for pair, count in rule_pairs.most_common(20):
        if count >= min_cluster_size:
            r1, r2 = pair.split("+", 1)
            union = rule_counter[r1] + rule_counter[r2] - count
            jaccard = count / union if union > 0 else 0.0
            co_activations.append({
                "type": "rule_co_activation", "rules": [r1, r2],
                "frequency": count, "jaccard_similarity": round(jaccard, 3),
            })

    return {
        "ok": True, "session_count": len(rows), "since_days": since_days,
        "patterns": patterns, "co_activations": co_activations,
        "top_tags": tag_counter.most_common(10),
        "top_rules": rule_counter.most_common(10),
    }


async def firm_hebbian_status(
    db_path: str | None = None,
    claude_md_path: str | None = None,
) -> dict[str, Any]:
    """Dashboard: session count, rule weights, atrophy/promotion candidates."""
    actual_db = db_path or _DEFAULT_DB_PATH
    dashboard: dict[str, Any] = {
        "ok": True, "db_exists": False, "total_sessions": 0,
        "last_harvest": None, "rules": [], "promotions": [],
        "atrophy": [], "weight_updates_count": 0,
    }

    if Path(actual_db).exists():
        dashboard["db_exists"] = True
        try:
            conn = sqlite3.connect(actual_db)
            row = conn.execute("SELECT COUNT(*) FROM hebbian_sessions WHERE archived = 0").fetchone()
            dashboard["total_sessions"] = row[0] if row else 0

            row = conn.execute("SELECT MAX(created_at) FROM hebbian_sessions").fetchone()
            dashboard["last_harvest"] = row[0] if row and row[0] else None

            row = conn.execute("SELECT COUNT(*) FROM hebbian_weight_history").fetchone()
            dashboard["weight_updates_count"] = row[0] if row else 0

            conn.close()
        except Exception as exc:
            dashboard["db_error"] = str(exc)

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
