"""
Runtime tools: harvest + weight_update.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

from ._helpers import (
    _DEFAULT_DB_PATH,
    _DEFAULT_DECAY,
    _DEFAULT_LEARNING_RATE,
    _WEIGHT_MAX,
    _WEIGHT_MIN,
    _THRESHOLD_STRONG_TO_CORE,
    _THRESHOLD_ATROPHY,
    _extract_layer2_rules,
    _init_db,
    _strip_pii,
    _validate_hebbian_path,
)

logger = logging.getLogger(__name__)


# ── Pure computation (no I/O) ────────────────────────────────────────────────


def _compute_hebbian_weights(
    rules: list[dict[str, Any]],
    activated_rule_ids: set[str],
    learning_rate: float = _DEFAULT_LEARNING_RATE,
    decay: float = _DEFAULT_DECAY,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    changes: list[dict[str, Any]] = []
    promotions: list[str] = []
    atrophy_candidates: list[str] = []

    for rule in rules:
        old_weight = rule["weight"]
        rule_id = rule["rule_id"]
        activated = 1.0 if rule_id in activated_rule_ids else 0.0

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

        if new_weight >= _THRESHOLD_STRONG_TO_CORE:
            promotions.append(rule_id)
        elif new_weight < _THRESHOLD_ATROPHY:
            atrophy_candidates.append(rule_id)

    return changes, promotions, atrophy_candidates


def _apply_weight_changes(content: str, changes: list[dict[str, Any]]) -> str:
    updated = content
    for ch in changes:
        old_weight = ch["old_weight"]
        old_formatted = f"[{old_weight:.2f}] {ch['text']}"
        old_raw = f"[{old_weight}] {ch['text']}"
        new_line = f"[{ch['new_weight']:.2f}] {ch['text']}"

        if old_formatted in updated:
            updated = updated.replace(old_formatted, new_line, 1)
        elif old_raw in updated:
            updated = updated.replace(old_raw, new_line, 1)
    return updated


# ── Tool 1: harvest ──────────────────────────────────────────────────────────


async def firm_hebbian_harvest(
    session_jsonl_path: str,
    claude_md_path: str | None = None,
    db_path: str | None = None,
    max_lines: int = 50_000,
) -> dict[str, Any]:
    """Ingest JSONL session logs into the local Hebbian SQLite database."""
    try:
        _validate_hebbian_path(session_jsonl_path, "session_jsonl_path")
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    actual_db = db_path or _DEFAULT_DB_PATH
    jsonl = Path(session_jsonl_path)

    if not jsonl.exists():
        return {"ok": False, "error": f"JSONL file not found: {session_jsonl_path}"}

    if jsonl.suffix.lower() not in (".jsonl", ".ndjson", ".log", ".json"):
        return {"ok": False, "error": f"Unexpected extension '{jsonl.suffix}'. Expected .jsonl/.ndjson/.log/.json."}

    if claude_md_path:
        md_path = Path(claude_md_path)
        if md_path.exists():
            md_content = md_path.read_text(encoding="utf-8")
            _extract_layer2_rules(md_content)

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
                        (session_id, summary, json.dumps(tags), quality_score,
                         json.dumps(rules_activated), git_diff_hash),
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


# ── Tool 2: weight_update ───────────────────────────────────────────────────


async def firm_hebbian_weight_update(
    claude_md_path: str,
    db_path: str | None = None,
    learning_rate: float = _DEFAULT_LEARNING_RATE,
    decay: float = _DEFAULT_DECAY,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Compute or apply Hebbian weight updates on Layer 2 rules."""
    md_path = Path(claude_md_path)
    if not md_path.exists():
        return {"ok": False, "error": f"Claude.md not found: {claude_md_path}"}

    content = md_path.read_text(encoding="utf-8")
    rules = _extract_layer2_rules(content)

    if not rules:
        return {
            "ok": True, "status": "no_rules",
            "message": "No weighted Layer 2 rules found in Claude.md.",
            "changes": [],
        }

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

    changes, promotions, atrophy_candidates = _compute_hebbian_weights(
        rules, activated_rule_ids, learning_rate, decay
    )

    if dry_run:
        return {
            "ok": True, "dry_run": True,
            "changes": changes, "promotions_candidates": promotions,
            "atrophy_candidates": atrophy_candidates,
            "total_rules": len(rules), "rules_changed": len(changes),
            "human_action_required": bool(promotions or atrophy_candidates),
        }

    if changes:
        updated_content = _apply_weight_changes(content, changes)
        md_path.write_text(updated_content, encoding="utf-8")

        try:
            conn = _init_db(actual_db)
            for ch in changes:
                conn.execute(
                    """INSERT INTO hebbian_weight_history
                       (rule_id, old_weight, new_weight, reason) VALUES (?, ?, ?, ?)""",
                    (ch["rule_id"], ch["old_weight"], ch["new_weight"],
                     "activated" if ch["activated"] else "decay"),
                )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning("Could not record weight history: %s", exc)

    return {
        "ok": True, "dry_run": False,
        "changes": changes, "promotions_candidates": promotions,
        "atrophy_candidates": atrophy_candidates,
        "total_rules": len(rules), "rules_changed": len(changes),
        "human_action_required": bool(promotions or atrophy_candidates),
    }
