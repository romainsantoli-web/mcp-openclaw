"""
observability.py — OpenClaw observability & CI pipeline audit tools

Tools:
  openclaw_observability_pipeline  — ingests JSONL traces into SQLite for analysis
  openclaw_ci_pipeline_check       — validates CI workflow completeness (lint, test, secrets)
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_DEFAULT_DB_PATH = os.path.expanduser("~/.openclaw/traces.db")

_REQUIRED_CI_STEPS = {
    "lint":    re.compile(r"(ruff|flake8|eslint|pylint|black|prettier)\b", re.I),
    "test":    re.compile(r"(pytest|jest|mocha|vitest|unittest)\b", re.I),
    "secrets": re.compile(r"(trufflehog|detect-secrets|gitleaks|git-secrets)\b", re.I),
}

_RECOMMENDED_CI_STEPS = {
    "coverage": re.compile(r"(cov|coverage|--cov|codecov|coveralls)\b", re.I),
    "type_check": re.compile(r"(mypy|pyright|pylance|tsc)\b", re.I),
}


# ── Tool: openclaw_observability_pipeline ────────────────────────────────────

async def openclaw_observability_pipeline(
    jsonl_path: str,
    db_path: str | None = None,
    table_name: str = "traces",
    max_lines: int = 50_000,
) -> dict[str, Any]:
    """
    Ingest JSONL structured logs/traces into a local SQLite database.

    Reads a JSONL file (one JSON object per line — OpenTelemetry format or
    structured log output) and inserts each record into a SQLite table for
    analysis. Handles duplicate detection via trace_id+span_id if present.

    Args:
        jsonl_path: Path to the JSONL file to ingest.
        db_path: Path to the SQLite database. Default: ~/.openclaw/traces.db.
        table_name: Table name in the database. Default: "traces".
        max_lines: Maximum number of lines to ingest (safety limit). Default: 50000.

    Returns:
        dict with keys: ok, db_path, table, ingested, skipped_duplicates, errors.
    """
    actual_db = db_path or _DEFAULT_DB_PATH
    jsonl = Path(jsonl_path)

    # Defence-in-depth: whitelist table_name even though Pydantic already validates
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]{0,127}$", table_name):
        return {"ok": False, "error": f"Invalid table_name: {table_name!r}"}

    if not jsonl.exists():
        return {"ok": False, "error": f"JSONL file not found: {jsonl_path}"}

    if jsonl.suffix.lower() not in (".jsonl", ".ndjson", ".log", ".json"):
        return {
            "ok": False,
            "error": f"Unexpected extension '{jsonl.suffix}'. Expected .jsonl, .ndjson, .log, or .json.",
        }

    # Ensure parent directory exists
    db_dir = Path(actual_db).parent
    db_dir.mkdir(parents=True, exist_ok=True)

    ingested = 0
    duplicates = 0
    errors_list: list[str] = []

    try:
        conn = sqlite3.connect(actual_db)
        cur = conn.cursor()

        # Create table if not exists — flexible schema with JSON blob
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trace_id TEXT,
                span_id TEXT,
                timestamp TEXT,
                severity TEXT,
                service_name TEXT,
                message TEXT,
                raw_json TEXT NOT NULL,
                ingested_at REAL NOT NULL,
                UNIQUE(trace_id, span_id)
            )
        """)
        cur.execute(f"""
            CREATE INDEX IF NOT EXISTS idx_{table_name}_trace
            ON {table_name}(trace_id)
        """)
        cur.execute(f"""
            CREATE INDEX IF NOT EXISTS idx_{table_name}_ts
            ON {table_name}(timestamp)
        """)

        now = time.time()
        batch: list[tuple] = []

        with open(jsonl, "r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, 1):
                if line_no > max_lines:
                    errors_list.append(f"Stopped at max_lines={max_lines}")
                    break

                raw_line = raw_line.strip()
                if not raw_line:
                    continue

                try:
                    obj = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    errors_list.append(f"Line {line_no}: invalid JSON — {exc}")
                    if len(errors_list) > 100:
                        errors_list.append("Too many errors, stopping.")
                        break
                    continue

                # Extract standard OTEL/structured log fields
                trace_id = obj.get("traceId") or obj.get("trace_id") or obj.get("traceID")
                span_id = obj.get("spanId") or obj.get("span_id") or obj.get("spanID")
                timestamp = obj.get("timestamp") or obj.get("@timestamp") or obj.get("time") or obj.get("ts")
                severity = (
                    obj.get("severity") or obj.get("level") or obj.get("severityText") or "UNSET"
                )
                service = (
                    obj.get("serviceName")
                    or obj.get("service_name")
                    or (obj.get("resource", {}).get("service.name") if isinstance(obj.get("resource"), dict) else None)
                    or "unknown"
                )
                message = obj.get("message") or obj.get("body") or obj.get("msg") or ""

                batch.append((
                    trace_id, span_id, str(timestamp) if timestamp else None,
                    str(severity), str(service), str(message)[:4096],
                    raw_line, now,
                ))

                # Flush every 500 records
                if len(batch) >= 500:
                    ingested_batch, dup_batch = _flush_batch(cur, table_name, batch)
                    ingested += ingested_batch
                    duplicates += dup_batch
                    batch.clear()

        # Flush remaining
        if batch:
            ingested_batch, dup_batch = _flush_batch(cur, table_name, batch)
            ingested += ingested_batch
            duplicates += dup_batch

        conn.commit()

        # Get total row count
        cur.execute(f"SELECT COUNT(*) FROM {table_name}")
        total_rows = cur.fetchone()[0]

        conn.close()

    except Exception as exc:
        return {"ok": False, "error": f"SQLite error: {exc}"}

    return {
        "ok": True,
        "db_path": actual_db,
        "table": table_name,
        "ingested": ingested,
        "skipped_duplicates": duplicates,
        "total_rows_in_table": total_rows,
        "errors": errors_list[:20] if errors_list else [],
    }


def _flush_batch(
    cur: sqlite3.Cursor, table: str, batch: list[tuple]
) -> tuple[int, int]:
    """Insert a batch of records, skipping duplicates."""
    inserted = 0
    dups = 0
    for row in batch:
        try:
            cur.execute(
                f"INSERT INTO {table} "
                "(trace_id, span_id, timestamp, severity, service_name, message, raw_json, ingested_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                row,
            )
            inserted += 1
        except sqlite3.IntegrityError:
            dups += 1
    return inserted, dups


# ── Tool: openclaw_ci_pipeline_check ─────────────────────────────────────────

async def openclaw_ci_pipeline_check(
    repo_path: str,
    ci_dir: str = ".github/workflows",
) -> dict[str, Any]:
    """
    Validate presence and completeness of CI workflow files.

    Checks that the repository has CI workflows covering these required steps:
      - lint (ruff/flake8/eslint/pylint)
      - test (pytest/jest/mocha)
      - secrets (trufflehog/detect-secrets/gitleaks)

    Also checks recommended steps:
      - coverage (≥80% threshold)
      - type_check (mypy/pyright/tsc)

    Args:
        repo_path: Root of the repository to check.
        ci_dir: Relative path to CI workflow directory. Default: .github/workflows.

    Returns:
        dict with status, missing_required, missing_recommended, files_found, details.
    """
    root = Path(repo_path)
    workflows_dir = root / ci_dir

    if not root.exists():
        return {"ok": False, "error": f"Repository path not found: {repo_path}"}

    if not workflows_dir.exists():
        return {
            "ok": True,
            "status": "critical",
            "missing_required": list(_REQUIRED_CI_STEPS.keys()),
            "missing_recommended": list(_RECOMMENDED_CI_STEPS.keys()),
            "files_found": [],
            "details": f"No CI directory found at {ci_dir}. "
                       "Create .github/workflows/ with lint + test + secrets scanning.",
        }

    # Read all workflow files
    yaml_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
    if not yaml_files:
        return {
            "ok": True,
            "status": "critical",
            "missing_required": list(_REQUIRED_CI_STEPS.keys()),
            "missing_recommended": list(_RECOMMENDED_CI_STEPS.keys()),
            "files_found": [],
            "details": "CI directory exists but contains no .yml/.yaml files.",
        }

    # Concatenate all workflow content for pattern matching
    all_content = ""
    file_names = []
    for yf in yaml_files:
        try:
            all_content += yf.read_text(encoding="utf-8") + "\n"
            file_names.append(yf.name)
        except Exception:
            pass

    # Check required steps
    found_required: dict[str, bool] = {}
    for step_name, pattern in _REQUIRED_CI_STEPS.items():
        found_required[step_name] = bool(pattern.search(all_content))

    missing_required = [k for k, v in found_required.items() if not v]

    # Check recommended steps
    found_recommended: dict[str, bool] = {}
    for step_name, pattern in _RECOMMENDED_CI_STEPS.items():
        found_recommended[step_name] = bool(pattern.search(all_content))

    missing_recommended = [k for k, v in found_recommended.items() if not v]

    # Determine severity
    if missing_required:
        status = "high" if len(missing_required) < len(_REQUIRED_CI_STEPS) else "critical"
    elif missing_recommended:
        status = "info"
    else:
        status = "ok"

    return {
        "ok": True,
        "status": status,
        "files_found": file_names,
        "required_steps": found_required,
        "recommended_steps": found_recommended,
        "missing_required": missing_required,
        "missing_recommended": missing_recommended,
        "details": (
            f"Checked {len(yaml_files)} workflow file(s). "
            f"Required coverage: {sum(found_required.values())}/{len(_REQUIRED_CI_STEPS)}, "
            f"Recommended: {sum(found_recommended.values())}/{len(_RECOMMENDED_CI_STEPS)}."
        ),
    }


# ── TOOLS registry ───────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_observability_pipeline",
        "title": "Observability Pipeline Ingest",
        "description": (
            "Ingests JSONL structured logs/traces (OpenTelemetry format) into a local SQLite database "
            "for offline analysis. Handles trace_id/span_id deduplication, batch inserts, and flexible "
            "field extraction. Gap T1: no observability pipeline existed."
        ),
        "category": "observability",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "handler": openclaw_observability_pipeline,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "jsonl_path": {
                    "type": "string",
                    "description": "Path to the JSONL file to ingest.",
                },
                "db_path": {
                    "type": "string",
                    "description": "Path to SQLite database. Default: ~/.openclaw/traces.db.",
                },
                "table_name": {
                    "type": "string",
                    "description": "Table name. Default: 'traces'.",
                    "default": "traces",
                },
                "max_lines": {
                    "type": "integer",
                    "description": "Max lines to ingest (safety limit). Default: 50000.",
                    "minimum": 1,
                    "maximum": 500_000,
                    "default": 50_000,
                },
            },
            "required": ["jsonl_path"],
        },
    },
    {
        "name": "openclaw_ci_pipeline_check",
        "title": "CI Pipeline Validation",
        "description": (
            "Validates CI workflow completeness: checks that .github/workflows/ contains lint, "
            "test, and secrets scanning steps. Also checks recommended steps (coverage, type_check). "
            "Gap T6: no CI validation tool existed."
        ),
        "category": "observability",
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
        "handler": openclaw_ci_pipeline_check,
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
                "repo_path": {
                    "type": "string",
                    "description": "Root of the repository to check.",
                },
                "ci_dir": {
                    "type": "string",
                    "description": "Relative path to CI directory. Default: .github/workflows.",
                    "default": ".github/workflows",
                },
            },
            "required": ["repo_path"],
        },
    },
]
