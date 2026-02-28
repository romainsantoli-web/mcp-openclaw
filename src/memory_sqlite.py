from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class SQLiteMemoryStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self._db_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_key ON memory_events(key)"
            )

    def retrieve(self, key: str) -> list[dict[str, Any]]:
        with sqlite3.connect(self._db_path) as connection:
            rows = connection.execute(
                "SELECT value_json, timestamp FROM memory_events WHERE key = ? ORDER BY id ASC",
                (key,),
            ).fetchall()
        return [
            {
                "key": key,
                "value": json.loads(row[0]),
                "timestamp": row[1],
            }
            for row in rows
        ]

    def write_back(self, key: str, value: dict[str, Any]) -> dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()
        value_json = json.dumps(value, ensure_ascii=False)
        with sqlite3.connect(self._db_path) as connection:
            connection.execute(
                "INSERT INTO memory_events (key, value_json, timestamp) VALUES (?, ?, ?)",
                (key, value_json, timestamp),
            )
            connection.commit()
        return {"status": "ok", "event": {"key": key, "timestamp": timestamp}}

    def diagnostics(self) -> dict[str, Any]:
        with sqlite3.connect(self._db_path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM memory_events").fetchone()[0]
        return {
            "backend": "sqlite",
            "db_path": str(self._db_path),
            "events_count": int(count),
        }
