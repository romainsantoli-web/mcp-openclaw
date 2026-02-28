from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-]+")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in _TOKEN_RE.findall(text)}


def _flatten(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts: list[str] = []
        for key, item in value.items():
            parts.append(f"{key}: {_flatten(item)}")
        return "\n".join(parts)
    if isinstance(value, list):
        return "\n".join(_flatten(item) for item in value)
    return str(value)


@dataclass(frozen=True)
class MemoryOsAiSettings:
    repo_path: Path
    events_path: Path
    context_limit: int = 16


class MemoryOsAiStore:
    def __init__(self, settings: MemoryOsAiSettings) -> None:
        self._settings = settings
        self._events_path = settings.events_path
        self._events_path.parent.mkdir(parents=True, exist_ok=True)
        self._pdfs_dir = settings.repo_path / "pdfs" / "mcp_openclaw_events"
        self._pdfs_dir.mkdir(parents=True, exist_ok=True)

    def retrieve(self, key: str) -> list[dict[str, Any]]:
        rows = self._read_events()
        matched = [row for row in rows if row.get("key") == key]
        return matched[-self._settings.context_limit :]

    def retrieve_context(self, query: str, limit: int | None = None) -> list[dict[str, Any]]:
        rows = self._read_events()
        if not rows:
            return []

        query_tokens = _tokens(query)
        scored: list[tuple[int, int, dict[str, Any]]] = []
        for index, row in enumerate(rows):
            haystack = " ".join(
                [
                    str(row.get("key", "")),
                    str(row.get("kind", "")),
                    str(row.get("tool", "")),
                    str(row.get("summary", "")),
                    _flatten(row.get("value", {})),
                ]
            )
            hay_tokens = _tokens(haystack)
            overlap = len(query_tokens.intersection(hay_tokens)) if query_tokens else 0
            recency_bonus = index // 50
            score = overlap * 10 + recency_bonus
            if score > 0 or not query_tokens:
                scored.append((score, index, row))

        if not scored:
            return rows[-(limit or self._settings.context_limit) :]

        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        selected = [item[2] for item in scored[: (limit or self._settings.context_limit)]]
        return selected

    def write_back(self, key: str, value: dict[str, Any]) -> dict[str, Any]:
        timestamp = _utc_now_iso()
        event = {
            "key": key,
            "timestamp": timestamp,
            "value": value,
            "summary": _flatten(value)[:3000],
            "kind": value.get("kind") if isinstance(value, dict) else "generic",
            "tool": value.get("tool") if isinstance(value, dict) else None,
        }

        with self._events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

        mirror_name = f"{timestamp.replace(':', '-').replace('+', '_')}_{key.replace('/', '_')}.txt"
        mirror_payload = (
            f"timestamp: {timestamp}\n"
            f"key: {key}\n"
            f"summary:\n{event['summary']}\n"
        )
        (self._pdfs_dir / mirror_name).write_text(mirror_payload, encoding="utf-8")

        return {"status": "ok", "event": {"key": key, "timestamp": timestamp}}

    def diagnostics(self) -> dict[str, Any]:
        rows = self._read_events()
        return {
            "backend": "memory_os_ai",
            "repo_path": str(self._settings.repo_path),
            "events_path": str(self._events_path),
            "events_count": len(rows),
            "context_limit": self._settings.context_limit,
        }

    def _read_events(self) -> list[dict[str, Any]]:
        if not self._events_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        with self._events_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows
