from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class MemoryEvent:
    key: str
    value: dict[str, Any]
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class MemoryAdapter:
    def __init__(self) -> None:
        self._store: dict[str, list[MemoryEvent]] = {}

    def retrieve(self, key: str) -> list[dict[str, Any]]:
        events = self._store.get(key, [])
        return [
            {"key": event.key, "value": event.value, "timestamp": event.timestamp}
            for event in events
        ]

    def write_back(self, key: str, value: dict[str, Any]) -> dict[str, Any]:
        event = MemoryEvent(key=key, value=value)
        self._store.setdefault(key, []).append(event)
        return {"status": "ok", "event": {"key": key, "timestamp": event.timestamp}}
