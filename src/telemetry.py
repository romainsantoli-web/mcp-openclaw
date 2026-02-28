from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass
class LatencyStat:
    count: int = 0
    total_ms: float = 0.0
    max_ms: float = 0.0

    def add(self, value_ms: float) -> None:
        self.count += 1
        self.total_ms += value_ms
        self.max_ms = max(self.max_ms, value_ms)

    def as_dict(self) -> dict[str, Any]:
        avg_ms = self.total_ms / self.count if self.count else 0.0
        return {
            "count": self.count,
            "avg_ms": round(avg_ms, 2),
            "max_ms": round(self.max_ms, 2),
        }


class TelemetryCollector:
    def __init__(self, enabled: bool) -> None:
        self._enabled = enabled
        self._counters: dict[str, int] = defaultdict(int)
        self._latencies: dict[str, LatencyStat] = defaultdict(LatencyStat)

    def inc(self, name: str, value: int = 1) -> None:
        if not self._enabled:
            return
        self._counters[name] += value

    def observe_ms(self, name: str, duration_ms: float) -> None:
        if not self._enabled:
            return
        self._latencies[name].add(duration_ms)

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self._enabled,
            "counters": dict(sorted(self._counters.items())),
            "latencies": {
                key: value.as_dict()
                for key, value in sorted(self._latencies.items())
            },
        }
