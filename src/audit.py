from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditSettings:
    enabled: bool
    file_path: Path


class AuditLogger:
    def __init__(self, settings: AuditSettings) -> None:
        self._settings = settings
        if self._settings.enabled:
            self._settings.file_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event_type: str, payload: dict[str, Any]) -> None:
        if not self._settings.enabled:
            return
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "payload": payload,
        }
        with self._settings.file_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def diagnostics(self) -> dict[str, Any]:
        return {
            "enabled": self._settings.enabled,
            "file_path": str(self._settings.file_path),
            "exists": self._settings.file_path.exists(),
        }
