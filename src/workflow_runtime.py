from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable


@dataclass(frozen=True)
class RuntimeSettings:
    max_attempts: int
    idempotency_enabled: bool
    store_path: Path


class WorkflowRuntime:
    def __init__(self, settings: RuntimeSettings) -> None:
        self._settings = settings
        self._settings.store_path.parent.mkdir(parents=True, exist_ok=True)
        self._idempotency_cache: dict[str, dict[str, Any]] = {}

    async def execute(
        self,
        workflow_name: str,
        run_callable: Callable[[], Awaitable[dict[str, Any]]],
        idempotency_key: str | None = None,
        max_attempts: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        attempts_limit = max(1, max_attempts or self._settings.max_attempts)
        run_id = str(uuid.uuid4())

        if (
            self._settings.idempotency_enabled
            and idempotency_key
            and idempotency_key in self._idempotency_cache
        ):
            cached = dict(self._idempotency_cache[idempotency_key])
            cached["idempotent_replay"] = True
            return cached

        attempt_results: list[dict[str, Any]] = []
        final_result: dict[str, Any] = {"ok": False, "error": "not_executed"}
        start = time.monotonic()

        for attempt in range(1, attempts_limit + 1):
            attempt_start = time.monotonic()
            try:
                result = await run_callable()
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}

            duration_ms = (time.monotonic() - attempt_start) * 1000
            attempt_entry = {
                "attempt": attempt,
                "ok": bool(result.get("ok")),
                "duration_ms": round(duration_ms, 2),
                "error": result.get("error"),
            }
            attempt_results.append(attempt_entry)

            final_result = result
            if result.get("ok"):
                break

        total_duration_ms = (time.monotonic() - start) * 1000

        envelope = {
            "run_id": run_id,
            "workflow": workflow_name,
            "attempts": attempt_results,
            "attempts_count": len(attempt_results),
            "max_attempts": attempts_limit,
            "ok": bool(final_result.get("ok")),
            "duration_ms": round(total_duration_ms, 2),
            "idempotency_key": idempotency_key,
            "metadata": metadata or {},
            "result": final_result,
        }

        self._append_history(envelope)

        if self._settings.idempotency_enabled and idempotency_key:
            self._idempotency_cache[idempotency_key] = envelope

        return envelope

    def list_recent_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self._settings.store_path.exists():
            return []
        with self._settings.store_path.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()
        records = [json.loads(line) for line in lines if line.strip()]
        return records[-max(1, limit) :]

    def diagnostics(self) -> dict[str, Any]:
        return {
            "max_attempts": self._settings.max_attempts,
            "idempotency_enabled": self._settings.idempotency_enabled,
            "store_path": str(self._settings.store_path),
            "cache_size": len(self._idempotency_cache),
            "store_exists": self._settings.store_path.exists(),
        }

    def _append_history(self, envelope: dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **envelope,
        }
        with self._settings.store_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
