from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CostGuardSettings:
    enabled: bool
    policy_mode: str
    per_run_budget: float
    daily_budget: float
    ledger_path: Path


class CostGuard:
    def __init__(self, settings: CostGuardSettings) -> None:
        self._settings = settings
        self._settings.ledger_path.parent.mkdir(parents=True, exist_ok=True)

    def estimate(self, objective: str, departments: list[str], push_to_openclaw: bool) -> dict[str, Any]:
        objective_tokens = max(1, len(objective) // 4)
        base = objective_tokens * 0.00008
        departments_cost = len(departments) * 0.045
        dispatch_cost = 0.12 if push_to_openclaw else 0.0
        estimated = round(base + departments_cost + dispatch_cost, 4)
        return {
            "estimated_cost": estimated,
            "objective_tokens_est": objective_tokens,
            "departments_count": len(departments),
            "push_to_openclaw": push_to_openclaw,
        }

    def check_and_record(
        self,
        workflow: str,
        objective: str,
        departments: list[str],
        push_to_openclaw: bool,
    ) -> dict[str, Any]:
        if not self._settings.enabled:
            return {
                "ok": True,
                "status": "disabled",
                "estimate": self.estimate(objective, departments, push_to_openclaw),
            }

        estimate = self.estimate(objective, departments, push_to_openclaw)
        estimated_cost = float(estimate["estimated_cost"])

        today_spend = self._today_spend()
        projected_day_total = today_spend + estimated_cost

        over_run = estimated_cost > self._settings.per_run_budget
        over_day = projected_day_total > self._settings.daily_budget

        allowed = not (over_run or over_day)
        if not allowed and self._settings.policy_mode == "warn":
            allowed = True

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "workflow": workflow,
            "estimated_cost": estimated_cost,
            "today_spend_before": round(today_spend, 4),
            "projected_day_total": round(projected_day_total, 4),
            "allowed": allowed,
            "policy_mode": self._settings.policy_mode,
            "over_run_budget": over_run,
            "over_daily_budget": over_day,
        }
        self._append_record(record)

        return {
            "ok": allowed,
            "status": "allowed" if allowed else "blocked",
            "estimate": estimate,
            "over_run_budget": over_run,
            "over_daily_budget": over_day,
            "today_spend_before": round(today_spend, 4),
            "projected_day_total": round(projected_day_total, 4),
            "policy_mode": self._settings.policy_mode,
            "reason": None if allowed else "cost_budget_exceeded",
        }

    def diagnostics(self) -> dict[str, Any]:
        return {
            "enabled": self._settings.enabled,
            "policy_mode": self._settings.policy_mode,
            "per_run_budget": self._settings.per_run_budget,
            "daily_budget": self._settings.daily_budget,
            "today_spend": round(self._today_spend(), 4),
            "ledger_path": str(self._settings.ledger_path),
            "ledger_exists": self._settings.ledger_path.exists(),
        }

    def recent_records(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self._settings.ledger_path.exists():
            return []
        with self._settings.ledger_path.open("r", encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle if line.strip()]
        return rows[-max(1, limit) :]

    def _today_spend(self) -> float:
        if not self._settings.ledger_path.exists():
            return 0.0
        today = datetime.now(timezone.utc).date().isoformat()
        total = 0.0
        with self._settings.ledger_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                timestamp = str(row.get("timestamp", ""))
                if not timestamp.startswith(today):
                    continue
                total += float(row.get("estimated_cost", 0.0))
        return total

    def _append_record(self, record: dict[str, Any]) -> None:
        with self._settings.ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
