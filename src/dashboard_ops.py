from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def build_dashboard_snapshot(
    *,
    enterprise: dict[str, Any],
    observability: dict[str, Any],
    recent_runs: list[dict[str, Any]],
    cost_guard: dict[str, Any],
    plugins: dict[str, Any],
) -> dict[str, Any]:
    ok_runs = sum(1 for row in recent_runs if bool(row.get("ok")))
    ko_runs = len(recent_runs) - ok_runs

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": {
            "secure_production_mode": enterprise.get("secure_production_mode"),
            "audit_enabled": (enterprise.get("audit") or {}).get("enabled"),
            "memory_backend": (enterprise.get("memory") or {}).get("backend"),
            "workflow_runs_ok": ok_runs,
            "workflow_runs_ko": ko_runs,
        },
        "enterprise": enterprise,
        "observability": observability,
        "recent_runs": recent_runs,
        "cost_guard": cost_guard,
        "plugins": plugins,
    }
