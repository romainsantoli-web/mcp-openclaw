from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class PluginResult:
    ok: bool
    context: dict[str, Any]
    events: list[dict[str, Any]]
    error: str | None = None


class PluginManager:
    def __init__(
        self,
        enabled_plugins: tuple[str, ...],
        objective_min_length: int,
        policy_mode: str,
    ) -> None:
        self._enabled_plugins = enabled_plugins
        self._objective_min_length = objective_min_length
        self._policy_mode = policy_mode

    def pre_workflow(self, context: dict[str, Any]) -> PluginResult:
        current = dict(context)
        events: list[dict[str, Any]] = []

        for name in self._enabled_plugins:
            if name == "enforce_objective_min_length":
                ok, event, error = self._enforce_objective_min_length(current)
            elif name == "normalize_departments":
                ok, event, error = self._normalize_departments(current)
            else:
                ok, event, error = True, {"plugin": name, "status": "skipped_unknown"}, None

            events.append(event)
            if not ok and self._policy_mode == "enforce":
                return PluginResult(
                    ok=False,
                    context=current,
                    events=events,
                    error=error or "plugin_precheck_failed",
                )

        return PluginResult(ok=True, context=current, events=events)

    def post_workflow(self, context: dict[str, Any], result: dict[str, Any]) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for name in self._enabled_plugins:
            events.append(
                {
                    "plugin": name,
                    "status": "post_processed",
                    "ok": bool(result.get("ok")),
                    "objective": context.get("objective"),
                }
            )
        return events

    def diagnostics(self) -> dict[str, Any]:
        return {
            "enabled_plugins": list(self._enabled_plugins),
            "policy_mode": self._policy_mode,
            "objective_min_length": self._objective_min_length,
        }

    def _enforce_objective_min_length(self, context: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
        objective = str(context.get("objective", ""))
        ok = len(objective.strip()) >= self._objective_min_length
        event = {
            "plugin": "enforce_objective_min_length",
            "status": "ok" if ok else "failed",
            "objective_length": len(objective.strip()),
            "min_length": self._objective_min_length,
        }
        error = None if ok else f"Objective trop court (< {self._objective_min_length} caractères)"
        return ok, event, error

    def _normalize_departments(self, context: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
        departments = context.get("departments")
        if not isinstance(departments, list):
            return True, {"plugin": "normalize_departments", "status": "noop"}, None
        normalized = [str(item).strip().lower() for item in departments if str(item).strip()]
        context["departments"] = normalized
        return True, {
            "plugin": "normalize_departments",
            "status": "ok",
            "count": len(normalized),
        }, None
