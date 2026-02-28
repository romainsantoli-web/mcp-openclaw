from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import Settings


@dataclass(frozen=True)
class RouteProfile:
    profile: str
    strengths: tuple[str, ...]
    default_method: str
    fallback_methods: tuple[str, ...]


_TASK_PROFILES: dict[str, RouteProfile] = {
    "marketing": RouteProfile(
        profile="creative-premium",
        strengths=("créativité", "narrative", "engagement"),
        default_method="agent.run",
        fallback_methods=("hooks.agent",),
    ),
    "translation": RouteProfile(
        profile="translation-precision",
        strengths=("fidelity", "terminologie", "consistance"),
        default_method="agent.run",
        fallback_methods=("hooks.agent",),
    ),
    "debug": RouteProfile(
        profile="reasoning-technical",
        strengths=("raisonnement", "diagnostic", "correction"),
        default_method="agent.run",
        fallback_methods=("hooks.agent",),
    ),
    "research": RouteProfile(
        profile="analysis-deep",
        strengths=("synthèse", "structure", "couverture"),
        default_method="agent.run",
        fallback_methods=("hooks.agent",),
    ),
}


def list_profiles() -> list[dict[str, Any]]:
    return [
        {
            "task_family": task_family,
            "profile": profile.profile,
            "strengths": list(profile.strengths),
            "default_method": profile.default_method,
            "fallback_methods": list(profile.fallback_methods),
        }
        for task_family, profile in sorted(_TASK_PROFILES.items())
    ]


def route_task(
    settings: Settings,
    objective: str,
    task_family: str | None,
    quality_tier: str | None,
    latency_budget_ms: int | None,
    model_override: str | None,
) -> dict[str, Any]:
    family = (task_family or settings.routing_default_task_family).strip().lower()
    profile = _TASK_PROFILES.get(family, _TASK_PROFILES["research"])

    quality = (quality_tier or settings.routing_default_quality_tier).strip().lower()
    mode = settings.routing_mode.strip().lower()

    selected_profile = model_override.strip() if model_override else profile.profile
    if settings.routing_allowed_profiles and selected_profile not in settings.routing_allowed_profiles:
        selected_profile = settings.routing_default_profile

    rationale = [
        f"task_family={family}",
        f"routing_mode={mode}",
        f"quality_tier={quality}",
        f"base_profile={profile.profile}",
        f"selected_profile={selected_profile}",
    ]
    if latency_budget_ms is not None:
        rationale.append(f"latency_budget_ms={latency_budget_ms}")

    copilot_hints = {
        "preferred_model_profile": selected_profile,
        "task_family": family,
        "quality_tier": quality,
        "mode": mode,
    }

    return {
        "task_family": family,
        "quality_tier": quality,
        "latency_budget_ms": latency_budget_ms,
        "objective_length": len(objective),
        "model_profile": selected_profile,
        "strengths": list(profile.strengths),
        "default_method": profile.default_method,
        "fallback_methods": list(profile.fallback_methods),
        "copilot_hints": copilot_hints if settings.routing_enable_copilot_hints else {},
        "rationale": rationale,
    }
