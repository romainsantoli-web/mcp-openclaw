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


@dataclass(frozen=True)
class SubtaskProfile:
    profile: str
    strengths: tuple[str, ...]


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

_SUBTASK_PROFILES: dict[str, dict[str, SubtaskProfile]] = {
    "marketing": {
        "hooks": SubtaskProfile(
            profile="creative-shortform",
            strengths=("hook", "impact", "conversion"),
        ),
        "long-form": SubtaskProfile(
            profile="creative-longform",
            strengths=("storytelling", "structure", "consistency"),
        ),
        "calendar": SubtaskProfile(
            profile="planning-strategic",
            strengths=("planning", "sequencing", "cadence"),
        ),
    },
    "translation": {
        "localization": SubtaskProfile(
            profile="translation-localization",
            strengths=("cultural-fit", "fidelity", "readability"),
        ),
        "seo": SubtaskProfile(
            profile="translation-seo",
            strengths=("keywords", "intent", "ranking"),
        ),
    },
    "debug": {
        "root-cause": SubtaskProfile(
            profile="debug-root-cause",
            strengths=("root-cause", "tracing", "fixes"),
        ),
        "patch": SubtaskProfile(
            profile="debug-patch",
            strengths=("safe-edits", "validation", "rollback"),
        ),
    },
    "research": {
        "synthesis": SubtaskProfile(
            profile="analysis-synthesis",
            strengths=("coverage", "structure", "clarity"),
        ),
        "comparison": SubtaskProfile(
            profile="analysis-comparison",
            strengths=("tradeoffs", "accuracy", "decision support"),
        ),
    },
}

_DEPARTMENT_TO_FAMILY: dict[str, str] = {
    "communications": "marketing",
    "social-media": "marketing",
    "articles": "marketing",
    "translation-utilization": "translation",
    "runtime-debugging": "debug",
    "source": "research",
    "data": "research",
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


def list_subtask_profiles() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for family, subtasks in sorted(_SUBTASK_PROFILES.items()):
        for subtask, profile in sorted(subtasks.items()):
            rows.append(
                {
                    "task_family": family,
                    "subtask_type": subtask,
                    "profile": profile.profile,
                    "strengths": list(profile.strengths),
                }
            )
    return rows


def _sanitize_profile(settings: Settings, profile_name: str) -> str:
    if settings.routing_allowed_profiles and profile_name not in settings.routing_allowed_profiles:
        return settings.routing_default_profile
    return profile_name


def infer_task_family_for_department(department: str) -> str:
    return _DEPARTMENT_TO_FAMILY.get(department.strip().lower(), "research")


def build_agent_copilot_access_plan(
    settings: Settings,
    departments: list[str],
    quality_tier: str,
    model_override: str | None,
) -> dict[str, Any]:
    if not settings.routing_enable_agent_copilot_access:
        return {
            department: {
                "copilot_access": False,
                "reason": "disabled_by_configuration",
            }
            for department in departments
        }

    plan: dict[str, Any] = {}
    for department in departments:
        family = infer_task_family_for_department(department)
        base_profile = _TASK_PROFILES.get(family, _TASK_PROFILES["research"])
        selected_profile = _sanitize_profile(
            settings,
            model_override.strip() if model_override else base_profile.profile,
        )
        plan[department] = {
            "copilot_access": True,
            "task_family": family,
            "quality_tier": quality_tier,
            "preferred_model_profile": selected_profile,
            "strengths": list(base_profile.strengths),
            "guidance": [
                "Prioriser ce profil pour la génération initiale.",
                "Escalader vers un profil premium en cas de qualité insuffisante.",
            ],
        }
    return plan


def route_task(
    settings: Settings,
    objective: str,
    task_family: str | None,
    quality_tier: str | None,
    subtask_type: str | None,
    latency_budget_ms: int | None,
    model_override: str | None,
) -> dict[str, Any]:
    family = (task_family or settings.routing_default_task_family).strip().lower()
    profile = _TASK_PROFILES.get(family, _TASK_PROFILES["research"])

    quality = (quality_tier or settings.routing_default_quality_tier).strip().lower()
    subtask = (subtask_type or "").strip().lower()
    mode = settings.routing_mode.strip().lower()

    subtask_profile = _SUBTASK_PROFILES.get(family, {}).get(subtask)
    base_selected_profile = profile.profile
    if subtask_profile is not None:
        base_selected_profile = subtask_profile.profile

    selected_profile = model_override.strip() if model_override else base_selected_profile
    selected_profile = _sanitize_profile(settings, selected_profile)

    rationale = [
        f"task_family={family}",
        f"routing_mode={mode}",
        f"quality_tier={quality}",
        f"subtask_type={subtask or 'n/a'}",
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
        "subtask_type": subtask or None,
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
