from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from .config import Settings


class FirmRepoError(RuntimeError):
    pass


def ensure_repo_path(settings: Settings) -> Path:
    repo_path = settings.firm_repo_path
    if repo_path is None:
        raise FirmRepoError("FIRM_REPO_PATH non configuré")
    return repo_path


def repo_status(settings: Settings) -> dict[str, Any]:
    try:
        repo_path = ensure_repo_path(settings)
    except FirmRepoError as exc:
        return {"ok": False, "error": str(exc)}

    git_dir = repo_path / ".git"
    agents_dir = repo_path / ".github" / "agents"
    prompts_dir = repo_path / ".github" / "prompts"

    return {
        "ok": True,
        "path": str(repo_path),
        "exists": repo_path.exists(),
        "is_git_repo": git_dir.exists(),
        "has_agents_dir": agents_dir.exists(),
        "has_prompts_dir": prompts_dir.exists(),
        "repo_url": settings.firm_repo_url,
        "branch": settings.firm_repo_branch,
    }


def sync_repo(settings: Settings) -> dict[str, Any]:
    repo_path = ensure_repo_path(settings)
    repo_path.parent.mkdir(parents=True, exist_ok=True)

    if not repo_path.exists() or not (repo_path / ".git").exists():
        cmd = [
            "git",
            "clone",
            "--branch",
            settings.firm_repo_branch,
            "--single-branch",
            settings.firm_repo_url,
            str(repo_path),
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            raise FirmRepoError(result.stderr.strip() or "Échec du clone")
        return {
            "ok": True,
            "action": "cloned",
            "path": str(repo_path),
            "stdout": result.stdout.strip(),
        }

    fetch_result = subprocess.run(
        ["git", "-C", str(repo_path), "fetch", "origin", settings.firm_repo_branch],
        check=False,
        capture_output=True,
        text=True,
    )
    if fetch_result.returncode != 0:
        raise FirmRepoError(fetch_result.stderr.strip() or "Échec du fetch")

    reset_result = subprocess.run(
        [
            "git",
            "-C",
            str(repo_path),
            "reset",
            "--hard",
            f"origin/{settings.firm_repo_branch}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if reset_result.returncode != 0:
        raise FirmRepoError(reset_result.stderr.strip() or "Échec du reset")

    return {
        "ok": True,
        "action": "updated",
        "path": str(repo_path),
        "stdout": "\n".join(
            line for line in [fetch_result.stdout.strip(), reset_result.stdout.strip()] if line
        ),
    }


def list_agents(settings: Settings) -> list[str]:
    repo_path = ensure_repo_path(settings)
    agents_dir = repo_path / ".github" / "agents"
    if not agents_dir.exists():
        return []
    return sorted(file_path.stem for file_path in agents_dir.glob("*.agent.md"))


def list_prompts(settings: Settings) -> list[str]:
    repo_path = ensure_repo_path(settings)
    prompts_dir = repo_path / ".github" / "prompts"
    if not prompts_dir.exists():
        return []
    return sorted(file_path.name for file_path in prompts_dir.glob("*.md"))


def load_prompt(settings: Settings, prompt_name: str) -> dict[str, Any]:
    repo_path = ensure_repo_path(settings)
    file_path = repo_path / ".github" / "prompts" / prompt_name
    if not file_path.exists():
        return {"ok": False, "error": f"Prompt introuvable: {prompt_name}"}

    return {
        "ok": True,
        "prompt": prompt_name,
        "content": file_path.read_text(encoding="utf-8"),
    }


def validate_layout(settings: Settings) -> dict[str, Any]:
    status = repo_status(settings)
    if not status.get("ok"):
        return status

    missing: list[str] = []
    required_paths = [
        ".github/agents",
        ".github/prompts",
        "README.md",
    ]
    repo_path = ensure_repo_path(settings)
    for rel_path in required_paths:
        if not (repo_path / rel_path).exists():
            missing.append(rel_path)

    return {
        "ok": len(missing) == 0,
        "missing": missing,
        "required": required_paths,
    }
