"""
skill_loader.py — Lazy SKILL.md loader for performance optimization

Tools exposed:
  firm_skill_lazy_loader — load SKILL.md metadata without full content parsing
  firm_skill_search      — search skills by keyword/tag across all SKILL.md files
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_YAML_FRONT_MATTER = re.compile(r"^---\n(.*?)\n---", re.DOTALL)
_METADATA_FIELDS = {"name", "version", "description", "tags", "os", "category", "author", "dependencies"}

# ── In-memory cache ──────────────────────────────────────────────────────────

_SKILL_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_TS: float = 0.0
_CACHE_TTL: float = 300.0  # 5 minutes


async def firm_skill_lazy_loader(
    skills_dir: str,
    skill_name: str | None = None,
    refresh: bool = False,
) -> dict[str, Any]:
    """
    Lazy-load SKILL.md metadata without parsing full content.

    Reads only the YAML front-matter (if present) or the first 20 lines
    to extract metadata. Caches results for 5 minutes.

    Args:
        skills_dir: Directory containing skill subdirectories with SKILL.md files.
        skill_name: Specific skill to load. If None, loads all skill metadata.
        refresh: Force cache refresh. Default: False.

    Returns:
        dict with: ok, skills (list of metadata), cached, total.
    """
    global _SKILL_CACHE, _CACHE_TS

    skills_path = Path(skills_dir)
    if not skills_path.exists():
        return {"ok": False, "error": f"Skills directory not found: {skills_dir}"}

    # Check cache validity
    now = time.time()
    if not refresh and _SKILL_CACHE and (now - _CACHE_TS) < _CACHE_TTL:
        if skill_name:
            if skill_name in _SKILL_CACHE:
                return {"ok": True, "skills": [_SKILL_CACHE[skill_name]], "cached": True, "total": 1}
            return {"ok": False, "error": f"Skill '{skill_name}' not found"}
        return {
            "ok": True,
            "skills": list(_SKILL_CACHE.values()),
            "cached": True,
            "total": len(_SKILL_CACHE),
        }

    # Scan skills directory
    _SKILL_CACHE.clear()

    for entry in skills_path.iterdir():
        if not entry.is_dir():
            continue

        skill_file = entry / "SKILL.md"
        if not skill_file.exists():
            continue

        metadata = _extract_metadata(skill_file, entry.name)
        _SKILL_CACHE[entry.name] = metadata

    _CACHE_TS = now

    if skill_name:
        if skill_name in _SKILL_CACHE:
            return {"ok": True, "skills": [_SKILL_CACHE[skill_name]], "cached": False, "total": 1}
        return {"ok": False, "error": f"Skill '{skill_name}' not found"}

    return {
        "ok": True,
        "skills": list(_SKILL_CACHE.values()),
        "cached": False,
        "total": len(_SKILL_CACHE),
    }


async def firm_skill_search(
    skills_dir: str,
    query: str,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """
    Search skills by keyword or tags across all SKILL.md files.

    Args:
        skills_dir: Directory containing skill subdirectories.
        query: Search query (matched against name, description, content).
        tags: Optional list of tags to filter by.

    Returns:
        dict with: ok, results (list of matching skills), total_matches.
    """
    # Ensure cache is loaded
    loader_result = await firm_skill_lazy_loader(skills_dir)
    if not loader_result.get("ok"):
        return loader_result

    query_lower = query.lower()
    results: list[dict[str, Any]] = []

    for skill in _SKILL_CACHE.values():
        score = 0

        # Match against name
        if query_lower in skill.get("name", "").lower():
            score += 10

        # Match against description
        if query_lower in skill.get("description", "").lower():
            score += 5

        # Match against tags
        skill_tags = skill.get("tags", [])
        if isinstance(skill_tags, list):
            for tag in skill_tags:
                if query_lower in str(tag).lower():
                    score += 3

        # Match against first lines content
        if query_lower in skill.get("preview", "").lower():
            score += 2

        # Tag filter
        if tags:
            if not isinstance(skill_tags, list):
                continue
            skill_tags_lower = [str(t).lower() for t in skill_tags]
            if not any(t.lower() in skill_tags_lower for t in tags):
                continue

        if score > 0:
            results.append({**skill, "_relevance": score})

    # Sort by relevance
    results.sort(key=lambda x: x.get("_relevance", 0), reverse=True)

    return {
        "ok": True,
        "results": results[:20],  # limit
        "total_matches": len(results),
        "query": query,
        "tags_filter": tags,
    }


def _extract_metadata(skill_file: Path, dir_name: str) -> dict[str, Any]:
    """Extract metadata from SKILL.md — YAML front-matter or first lines."""
    try:
        content = skill_file.read_text(encoding="utf-8")
    except Exception:
        return {"name": dir_name, "path": str(skill_file), "error": "unreadable"}

    metadata: dict[str, Any] = {
        "name": dir_name,
        "path": str(skill_file),
        "size_bytes": skill_file.stat().st_size,
    }

    # Try YAML front-matter
    fm_match = _YAML_FRONT_MATTER.match(content)
    if fm_match:
        try:
            # Simple YAML-like parsing (no PyYAML dependency)
            for line in fm_match.group(1).splitlines():
                line = line.strip()
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip()
                    val = val.strip()
                    if key in _METADATA_FIELDS:
                        # Handle lists (tags: [a, b, c])
                        if val.startswith("[") and val.endswith("]"):
                            metadata[key] = [v.strip().strip("'\"") for v in val[1:-1].split(",")]
                        else:
                            metadata[key] = val.strip("'\"")
        except Exception:
            pass

    # Extract first heading as name fallback
    for line in content.splitlines()[:20]:
        if line.startswith("# "):
            metadata.setdefault("name", line[2:].strip())
            break

    # Extract description from first paragraph
    lines = content.splitlines()
    desc_lines: list[str] = []
    in_desc = False
    for line in lines[:30]:
        if line.startswith("# "):
            in_desc = True
            continue
        if in_desc:
            if not line.strip():
                if desc_lines:
                    break
                continue
            if line.startswith("#"):
                break
            desc_lines.append(line.strip())

    if desc_lines:
        metadata["description"] = " ".join(desc_lines)[:300]

    # Preview (first 500 chars for search)
    metadata["preview"] = content[:500]

    return metadata


# ── TOOLS registry ───────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "firm_skill_lazy_loader",
        "title": "Lazy Skill Loader",
        "description": (
            "Lazy-loads SKILL.md metadata (YAML front-matter) without parsing full content. "
            "Caches for 5 minutes. Supports per-skill or bulk loading. "
            "Gap T7/issue #26301: reduces startup time for large skill catalogs."
        ),
        "category": "performance",
        "handler": firm_skill_lazy_loader,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "skills_dir": {
                    "type": "string",
                    "description": "Directory containing skill subdirectories.",
                },
                "skill_name": {
                    "type": "string",
                    "description": "Specific skill to load. Omit to load all.",
                },
                "refresh": {
                    "type": "boolean",
                    "description": "Force cache refresh. Default: false.",
                    "default": False,
                },
            },
            "required": ["skills_dir"],
        },
    },
    {
        "name": "firm_skill_search",
        "title": "Skill Keyword Search",
        "description": (
            "Search skills by keyword/tags across all SKILL.md files. "
            "Returns relevance-ranked results with metadata. "
            "Uses the lazy loader cache for performance."
        ),
        "category": "performance",
        "handler": firm_skill_search,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "skills_dir": {
                    "type": "string",
                    "description": "Directory containing skill subdirectories.",
                },
                "query": {
                    "type": "string",
                    "description": "Search query.",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional tag filter.",
                },
            },
            "required": ["skills_dir", "query"],
        },
    },
]
