from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _to_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    openclaw_gateway_url: str
    openclaw_token: str
    openclaw_timeout_seconds: int
    openclaw_reconnect_max_attempts: int
    openclaw_allowed_methods: tuple[str, ...]
    openclaw_allowlist_policy: str
    openclaw_webhook_url: str
    openclaw_dispatch_mode: str
    firm_repo_path: Path | None
    read_only_mode: bool
    log_level: str
    mcp_transport: str
    mcp_mount_path: str | None
    mcp_host: str
    mcp_port: int
    firm_repo_url: str
    firm_repo_branch: str
    firm_repo_auto_sync: bool
    routing_mode: str
    routing_default_task_family: str
    routing_default_quality_tier: str
    routing_default_profile: str
    routing_allowed_profiles: tuple[str, ...]
    routing_enable_copilot_hints: bool
    routing_enable_agent_copilot_access: bool


def load_settings(env_file: Path | None = None) -> Settings:
    if env_file is not None and env_file.exists():
        load_dotenv(env_file)
    else:
        load_dotenv()

    allowed_raw = os.getenv(
        "OPENCLAW_ALLOWED_METHODS",
        "connect,agent.list,agent.run,memory.read,memory.write,health.ping",
    )
    allowed_methods = tuple(
        item.strip() for item in allowed_raw.split(",") if item.strip()
    )

    allowed_profiles_raw = os.getenv(
        "ROUTING_ALLOWED_PROFILES",
        "creative-premium,creative-shortform,creative-longform,planning-strategic,translation-precision,translation-localization,translation-seo,reasoning-technical,debug-root-cause,debug-patch,analysis-deep,analysis-synthesis,analysis-comparison",
    )
    allowed_profiles = tuple(
        item.strip() for item in allowed_profiles_raw.split(",") if item.strip()
    )

    repo_path = os.getenv("FIRM_REPO_PATH", "").strip()
    if repo_path:
        firm_repo_path = Path(repo_path).expanduser().resolve()
    else:
        project_root = Path(__file__).resolve().parents[1]
        firm_repo_path = project_root / "external" / "setup-vs-agent-firm"

    return Settings(
        openclaw_gateway_url=os.getenv(
            "OPENCLAW_GATEWAY_URL", "ws://127.0.0.1:18789/gateway"
        ),
        openclaw_token=os.getenv("OPENCLAW_TOKEN", ""),
        openclaw_timeout_seconds=int(os.getenv("OPENCLAW_TIMEOUT_SECONDS", "20")),
        openclaw_reconnect_max_attempts=int(
            os.getenv("OPENCLAW_RECONNECT_MAX_ATTEMPTS", "3")
        ),
        openclaw_allowed_methods=allowed_methods,
        openclaw_allowlist_policy=os.getenv("OPENCLAW_ALLOWLIST_POLICY", "strict"),
        openclaw_webhook_url=os.getenv("OPENCLAW_WEBHOOK_URL", "").strip(),
        openclaw_dispatch_mode=os.getenv("OPENCLAW_DISPATCH_MODE", "auto"),
        firm_repo_path=firm_repo_path,
        read_only_mode=_to_bool(os.getenv("READ_ONLY_MODE"), default=True),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        mcp_transport=os.getenv("MCP_TRANSPORT", "streamable-http"),
        mcp_mount_path=os.getenv("MCP_MOUNT_PATH", "").strip() or None,
        mcp_host=os.getenv("MCP_HOST", "127.0.0.1"),
        mcp_port=int(os.getenv("MCP_PORT", "8011")),
        firm_repo_url=os.getenv(
            "FIRM_REPO_URL",
            "https://github.com/romainsantoli-web/setup-vs-agent-firm.git",
        ),
        firm_repo_branch=os.getenv("FIRM_REPO_BRANCH", "main"),
        firm_repo_auto_sync=_to_bool(os.getenv("FIRM_REPO_AUTO_SYNC"), default=False),
        routing_mode=os.getenv("ROUTING_MODE", "quality-first"),
        routing_default_task_family=os.getenv("ROUTING_DEFAULT_TASK_FAMILY", "research"),
        routing_default_quality_tier=os.getenv("ROUTING_DEFAULT_QUALITY_TIER", "high"),
        routing_default_profile=os.getenv("ROUTING_DEFAULT_PROFILE", "analysis-deep"),
        routing_allowed_profiles=allowed_profiles,
        routing_enable_copilot_hints=_to_bool(
            os.getenv("ROUTING_ENABLE_COPILOT_HINTS"),
            default=True,
        ),
        routing_enable_agent_copilot_access=_to_bool(
            os.getenv("ROUTING_ENABLE_AGENT_COPILOT_ACCESS"),
            default=True,
        ),
    )
