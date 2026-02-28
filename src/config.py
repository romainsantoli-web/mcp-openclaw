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
    firm_repo_path: Path | None
    read_only_mode: bool
    log_level: str
    mcp_transport: str
    mcp_mount_path: str | None
    mcp_host: str
    mcp_port: int


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

    repo_path = os.getenv("FIRM_REPO_PATH", "").strip()
    firm_repo_path = Path(repo_path).expanduser().resolve() if repo_path else None

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
        firm_repo_path=firm_repo_path,
        read_only_mode=_to_bool(os.getenv("READ_ONLY_MODE"), default=True),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        mcp_transport=os.getenv("MCP_TRANSPORT", "streamable-http"),
        mcp_mount_path=os.getenv("MCP_MOUNT_PATH", "").strip() or None,
        mcp_host=os.getenv("MCP_HOST", "127.0.0.1"),
        mcp_port=int(os.getenv("MCP_PORT", "8011")),
    )
