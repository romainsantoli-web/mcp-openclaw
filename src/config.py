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
    secure_production_mode: bool
    policy_blocked_tools: tuple[str, ...]
    policy_allow_write_tools: bool
    policy_allow_network_tools: bool
    audit_enabled: bool
    audit_file_path: Path
    memory_backend: str
    memory_sqlite_path: Path
    memory_os_ai_repo_path: Path
    memory_os_ai_events_path: Path
    memory_os_ai_context_limit: int
    memory_bridge_enabled: bool
    memory_bridge_host: str
    memory_bridge_port: int
    memory_bridge_query_path: str
    memory_bridge_timeout_seconds: int
    memory_bridge_use_in_context: bool
    telemetry_enabled: bool
    workflow_max_attempts: int
    workflow_idempotency_enabled: bool
    workflow_store_path: Path
    plugins_enabled: tuple[str, ...]
    plugin_enforce_objective_min_length: int
    plugin_policy_mode: str
    cost_guard_enabled: bool
    cost_guard_policy_mode: str
    cost_guard_per_run_budget: float
    cost_guard_daily_budget: float
    cost_guard_ledger_path: Path
    prometheus_exporter_enabled: bool
    prometheus_exporter_host: str
    prometheus_exporter_port: int
    prometheus_exporter_path: str


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

    blocked_tools_raw = os.getenv("POLICY_BLOCKED_TOOLS", "")
    blocked_tools = tuple(
        item.strip() for item in blocked_tools_raw.split(",") if item.strip()
    )

    repo_path = os.getenv("FIRM_REPO_PATH", "").strip()
    if repo_path:
        firm_repo_path = Path(repo_path).expanduser().resolve()
    else:
        project_root = Path(__file__).resolve().parents[1]
        firm_repo_path = project_root / "external" / "setup-vs-agent-firm"

    project_root = Path(__file__).resolve().parents[1]
    audit_path_raw = os.getenv("AUDIT_FILE_PATH", "")
    if audit_path_raw:
        audit_file_path = Path(audit_path_raw).expanduser().resolve()
    else:
        audit_file_path = project_root / "data" / "audit.log.jsonl"

    memory_sqlite_raw = os.getenv("MEMORY_SQLITE_PATH", "")
    if memory_sqlite_raw:
        memory_sqlite_path = Path(memory_sqlite_raw).expanduser().resolve()
    else:
        memory_sqlite_path = project_root / "data" / "memory.db"

    memory_os_repo_raw = os.getenv("MEMORY_OS_AI_REPO_PATH", "")
    if memory_os_repo_raw:
        memory_os_ai_repo_path = Path(memory_os_repo_raw).expanduser().resolve()
    else:
        memory_os_ai_repo_path = project_root / "external" / "memory-os-ai"

    memory_os_events_raw = os.getenv("MEMORY_OS_AI_EVENTS_PATH", "")
    if memory_os_events_raw:
        memory_os_ai_events_path = Path(memory_os_events_raw).expanduser().resolve()
    else:
        memory_os_ai_events_path = (
            memory_os_ai_repo_path / "pdfs" / "mcp_openclaw_events.jsonl"
        )

    workflow_store_raw = os.getenv("WORKFLOW_STORE_PATH", "")
    if workflow_store_raw:
        workflow_store_path = Path(workflow_store_raw).expanduser().resolve()
    else:
        workflow_store_path = project_root / "data" / "workflow_runs.jsonl"

    plugins_raw = os.getenv("PLUGINS_ENABLED", "enforce_objective_min_length")
    plugins_enabled = tuple(
        item.strip() for item in plugins_raw.split(",") if item.strip()
    )

    cost_ledger_raw = os.getenv("COST_GUARD_LEDGER_PATH", "")
    if cost_ledger_raw:
        cost_guard_ledger_path = Path(cost_ledger_raw).expanduser().resolve()
    else:
        cost_guard_ledger_path = project_root / "data" / "cost_ledger.jsonl"

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
        secure_production_mode=_to_bool(
            os.getenv("SECURE_PRODUCTION_MODE"),
            default=False,
        ),
        policy_blocked_tools=blocked_tools,
        policy_allow_write_tools=_to_bool(
            os.getenv("POLICY_ALLOW_WRITE_TOOLS"),
            default=False,
        ),
        policy_allow_network_tools=_to_bool(
            os.getenv("POLICY_ALLOW_NETWORK_TOOLS"),
            default=True,
        ),
        audit_enabled=_to_bool(os.getenv("AUDIT_ENABLED"), default=True),
        audit_file_path=audit_file_path,
        memory_backend=os.getenv("MEMORY_BACKEND", "memory_os_ai").strip().lower(),
        memory_sqlite_path=memory_sqlite_path,
        memory_os_ai_repo_path=memory_os_ai_repo_path,
        memory_os_ai_events_path=memory_os_ai_events_path,
        memory_os_ai_context_limit=int(os.getenv("MEMORY_OS_AI_CONTEXT_LIMIT", "16")),
        memory_bridge_enabled=_to_bool(
            os.getenv("MEMORY_BRIDGE_ENABLED"),
            default=True,
        ),
        memory_bridge_host=os.getenv("MEMORY_BRIDGE_HOST", "127.0.0.1").strip(),
        memory_bridge_port=int(os.getenv("MEMORY_BRIDGE_PORT", "9120")),
        memory_bridge_query_path=os.getenv("MEMORY_BRIDGE_QUERY_PATH", "/context/query").strip() or "/context/query",
        memory_bridge_timeout_seconds=int(os.getenv("MEMORY_BRIDGE_TIMEOUT_SECONDS", "3")),
        memory_bridge_use_in_context=_to_bool(
            os.getenv("MEMORY_BRIDGE_USE_IN_CONTEXT"),
            default=True,
        ),
        telemetry_enabled=_to_bool(os.getenv("TELEMETRY_ENABLED"), default=True),
        workflow_max_attempts=int(os.getenv("WORKFLOW_MAX_ATTEMPTS", "2")),
        workflow_idempotency_enabled=_to_bool(
            os.getenv("WORKFLOW_IDEMPOTENCY_ENABLED"),
            default=True,
        ),
        workflow_store_path=workflow_store_path,
        plugins_enabled=plugins_enabled,
        plugin_enforce_objective_min_length=int(
            os.getenv("PLUGIN_ENFORCE_OBJECTIVE_MIN_LENGTH", "24")
        ),
        plugin_policy_mode=os.getenv("PLUGIN_POLICY_MODE", "enforce").strip().lower(),
        cost_guard_enabled=_to_bool(os.getenv("COST_GUARD_ENABLED"), default=True),
        cost_guard_policy_mode=os.getenv("COST_GUARD_POLICY_MODE", "enforce").strip().lower(),
        cost_guard_per_run_budget=float(os.getenv("COST_GUARD_PER_RUN_BUDGET", "2.5")),
        cost_guard_daily_budget=float(os.getenv("COST_GUARD_DAILY_BUDGET", "25.0")),
        cost_guard_ledger_path=cost_guard_ledger_path,
        prometheus_exporter_enabled=_to_bool(
            os.getenv("PROMETHEUS_EXPORTER_ENABLED"),
            default=True,
        ),
        prometheus_exporter_host=os.getenv("PROMETHEUS_EXPORTER_HOST", "127.0.0.1").strip(),
        prometheus_exporter_port=int(os.getenv("PROMETHEUS_EXPORTER_PORT", "9108")),
        prometheus_exporter_path=os.getenv("PROMETHEUS_EXPORTER_PATH", "/metrics").strip() or "/metrics",
    )
