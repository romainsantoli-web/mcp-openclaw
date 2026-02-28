"""
models.py — Pydantic v2 input models for all 75 MCP tools.

Validated in main.py before dispatching to handlers.
ValidationError is caught and returned as a structured tool error.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field, field_validator, model_validator


# ── Shared path-traversal guard ──────────────────────────────────────────────

def _check_no_traversal(v: str | None, field_name: str = "path") -> str | None:
    """Block '..' in path fields — single source of truth for all models."""
    if v is not None and ".." in v:
        raise ValueError(f"{field_name} must not contain path traversal (..)")
    return v


# ── Reusable base for config-path-only models ───────────────────────────────

class ConfigPathInput(BaseModel):
    """Base model for tools that take a single optional config_path."""
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


# ════════════════════════════════════════════════════════════
# vs_bridge — 4 tools
# ════════════════════════════════════════════════════════════

_SESSION_ID_PATTERN = r"^[a-zA-Z0-9_\-:.]+$"


class VsContextPushInput(BaseModel):
    session_id: Annotated[str, Field(min_length=1, max_length=256, pattern=_SESSION_ID_PATTERN)]
    workspace_path: Annotated[str, Field(min_length=1, max_length=4096)]
    open_files: list[str] = Field(default_factory=list, max_length=200)
    active_file: str | None = None
    selection: str | None = Field(default=None, max_length=16_384)
    diagnostics: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    language_id: str | None = Field(default=None, max_length=64)
    metadata: dict[str, Any] | None = None


class VsContextPullInput(BaseModel):
    session_id: Annotated[str, Field(min_length=1, max_length=256, pattern=_SESSION_ID_PATTERN)]


class VsSessionLinkInput(BaseModel):
    workspace_path: Annotated[str, Field(min_length=1, max_length=4096)]
    session_id: Annotated[str, Field(min_length=1, max_length=256, pattern=_SESSION_ID_PATTERN)]


class VsSessionStatusInput(BaseModel):
    workspace_path: str | None = Field(default=None, max_length=4096)


# ════════════════════════════════════════════════════════════
# gateway_fleet — 6 tools
# ════════════════════════════════════════════════════════════

class FleetStatusInput(BaseModel):
    filter_tags: list[str] | None = Field(default=None, max_length=20)


class FleetAddInput(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_\-]+$")]
    url: Annotated[str, Field(min_length=7, max_length=2048)]
    tags: list[str] = Field(default_factory=list, max_length=20)
    notes: str | None = Field(default=None, max_length=512)

    @field_validator("url")
    @classmethod
    def must_be_http_or_ws(cls, v: str) -> str:
        if not (v.startswith("http://") or v.startswith("https://")
                or v.startswith("ws://") or v.startswith("wss://")):
            raise ValueError("url must start with http://, https://, ws://, or wss://")
        return v


class FleetRemoveInput(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]


class FleetBroadcastInput(BaseModel):
    agent: Annotated[str, Field(min_length=1, max_length=128)]
    message: Annotated[str, Field(min_length=1, max_length=32_768)]
    filter_tags: list[str] | None = Field(default=None, max_length=20)
    metadata: dict[str, Any] | None = None


class FleetSyncInput(BaseModel):
    config_patch: dict[str, Any] | None = None
    skill_slugs: list[str] = Field(default_factory=list, max_length=100)
    filter_tags: list[str] | None = Field(default=None, max_length=20)
    dry_run: bool = False


class FleetListInput(BaseModel):
    filter_tags: list[str] | None = Field(default=None, max_length=20)
    include_health: bool = False


# ════════════════════════════════════════════════════════════
# delivery_export — 6 tools
# ════════════════════════════════════════════════════════════

class ExportGithubPrInput(BaseModel):
    objective: Annotated[str, Field(min_length=1, max_length=512)]
    content: Annotated[str, Field(min_length=1, max_length=1_048_576)]  # 1 MB cap
    departments: list[str] = Field(default_factory=list, max_length=50)
    repo: str | None = Field(default=None, max_length=256)
    base_branch: str = Field(default="main", max_length=256)
    reviewers: list[str] = Field(default_factory=list, max_length=20)
    labels: list[str] = Field(default_factory=list, max_length=20)
    metadata: dict[str, Any] | None = None

    @field_validator("repo")
    @classmethod
    def repo_format(cls, v: str | None) -> str | None:
        if v is not None and "/" not in v:
            raise ValueError("repo must be in 'owner/name' format")
        return v


class ExportJiraTicketInput(BaseModel):
    objective: Annotated[str, Field(min_length=1, max_length=512)]
    content: Annotated[str, Field(min_length=1, max_length=100_000)]
    departments: list[str] = Field(default_factory=list, max_length=50)
    project_key: str | None = Field(default=None, max_length=32)
    issue_type: str = Field(default="Task", max_length=64)
    priority: str = Field(default="Medium", max_length=32)
    metadata: dict[str, Any] | None = None


class ExportLinearIssueInput(BaseModel):
    objective: Annotated[str, Field(min_length=1, max_length=512)]
    content: Annotated[str, Field(min_length=1, max_length=100_000)]
    departments: list[str] = Field(default_factory=list, max_length=50)
    team_id: str | None = Field(default=None, max_length=128)
    priority: int = Field(default=2, ge=0, le=4)
    labels: list[str] = Field(default_factory=list, max_length=20)
    metadata: dict[str, Any] | None = None


class ExportSlackDigestInput(BaseModel):
    objective: Annotated[str, Field(min_length=1, max_length=512)]
    content: Annotated[str, Field(min_length=1, max_length=40_000)]
    departments: list[str] = Field(default_factory=list, max_length=50)
    channel: str | None = Field(default=None, max_length=128)
    mention_users: list[str] = Field(default_factory=list, max_length=10)
    metadata: dict[str, Any] | None = None


class ExportDocumentInput(BaseModel):
    objective: Annotated[str, Field(min_length=1, max_length=512)]
    content: Annotated[str, Field(min_length=1, max_length=1_048_576)]
    departments: list[str] = Field(default_factory=list, max_length=50)
    output_path: str | None = Field(default=None, max_length=4096)
    metadata: dict[str, Any] | None = None

    @field_validator("output_path")
    @classmethod
    def no_path_traversal(cls, v):
        return _check_no_traversal(v, "output_path")


_VALID_FORMATS = {
    "github_pr", "jira_ticket", "linear_issue",
    "slack_digest", "markdown_report", "structured_document", "project_brief",
}


# ════════════════════════════════════════════════════════════
# security_audit — 4 tools (C1, C2, C3, H8)
# ════════════════════════════════════════════════════════════

class SecurityScanInput(BaseModel):
    target_path: Annotated[str, Field(min_length=1, max_length=4096)]
    endpoint: str | None = Field(default=None, max_length=256)
    scan_depth: int = Field(default=3, ge=1, le=5)

    @field_validator("target_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "target_path")


class SandboxAuditInput(BaseModel):
    config_path: Annotated[str, Field(min_length=1, max_length=4096)]

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class SessionConfigCheckInput(BaseModel):
    env_file_path: str | None = Field(default=None, max_length=4096)
    compose_file_path: str | None = Field(default=None, max_length=4096)

    @field_validator("env_file_path", "compose_file_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "path")

    @model_validator(mode="after")
    def at_least_one_path(self) -> "SessionConfigCheckInput":
        """Cross-field: at least one of env_file_path or compose_file_path must be provided."""
        if self.env_file_path is None and self.compose_file_path is None:
            raise ValueError(
                "At least one of env_file_path or compose_file_path must be provided"
            )
        return self


class RateLimitCheckInput(BaseModel):
    gateway_config_path: Annotated[str, Field(min_length=1, max_length=4096)]
    check_funnel: bool = True

    @field_validator("gateway_config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "gateway_config_path")


# ════════════════════════════════════════════════════════════
# acp_bridge — 6 tools (C4, H3, H4, H5)
# ════════════════════════════════════════════════════════════

class AcpSessionPersistInput(BaseModel):
    run_id: Annotated[str, Field(min_length=1, max_length=256)]
    gateway_session_key: Annotated[str, Field(min_length=1, max_length=256)]
    metadata: dict[str, Any] | None = None


class AcpSessionRestoreInput(BaseModel):
    max_age_hours: int = Field(default=24, ge=1, le=720)  # 1h — 30 days


class AcpSessionListActiveInput(BaseModel):
    include_stale: bool = False


class FleetSessionInjectEnvInput(BaseModel):
    env_vars: dict[str, str] = Field(min_length=1)
    filter_tags: list[str] | None = Field(default=None, max_length=20)
    allowlist_keys: list[str] | None = Field(default=None, max_length=50)
    dry_run: bool = False

    @field_validator("env_vars")
    @classmethod
    def no_empty_values(cls, v: dict[str, str]) -> dict[str, str]:
        for key, val in v.items():
            if not key or not key.strip():
                raise ValueError("env_vars keys must not be empty")
        return v


class FleetCronScheduleInput(BaseModel):
    command: Annotated[str, Field(min_length=1, max_length=512)]
    schedule: Annotated[str, Field(min_length=9, max_length=64)]
    session: str = Field(default="main", max_length=128)
    description: str | None = Field(default=None, max_length=512)

    @field_validator("command")
    @classmethod
    def safe_command(cls, v: str) -> str:
        import re
        if not re.match(r"^[a-zA-Z0-9 /._\-=]+$", v):
            raise ValueError(
                "command contains disallowed characters. "
                "Only [a-zA-Z0-9 /._-=] are permitted."
            )
        return v

    @field_validator("schedule")
    @classmethod
    def valid_cron(cls, v: str) -> str:
        if len(v.strip().split()) != 5:
            raise ValueError("schedule must be a valid 5-field cron expression (min hour dom mon dow)")
        return v


class WorkspaceLockInput(BaseModel):
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    action: str = Field(..., pattern=r"^(acquire|release|status)$")
    owner: Annotated[str, Field(min_length=1, max_length=256)]
    timeout_s: float = Field(default=30.0, ge=1.0, le=300.0)

    @field_validator("path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "path")

    @model_validator(mode="after")
    def timeout_only_for_acquire(self) -> "WorkspaceLockInput":
        """Cross-field: warn if timeout_s changed for non-acquire actions (ignored)."""
        if self.action in ("release", "status") and self.timeout_s != 30.0:
            # Silently reset — timeout is meaningless for release/status
            object.__setattr__(self, "timeout_s", 30.0)
        return self


# ════════════════════════════════════════════════════════════
# reliability_probe — 4 tools (H6, H7, M1, M5, M6)
# ════════════════════════════════════════════════════════════

class GatewayProbeInput(BaseModel):
    gateway_url: str = Field(
        default="ws://127.0.0.1:18789",
        min_length=6,
        max_length=512,
    )
    max_retries: int = Field(default=3, ge=1, le=5)
    backoff_factor: float = Field(default=1.0, ge=0.1, le=10.0)

    @field_validator("gateway_url")
    @classmethod
    def must_be_ws(cls, v: str) -> str:
        if not (v.startswith("ws://") or v.startswith("wss://")):
            raise ValueError("gateway_url must start with ws:// or wss://")
        return v


class DocSyncCheckInput(BaseModel):
    package_json_path: Annotated[str, Field(min_length=1, max_length=4096)]
    docs_glob: str = Field(default="**/*.md", max_length=256)

    @field_validator("package_json_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "package_json_path")


class ChannelAuditInput(BaseModel):
    package_json_path: Annotated[str, Field(min_length=1, max_length=4096)]
    readme_path: Annotated[str, Field(min_length=1, max_length=4096)]

    @field_validator("package_json_path", "readme_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "path")


_VALID_ADR_STATUSES = {"proposed", "accepted", "deprecated", "superseded"}


class AdrGenerateInput(BaseModel):
    title: Annotated[str, Field(min_length=3, max_length=256)]
    context: Annotated[str, Field(min_length=10, max_length=8192)]
    decision: Annotated[str, Field(min_length=10, max_length=8192)]
    alternatives: list[str] = Field(default_factory=list, max_length=20)
    consequences: list[str] = Field(default_factory=list, max_length=20)
    status: str = Field(default="proposed", max_length=32)
    adr_id: str | None = Field(default=None, max_length=64)

    @field_validator("status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        if v not in _VALID_ADR_STATUSES:
            raise ValueError(f"status must be one of {sorted(_VALID_ADR_STATUSES)}, got {v!r}")
        return v


class ExportAutoInput(BaseModel):
    objective: Annotated[str, Field(min_length=1, max_length=512)]
    content: Annotated[str, Field(min_length=1, max_length=1_048_576)]
    departments: list[str] = Field(default_factory=list, max_length=50)
    delivery_format: str = Field(default="markdown_report", max_length=64)
    metadata: dict[str, Any] | None = None

    @field_validator("delivery_format")
    @classmethod
    def valid_format(cls, v: str) -> str:
        if v not in _VALID_FORMATS:
            raise ValueError(
                f"delivery_format must be one of {sorted(_VALID_FORMATS)}, got {v!r}"
            )
        return v


# ════════════════════════════════════════════════════════════
# gateway_hardening — 5 tools (H2, M3, M4, M7, M8)
# ════════════════════════════════════════════════════════════

class GatewayAuthCheckInput(ConfigPathInput):
    pass


class CredentialsCheckInput(BaseModel):
    credentials_dir: str | None = Field(default=None, max_length=4096)
    max_age_days: int = Field(default=30, ge=1, le=365)

    @field_validator("credentials_dir")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "credentials_dir")


class WebhookSigCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)
    channel: str | None = Field(default=None, max_length=64)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class LogConfigCheckInput(ConfigPathInput):
    pass


class WorkspaceIntegrityCheckInput(BaseModel):
    workspace_dir: str | None = Field(default=None, max_length=4096)
    stale_days: int = Field(default=30, ge=1, le=365)

    @field_validator("workspace_dir")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "workspace_dir")


# ════════════════════════════════════════════════════════════
# runtime_audit (C5, C6, H9, H10, H11, M15, M16)
# ════════════════════════════════════════════════════════════

class NodeVersionCheckInput(BaseModel):
    node_binary: str | None = Field(default=None, max_length=4096)

    @field_validator("node_binary")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "node_binary")


class SecretsWorkflowCheckInput(ConfigPathInput):
    pass


class HttpHeadersCheckInput(ConfigPathInput):
    pass


class NodesCommandsCheckInput(ConfigPathInput):
    pass


class TrustedProxyCheckInput(ConfigPathInput):
    pass


class SessionDiskBudgetCheckInput(ConfigPathInput):
    pass


class DmAllowlistCheckInput(ConfigPathInput):
    pass


# ════════════════════════════════════════════════════════════
# advanced_security (C7, C8, C9, H12, H13, H14, H15, H16)
# ════════════════════════════════════════════════════════════


class SecretsLifecycleCheckInput(ConfigPathInput):
    pass


class ChannelAuthCanonCheckInput(ConfigPathInput):
    pass


class ExecApprovalFreezeCheckInput(ConfigPathInput):
    pass


class HookSessionRoutingCheckInput(ConfigPathInput):
    pass


class ConfigIncludeCheckInput(ConfigPathInput):
    pass


class ConfigPrototypeCheckInput(ConfigPathInput):
    pass


class SafeBinsProfileCheckInput(ConfigPathInput):
    pass


class GroupPolicyDefaultCheckInput(ConfigPathInput):
    pass


# ════════════════════════════════════════════════════════════
# config_migration (H17, H18, H19, M17, M21)
# ════════════════════════════════════════════════════════════


class ShellEnvCheckInput(ConfigPathInput):
    pass


class PluginIntegrityCheckInput(ConfigPathInput):
    pass


class TokenSeparationCheckInput(ConfigPathInput):
    pass


class OtelRedactionCheckInput(ConfigPathInput):
    pass


class RpcRateLimitCheckInput(ConfigPathInput):
    pass


# ════════════════════════════════════════════════════════════
# observability (T1, T6)
# ════════════════════════════════════════════════════════════


class ObservabilityPipelineInput(BaseModel):
    jsonl_path: Annotated[str, Field(min_length=1, max_length=4096)]
    db_path: str | None = Field(default=None, max_length=4096)
    table_name: Annotated[str, Field(
        min_length=1, max_length=128,
        pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,127}$",
    )] = "traces"
    max_lines: int = Field(default=50_000, ge=1, le=500_000)

    @field_validator("jsonl_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "jsonl_path")

    @field_validator("db_path")
    @classmethod
    def no_traversal_db(cls, v):
        return _check_no_traversal(v, "db_path")


class CiPipelineCheckInput(BaseModel):
    repo_path: Annotated[str, Field(min_length=1, max_length=4096)]
    ci_dir: Annotated[str, Field(max_length=256)] = ".github/workflows"

    @field_validator("repo_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "repo_path")

    @field_validator("ci_dir")
    @classmethod
    def no_traversal_ci(cls, v):
        return _check_no_traversal(v, "ci_dir")


# ════════════════════════════════════════════════════════════
# memory_audit (T3, T9)
# ════════════════════════════════════════════════════════════


class PgvectorMemoryCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)
    connection_string: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class KnowledgeGraphCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)
    graph_data_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")

    @field_validator("graph_data_path")
    @classmethod
    def no_traversal_graph(cls, v):
        return _check_no_traversal(v, "graph_data_path")


# ════════════════════════════════════════════════════════════
# hebbian_memory — Adaptive Hebbian memory system
# ════════════════════════════════════════════════════════════


class HebbianHarvestInput(BaseModel):
    """Ingest JSONL session logs into the local Hebbian SQLite database."""
    session_jsonl_path: Annotated[str, Field(min_length=1, max_length=4096)]
    claude_md_path: str | None = Field(default=None, max_length=4096)
    db_path: str | None = Field(default=None, max_length=4096)
    max_lines: int = Field(default=50_000, ge=1, le=200_000)

    @field_validator("session_jsonl_path")
    @classmethod
    def no_traversal_jsonl(cls, v):
        return _check_no_traversal(v, "session_jsonl_path")

    @field_validator("claude_md_path")
    @classmethod
    def no_traversal_md(cls, v):
        return _check_no_traversal(v, "claude_md_path")

    @field_validator("db_path")
    @classmethod
    def no_traversal_db(cls, v):
        return _check_no_traversal(v, "db_path")


class HebbianWeightUpdateInput(BaseModel):
    """Compute or apply Hebbian weight updates on Layer 2 rules."""
    claude_md_path: Annotated[str, Field(min_length=1, max_length=4096)]
    db_path: str | None = Field(default=None, max_length=4096)
    learning_rate: float = Field(default=0.05, ge=0.001, le=0.5)
    decay: float = Field(default=0.02, ge=0.001, le=0.2)
    dry_run: bool = Field(default=True)

    @field_validator("claude_md_path")
    @classmethod
    def no_traversal_md(cls, v):
        return _check_no_traversal(v, "claude_md_path")

    @field_validator("db_path")
    @classmethod
    def no_traversal_db(cls, v):
        return _check_no_traversal(v, "db_path")


class HebbianAnalyzeInput(BaseModel):
    """Analyze co-activation patterns from harvested sessions."""
    db_path: str | None = Field(default=None, max_length=4096)
    since_days: int = Field(default=90, ge=1, le=365)
    min_cluster_size: int = Field(default=5, ge=2, le=100)

    @field_validator("db_path")
    @classmethod
    def no_traversal_db(cls, v):
        return _check_no_traversal(v, "db_path")


class HebbianStatusInput(BaseModel):
    """Dashboard: session count, rule weights, atrophy/promotion candidates."""
    db_path: str | None = Field(default=None, max_length=4096)
    claude_md_path: str | None = Field(default=None, max_length=4096)

    @field_validator("db_path")
    @classmethod
    def no_traversal_db(cls, v):
        return _check_no_traversal(v, "db_path")

    @field_validator("claude_md_path")
    @classmethod
    def no_traversal_md(cls, v):
        return _check_no_traversal(v, "claude_md_path")


class HebbianLayerValidateInput(BaseModel):
    """Validate the 4-layer structure of a Hebbian-augmented Claude.md."""
    claude_md_path: Annotated[str, Field(min_length=1, max_length=4096)]

    @field_validator("claude_md_path")
    @classmethod
    def no_traversal_md(cls, v):
        return _check_no_traversal(v, "claude_md_path")


class HebbianPiiCheckInput(BaseModel):
    """Audit PII stripping configuration for Hebbian memory storage."""
    config_path: str | None = Field(default=None, max_length=4096)
    config_data: dict[str, Any] | None = Field(default=None)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class HebbianDecayConfigCheckInput(BaseModel):
    """Validate Hebbian learning rate, decay, and consolidation thresholds."""
    config_path: str | None = Field(default=None, max_length=4096)
    config_data: dict[str, Any] | None = Field(default=None)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class HebbianDriftCheckInput(BaseModel):
    """Compare Claude.md against a baseline to detect semantic drift."""
    claude_md_path: Annotated[str, Field(min_length=1, max_length=4096)]
    baseline_path: str | None = Field(default=None, max_length=4096)
    threshold: float = Field(default=0.7, ge=0.0, le=1.0)

    @field_validator("claude_md_path")
    @classmethod
    def no_traversal_md(cls, v):
        return _check_no_traversal(v, "claude_md_path")

    @field_validator("baseline_path")
    @classmethod
    def no_traversal_baseline(cls, v):
        return _check_no_traversal(v, "baseline_path")


# ════════════════════════════════════════════════════════════
# agent_orchestration (T4)
# ════════════════════════════════════════════════════════════


class AgentTeamOrchestrateInput(BaseModel):
    tasks: list[dict[str, Any]] = Field(..., min_length=1, max_length=100)
    objective: str = Field(default="", max_length=1024)
    aggregation_strategy: str = Field(
        default="collect", pattern=r"^(collect|vote|first_success)$"
    )
    timeout_s: float = Field(default=120.0, ge=1.0, le=600.0)

    @model_validator(mode="after")
    def validate_task_dependencies(self) -> "AgentTeamOrchestrateInput":
        """Cross-field: check task IDs are unique and deps reference existing tasks."""
        task_ids: set[str] = set()
        for i, task in enumerate(self.tasks):
            tid = task.get("id")
            if tid:
                if tid in task_ids:
                    raise ValueError(f"Duplicate task id '{tid}' at index {i}")
                task_ids.add(tid)
        # Validate dependencies reference existing task IDs
        for i, task in enumerate(self.tasks):
            deps = task.get("depends_on", [])
            if isinstance(deps, str):
                deps = [deps]
            for dep in deps:
                if dep and task_ids and dep not in task_ids:
                    raise ValueError(
                        f"Task {i} depends on '{dep}' which is not a valid task id"
                    )
        return self


class AgentTeamStatusInput(BaseModel):
    orchestration_id: str | None = Field(default=None, max_length=256)


# ════════════════════════════════════════════════════════════
# i18n_audit (T5)
# ════════════════════════════════════════════════════════════


class I18nAuditInput(BaseModel):
    project_path: Annotated[str, Field(min_length=1, max_length=4096)]
    base_locale: str = Field(default="en", min_length=2, max_length=10)
    locale_dir: str | None = Field(default=None, max_length=4096)
    file_format: str = Field(default="json", pattern=r"^(json|yaml|properties)$")

    @field_validator("project_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "project_path")

    @field_validator("locale_dir")
    @classmethod
    def no_traversal_locale(cls, v):
        return _check_no_traversal(v, "locale_dir")


# ════════════════════════════════════════════════════════════
# skill_loader (T7)
# ════════════════════════════════════════════════════════════


class SkillLazyLoaderInput(BaseModel):
    skills_dir: Annotated[str, Field(min_length=1, max_length=4096)]
    skill_name: str | None = Field(default=None, max_length=256)
    refresh: bool = False

    @field_validator("skills_dir")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "skills_dir")


class SkillSearchInput(BaseModel):
    skills_dir: Annotated[str, Field(min_length=1, max_length=4096)]
    query: Annotated[str, Field(min_length=1, max_length=512)]
    tags: list[str] | None = Field(default=None, max_length=20)

    @field_validator("skills_dir")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "skills_dir")


# ════════════════════════════════════════════════════════════
# n8n_bridge — 2 tools (T8)
# ════════════════════════════════════════════════════════════

class N8nWorkflowExportInput(BaseModel):
    pipeline_name: Annotated[str, Field(min_length=1, max_length=256)]
    steps: list[dict[str, Any]] = Field(min_length=1, max_length=200)
    output_path: str | None = Field(default=None, max_length=4096)

    @field_validator("output_path")
    @classmethod
    def no_traversal_output(cls, v):
        return _check_no_traversal(v, "output_path")


class N8nWorkflowImportInput(BaseModel):
    workflow_path: Annotated[str, Field(min_length=1, max_length=4096)]
    target_dir: str | None = Field(default=None, max_length=4096)
    strict: bool = True

    @field_validator("workflow_path")
    @classmethod
    def no_traversal_workflow(cls, v):
        return _check_no_traversal(v, "workflow_path")

    @field_validator("target_dir")
    @classmethod
    def no_traversal_target(cls, v):
        return _check_no_traversal(v, "target_dir")


# ════════════════════════════════════════════════════════════
# browser_audit — 1 tool (T10)
# ════════════════════════════════════════════════════════════

class BrowserContextCheckInput(BaseModel):
    workspace_path: Annotated[str, Field(min_length=1, max_length=4096)]
    config_override: dict[str, Any] | None = None
    check_deps: bool = True

    @field_validator("workspace_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "workspace_path")


# ════════════════════════════════════════════════════════════
# Registry: tool name → Pydantic model class
# ════════════════════════════════════════════════════════════

TOOL_MODELS: dict[str, type[BaseModel]] = {
    # vs_bridge
    "vs_context_push":              VsContextPushInput,
    "vs_context_pull":              VsContextPullInput,
    "vs_session_link":              VsSessionLinkInput,
    "vs_session_status":            VsSessionStatusInput,
    # gateway_fleet
    "firm_gateway_fleet_status":    FleetStatusInput,
    "firm_gateway_fleet_add":       FleetAddInput,
    "firm_gateway_fleet_remove":    FleetRemoveInput,
    "firm_gateway_fleet_broadcast": FleetBroadcastInput,
    "firm_gateway_fleet_sync":      FleetSyncInput,
    "firm_gateway_fleet_list":      FleetListInput,
    # delivery_export
    "firm_export_github_pr":        ExportGithubPrInput,
    "firm_export_jira_ticket":      ExportJiraTicketInput,
    "firm_export_linear_issue":     ExportLinearIssueInput,
    "firm_export_slack_digest":     ExportSlackDigestInput,
    "firm_export_document":         ExportDocumentInput,
    "firm_export_auto":             ExportAutoInput,
    # security_audit (C1, C2, C3, H8)
    "openclaw_security_scan":       SecurityScanInput,
    "openclaw_sandbox_audit":       SandboxAuditInput,
    "openclaw_session_config_check": SessionConfigCheckInput,
    "openclaw_rate_limit_check":    RateLimitCheckInput,
    # acp_bridge (C4, H3, H4, H5)
    "acp_session_persist":          AcpSessionPersistInput,
    "acp_session_restore":          AcpSessionRestoreInput,
    "acp_session_list_active":      AcpSessionListActiveInput,
    "fleet_session_inject_env":     FleetSessionInjectEnvInput,
    "fleet_cron_schedule":          FleetCronScheduleInput,
    "openclaw_workspace_lock":      WorkspaceLockInput,
    # reliability_probe (H6, H7, M1, M5, M6)
    "openclaw_gateway_probe":       GatewayProbeInput,
    "openclaw_doc_sync_check":      DocSyncCheckInput,
    "openclaw_channel_audit":       ChannelAuditInput,
    "firm_adr_generate":            AdrGenerateInput,
    # gateway_hardening (H2, M3, M4, M7, M8)
    "openclaw_gateway_auth_check":        GatewayAuthCheckInput,
    "openclaw_credentials_check":         CredentialsCheckInput,
    "openclaw_webhook_sig_check":         WebhookSigCheckInput,
    "openclaw_log_config_check":          LogConfigCheckInput,
    "openclaw_workspace_integrity_check": WorkspaceIntegrityCheckInput,
    # runtime_audit (C5, C6, H9, H10, H11, M15, M16)
    "openclaw_node_version_check":        NodeVersionCheckInput,
    "openclaw_secrets_workflow_check":    SecretsWorkflowCheckInput,
    "openclaw_http_headers_check":        HttpHeadersCheckInput,
    "openclaw_nodes_commands_check":      NodesCommandsCheckInput,
    "openclaw_trusted_proxy_check":       TrustedProxyCheckInput,
    "openclaw_session_disk_budget_check": SessionDiskBudgetCheckInput,
    "openclaw_dm_allowlist_check":        DmAllowlistCheckInput,
    # advanced_security (C7, C8, C9, H12, H13, H14, H15, H16)
    "openclaw_secrets_lifecycle_check":       SecretsLifecycleCheckInput,
    "openclaw_channel_auth_canon_check":      ChannelAuthCanonCheckInput,
    "openclaw_exec_approval_freeze_check":    ExecApprovalFreezeCheckInput,
    "openclaw_hook_session_routing_check":    HookSessionRoutingCheckInput,
    "openclaw_config_include_check":          ConfigIncludeCheckInput,
    "openclaw_config_prototype_check":        ConfigPrototypeCheckInput,
    "openclaw_safe_bins_profile_check":       SafeBinsProfileCheckInput,
    "openclaw_group_policy_default_check":    GroupPolicyDefaultCheckInput,
    # config_migration (H17, H18, H19, M17, M21)
    "openclaw_shell_env_check":              ShellEnvCheckInput,
    "openclaw_plugin_integrity_check":       PluginIntegrityCheckInput,
    "openclaw_token_separation_check":       TokenSeparationCheckInput,
    "openclaw_otel_redaction_check":         OtelRedactionCheckInput,
    "openclaw_rpc_rate_limit_check":         RpcRateLimitCheckInput,
    # observability (T1, T6)
    "openclaw_observability_pipeline":          ObservabilityPipelineInput,
    "openclaw_ci_pipeline_check":               CiPipelineCheckInput,
    # memory_audit (T3, T9)
    "openclaw_pgvector_memory_check":            PgvectorMemoryCheckInput,
    "openclaw_knowledge_graph_check":            KnowledgeGraphCheckInput,
    # hebbian_memory
    "openclaw_hebbian_harvest":                  HebbianHarvestInput,
    "openclaw_hebbian_weight_update":            HebbianWeightUpdateInput,
    "openclaw_hebbian_analyze":                  HebbianAnalyzeInput,
    "openclaw_hebbian_status":                   HebbianStatusInput,
    "openclaw_hebbian_layer_validate":           HebbianLayerValidateInput,
    "openclaw_hebbian_pii_check":                HebbianPiiCheckInput,
    "openclaw_hebbian_decay_config_check":       HebbianDecayConfigCheckInput,
    "openclaw_hebbian_drift_check":              HebbianDriftCheckInput,
    # agent_orchestration (T4)
    "openclaw_agent_team_orchestrate":           AgentTeamOrchestrateInput,
    "openclaw_agent_team_status":                AgentTeamStatusInput,
    # i18n_audit (T5)
    "openclaw_i18n_audit":                       I18nAuditInput,
    # skill_loader (T7)
    "openclaw_skill_lazy_loader":                SkillLazyLoaderInput,
    "openclaw_skill_search":                     SkillSearchInput,
    # n8n_bridge (T8)
    "openclaw_n8n_workflow_export":              N8nWorkflowExportInput,
    "openclaw_n8n_workflow_import":              N8nWorkflowImportInput,
    # browser_audit (T10)
    "openclaw_browser_context_check":            BrowserContextCheckInput,
}
