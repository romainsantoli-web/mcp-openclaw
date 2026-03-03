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


class AcpxVersionCheckInput(ConfigPathInput):
    """ACPX plugin version pin and streaming mode check (2026.3.1)."""
    pass


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
    check_health_endpoints: bool = Field(default=True, description="Also probe HTTP health endpoints (2026.3.1)")

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
# a2a_bridge — 8 tools (G1-G8)
# ════════════════════════════════════════════════════════════

class A2aCardGenerateInput(BaseModel):
    """Generate an A2A Agent Card from a SOUL.md file (RC v1.0)."""
    soul_path: Annotated[str, Field(min_length=1, max_length=4096)]
    base_url: Annotated[str, Field(min_length=7, max_length=2048)]
    output_path: str | None = Field(default=None, max_length=4096)
    capabilities: dict[str, bool] | None = None
    security_schemes: dict[str, Any] | None = None
    extensions: list[dict[str, Any]] | None = None
    sign: bool = False
    signing_key: str | None = Field(default=None, max_length=512)
    default_input_modes: list[str] | None = None
    default_output_modes: list[str] | None = None

    @field_validator("soul_path")
    @classmethod
    def no_traversal_soul(cls, v):
        return _check_no_traversal(v, "soul_path")

    @field_validator("output_path")
    @classmethod
    def no_traversal_output(cls, v):
        return _check_no_traversal(v, "output_path")


class A2aCardValidateInput(BaseModel):
    """Validate an Agent Card against A2A v1.0 RC spec."""
    card_path: str | None = Field(default=None, max_length=4096)
    card_json: dict[str, Any] | None = None

    @field_validator("card_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "card_path")

    @model_validator(mode="after")
    def at_least_one_source(self):
        if not self.card_path and not self.card_json:
            raise ValueError("Provide either card_path or card_json")
        return self


class A2aTaskSendInput(BaseModel):
    """Send a message/task to an A2A agent."""
    agent_url: Annotated[str, Field(min_length=7, max_length=2048)]
    message: Annotated[str, Field(min_length=1, max_length=65536)]
    context_id: str | None = Field(default=None, max_length=256, pattern=_SESSION_ID_PATTERN)
    blocking: bool = False
    metadata: dict[str, Any] | None = None


class A2aTaskStatusInput(BaseModel):
    """Get A2A task status or list tasks."""
    task_id: str | None = Field(default=None, max_length=256)
    context_id: str | None = Field(default=None, max_length=256)
    include_history: bool = False


class A2aPushConfigInput(BaseModel):
    """CRUD for A2A push notification webhook configs."""
    task_id: Annotated[str, Field(min_length=1, max_length=256)]
    action: str = Field(default="list", pattern=r"^(create|get|list|delete)$")
    webhook_url: str | None = Field(default=None, max_length=2048)
    auth_token: str | None = Field(default=None, max_length=512)
    config_id: str | None = Field(default=None, max_length=128)


class A2aCancelTaskInput(BaseModel):
    """Cancel a running A2A task (RC v1.0 CancelTask)."""
    task_id: Annotated[str, Field(min_length=1, max_length=256)]


class A2aSubscribeTaskInput(BaseModel):
    """Subscribe to A2A task updates via SSE (RC v1.0 SubscribeToTask)."""
    task_id: Annotated[str, Field(min_length=1, max_length=256)]
    callback_url: str | None = Field(default=None, max_length=2048)


class A2aDiscoveryInput(BaseModel):
    """Discover A2A agents via Agent Cards or local SOUL.md scan."""
    urls: list[str] | None = Field(default=None, max_length=50)
    souls_dir: str | None = Field(default=None, max_length=4096)
    check_reachability: bool = False

    @field_validator("souls_dir")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "souls_dir")


# ════════════════════════════════════════════════════════════
# platform_audit — 8 tools (G12-G20)
# ════════════════════════════════════════════════════════════

class SecretsV2AuditInput(ConfigPathInput):
    """Audit Firm secrets v2 lifecycle."""
    secrets_config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("secrets_config_path")
    @classmethod
    def no_traversal_secrets(cls, v):
        return _check_no_traversal(v, "secrets_config_path")


class AgentRoutingCheckInput(ConfigPathInput):
    """Validate agent routing bindings."""
    pass


class VoiceSecurityCheckInput(ConfigPathInput):
    """TTS/voice channel security audit."""
    pass


class TrustModelCheckInput(ConfigPathInput):
    """Multi-user trust model validation."""
    pass


class AutoupdateCheckInput(ConfigPathInput):
    """Auto-updater supply chain check."""
    pass


class PluginSdkCheckInput(ConfigPathInput):
    """Plugin SDK integrity validation."""
    pass


class ContentBoundaryCheckInput(ConfigPathInput):
    """Content boundary anti-prompt-injection audit."""
    pass


class SqliteVecCheckInput(ConfigPathInput):
    """SQLite-vec memory backend validation."""
    pass


class AdaptiveThinkingCheckInput(ConfigPathInput):
    """Claude 4.6 adaptive thinking configuration check (2026.3.1)."""
    pass


# ════════════════════════════════════════════════════════════
# ecosystem_audit — 7 tools (G21-G27)
# ════════════════════════════════════════════════════════════

class McpFirewallCheckInput(ConfigPathInput):
    """MCP Gateway firewall policy audit."""
    pass


class RagPipelineCheckInput(ConfigPathInput):
    """RAG pipeline health & configuration audit."""
    pass


class SandboxExecCheckInput(ConfigPathInput):
    """Sandbox execution isolation audit."""
    pass


class ContextHealthCheckInput(BaseModel):
    """Context rot / cognitive health detection."""
    session_data: dict[str, Any] | None = None
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class ProvenanceTrackerInput(BaseModel):
    """Cryptographic audit trail / provenance tracking."""
    action: str = Field(default="status", pattern=r"^(append|verify|status|export)$")
    entry: dict[str, Any] | None = None
    chain_path: str | None = Field(default=None, max_length=4096)
    algorithm: str = Field(default="sha256", pattern=r"^(sha256|sha384|sha512)$")

    @field_validator("chain_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "chain_path")


class CostAnalyticsInput(BaseModel):
    """Usage/cost tracking and analysis."""
    session_data: dict[str, Any] | None = None
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class TokenBudgetOptimizerInput(BaseModel):
    """Token optimization analysis."""
    session_data: dict[str, Any] | None = None
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


# ════════════════════════════════════════════════════════════
# spec_compliance models (S4, S5, S6, H3, H5, H6, H7)
# ════════════════════════════════════════════════════════════

class ElicitationAuditInput(BaseModel):
    """MCP elicitation capability audit."""
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class TasksAuditInput(BaseModel):
    """MCP Tasks (durable requests) audit."""
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class ResourcesPromptsAuditInput(BaseModel):
    """MCP Resources & Prompts capability audit."""
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class AudioContentAuditInput(BaseModel):
    """MCP audio content support audit."""
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class JsonSchemaDialectCheckInput(BaseModel):
    """JSON Schema 2020-12 dialect compliance check."""
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class SseTransportAuditInput(BaseModel):
    """SSE / Streamable HTTP transport compliance audit."""
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class IconMetadataAuditInput(BaseModel):
    """Icon metadata support audit."""
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


# ════════════════════════════════════════════════════════════
# prompt_security models (H2)
# ════════════════════════════════════════════════════════════

class PromptInjectionCheckInput(BaseModel):
    """Prompt injection detection scan."""
    text: str = Field(..., min_length=1, max_length=100000)
    context: str = Field(default="user_input", max_length=256)


class PromptInjectionBatchInput(BaseModel):
    """Batch prompt injection scan."""
    items: list[dict[str, str]] = Field(..., min_length=1, max_length=100)


# ════════════════════════════════════════════════════════════
# auth_compliance models (H4)
# ════════════════════════════════════════════════════════════

class OAuthOidcAuditInput(BaseModel):
    """OAuth/OIDC compliance audit."""
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


class TokenScopeCheckInput(BaseModel):
    """Token scope enforcement check."""
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "config_path")


# ════════════════════════════════════════════════════════════
# compliance_medium models (M1–M6)
# ════════════════════════════════════════════════════════════

class ToolDeprecationAuditInput(ConfigPathInput):
    """Tool deprecation lifecycle audit."""
    pass


class CircuitBreakerAuditInput(ConfigPathInput):
    """Circuit breaker / resilience pattern audit."""
    pass


class GdprResidencyAuditInput(ConfigPathInput):
    """GDPR and data residency compliance audit."""
    pass


class AgentIdentityAuditInput(ConfigPathInput):
    """Agent identity / DID audit."""
    pass


class ModelRoutingAuditInput(ConfigPathInput):
    """Multi-model routing configuration audit."""
    pass


class ResourceLinksAuditInput(ConfigPathInput):
    """Resource links in tool results audit."""
    pass


# ════════════════════════════════════════════════════════════
# market_research — 6 tools
# ════════════════════════════════════════════════════════════

_VALID_SIZING_APPROACHES = {"top_down", "bottom_up", "both"}
_VALID_MONITOR_ACTIONS = {"add", "remove", "update", "status", "export"}
_VALID_REPORT_LANGUAGES = {"fr", "en"}


class MarketCompetitiveAnalysisInput(BaseModel):
    """Competitive landscape analysis with feature matrix, SWOT, positioning."""
    sector: Annotated[str, Field(min_length=1, max_length=512)]
    competitors: list[str] | None = Field(default=None, max_length=50)
    geography: str | None = Field(default=None, max_length=256)
    criteria: list[str] | None = Field(default=None, max_length=30)
    include_swot: bool = True
    include_positioning: bool = True
    our_product: str | None = Field(default=None, max_length=256)


class MarketSizingInput(BaseModel):
    """TAM/SAM/SOM market sizing."""
    sector: Annotated[str, Field(min_length=1, max_length=512)]
    geography: str | None = Field(default=None, max_length=256)
    target_segment: str | None = Field(default=None, max_length=256)
    horizon_years: int = Field(default=5, ge=1, le=20)
    known_data: dict[str, Any] | None = None
    approach: str = Field(default="both")

    @field_validator("approach")
    @classmethod
    def valid_approach(cls, v: str) -> str:
        if v not in _VALID_SIZING_APPROACHES:
            raise ValueError(f"approach must be one of {_VALID_SIZING_APPROACHES}")
        return v


class MarketFinancialBenchmarkInput(BaseModel):
    """Financial benchmarking — unit economics, pricing, revenue."""
    sector: Annotated[str, Field(min_length=1, max_length=512)]
    metrics: list[str] | None = Field(default=None, max_length=20)
    competitors: list[str] | None = Field(default=None, max_length=50)
    our_data: dict[str, Any] | None = None
    include_pricing: bool = True


class MarketWebResearchInput(BaseModel):
    """Structured web research & OSINT."""
    query: Annotated[str, Field(min_length=1, max_length=2048)]
    sources: list[str] | None = Field(default=None, max_length=20)
    competitor: str | None = Field(default=None, max_length=256)
    max_results: int = Field(default=10, ge=1, le=100)


class MarketReportGenerateInput(BaseModel):
    """Professional market research report generator."""
    title: Annotated[str, Field(min_length=1, max_length=512)]
    sections: list[str] | None = Field(default=None, max_length=20)
    data: dict[str, Any] | None = None
    output_path: str | None = Field(default=None, max_length=4096)
    language: str = Field(default="fr")
    include_toc: bool = True

    @field_validator("output_path")
    @classmethod
    def no_traversal(cls, v):
        return _check_no_traversal(v, "output_path")

    @field_validator("language")
    @classmethod
    def valid_language(cls, v: str) -> str:
        if v not in _VALID_REPORT_LANGUAGES:
            raise ValueError(f"language must be one of {_VALID_REPORT_LANGUAGES}")
        return v


class MarketResearchMonitorInput(BaseModel):
    """Competitive monitoring — add/remove/update/status/export."""
    action: str = Field(default="status")
    competitor: str | None = Field(default=None, max_length=256)
    watch: list[str] | None = Field(default=None, max_length=20)
    notes: str | None = Field(default=None, max_length=4096)

    @field_validator("action")
    @classmethod
    def valid_action(cls, v: str) -> str:
        if v not in _VALID_MONITOR_ACTIONS:
            raise ValueError(f"action must be one of {_VALID_MONITOR_ACTIONS}")
        return v


# ════════════════════════════════════════════════════════════
# legal_status — 5 tools
# ════════════════════════════════════════════════════════════

_VALID_LEGAL_FORMS = {"SAS", "SASU", "SARL", "EURL", "SA", "MICRO", "SCI"}
_VALID_SOCIAL_STATUSES = {"TNS", "assimile_salarie", "TNS_micro"}


class LegalStatusCompareInput(BaseModel):
    """Compare legal forms with multi-criteria scoring."""
    project_type: str = Field(default="startup", max_length=128)
    founders: int = Field(default=1, ge=1, le=100)
    revenue_y1: float = Field(default=0, ge=0)
    fundraising: bool = False
    sector: str = Field(default="tech", max_length=256)
    criteria_weights: dict[str, Any] | None = None


class LegalTaxSimulateInput(BaseModel):
    """Tax simulation IS vs IR over multiple years."""
    legal_form: str = Field(default="SAS", max_length=10)
    revenue: float = Field(default=100000, ge=0)
    salary: float = Field(default=0, ge=0)
    dividends: float = Field(default=0, ge=0)
    horizon_years: int = Field(default=3, ge=1, le=10)
    growth_rate: float = Field(default=0.1, ge=0, le=2.0)
    holding: bool = False

    @field_validator("legal_form")
    @classmethod
    def valid_legal_form(cls, v: str) -> str:
        if v not in _VALID_LEGAL_FORMS:
            raise ValueError(f"legal_form must be one of {_VALID_LEGAL_FORMS}")
        return v


class LegalSocialProtectionInput(BaseModel):
    """Social protection analysis by status."""
    status: str = Field(default="assimile_salarie", max_length=64)
    salary: float = Field(default=50000, ge=0)
    include_options: bool = True

    @field_validator("status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        if v not in _VALID_SOCIAL_STATUSES:
            raise ValueError(f"status must be one of {_VALID_SOCIAL_STATUSES}")
        return v


class LegalGovernanceAuditInput(BaseModel):
    """Governance structure audit."""
    legal_form: str = Field(default="SAS", max_length=10)
    founders: int = Field(default=2, ge=1, le=100)
    has_investors: bool = False
    specific_clauses: list[str] | None = Field(default=None, max_length=20)

    @field_validator("legal_form")
    @classmethod
    def valid_legal_form(cls, v: str) -> str:
        if v not in _VALID_LEGAL_FORMS:
            raise ValueError(f"legal_form must be one of {_VALID_LEGAL_FORMS}")
        return v


class LegalCreationChecklistInput(BaseModel):
    """Post-creation compliance checklist."""
    legal_form: str = Field(default="SAS", max_length=10)
    sector: str = Field(default="tech", max_length=256)
    geography: str = Field(default="France", max_length=256)

    @field_validator("legal_form")
    @classmethod
    def valid_legal_form(cls, v: str) -> str:
        if v not in _VALID_LEGAL_FORMS:
            raise ValueError(f"legal_form must be one of {_VALID_LEGAL_FORMS}")
        return v


# ════════════════════════════════════════════════════════════
# location_strategy — 5 tools
# ════════════════════════════════════════════════════════════

_VALID_PROPERTY_TYPES = {"bureau", "coworking", "entrepot", "commerce", "mixte", "atelier", "terrain"}


class LocationGeoAnalysisInput(BaseModel):
    """Geo-economic analysis of candidate cities."""
    cities: list[str] = Field(min_length=1, max_length=20)
    sector: str = Field(default="tech", max_length=256)
    headcount: int = Field(default=10, ge=1, le=100000)
    priorities: list[str] | None = Field(default=None, max_length=10)


class LocationRealEstateInput(BaseModel):
    """Real estate market intelligence."""
    zone: str = Field(default="Île-de-France", max_length=512)
    property_type: str = Field(default="bureau", max_length=64)
    surface_min: int = Field(default=100, ge=1, le=100000)
    surface_max: int | None = Field(default=None, ge=1, le=100000)
    budget_max: float | None = Field(default=None, ge=0)

    @field_validator("property_type")
    @classmethod
    def valid_property_type(cls, v: str) -> str:
        if v not in _VALID_PROPERTY_TYPES:
            raise ValueError(f"property_type must be one of {_VALID_PROPERTY_TYPES}")
        return v


class LocationSiteScoreInput(BaseModel):
    """Multi-criteria site scoring."""
    sites: list[str] = Field(min_length=1, max_length=20)
    scores: dict[str, Any] | None = None
    weights: dict[str, Any] | None = None


class LocationIncentivesInput(BaseModel):
    """Tax incentives and aid programs by territory."""
    zone: str = Field(default="", max_length=512)
    company_type: str = Field(default="startup", max_length=64)
    headcount: int = Field(default=10, ge=1, le=100000)
    sector: str = Field(default="tech", max_length=256)


class LocationTcoSimulateInput(BaseModel):
    """Total Cost of Occupation simulation."""
    sites: list[str] = Field(min_length=1, max_length=20)
    surface: int = Field(default=200, ge=1, le=100000)
    horizon_years: int = Field(default=3, ge=1, le=10)
    headcount: int = Field(default=10, ge=1, le=100000)
    annual_rent_increase: float = Field(default=0.03, ge=0, le=0.5)


# ════════════════════════════════════════════════════════════
# supplier_management — 5 tools
# ════════════════════════════════════════════════════════════

_VALID_SUPPLIER_CATEGORIES = {"saas", "cloud", "services", "hardware", "office", "logistics", "raw_materials", "marketing", "consulting", "telecom", "insurance", "accounting"}
_VALID_SUPPLIER_MONITOR_ACTIONS = {"add", "remove", "update", "status", "export"}


class SupplierSearchInput(BaseModel):
    """Market-wide supplier sourcing."""
    category: str = Field(default="saas", max_length=64)
    query: str = Field(default="", max_length=2048)
    budget_max: float | None = Field(default=None, ge=0)
    users: int | None = Field(default=None, ge=1, le=1000000)
    geography: str = Field(default="France", max_length=256)
    requirements: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("category")
    @classmethod
    def valid_category(cls, v: str) -> str:
        if v not in _VALID_SUPPLIER_CATEGORIES:
            raise ValueError(f"category must be one of {_VALID_SUPPLIER_CATEGORIES}")
        return v


class SupplierEvaluateInput(BaseModel):
    """Multi-criteria supplier evaluation."""
    suppliers: list[str] = Field(min_length=1, max_length=20)
    scores: dict[str, Any] | None = None
    criteria: dict[str, Any] | None = None


class SupplierTcoAnalyzeInput(BaseModel):
    """Total Cost of Ownership analysis."""
    suppliers: list[str] = Field(min_length=1, max_length=20)
    volume: int = Field(default=1, ge=1, le=1000000)
    horizon_years: int = Field(default=3, ge=1, le=10)
    unit_prices: dict[str, Any] | None = None
    include_hidden_costs: bool = True


class SupplierContractCheckInput(BaseModel):
    """Contract clause analysis."""
    supplier: str = Field(default="", max_length=256)
    contract_type: str = Field(default="SaaS", max_length=64)
    requirements: list[str] = Field(default_factory=list, max_length=20)
    existing_clauses: list[str] = Field(default_factory=list, max_length=30)


class SupplierRiskMonitorInput(BaseModel):
    """Supplier risk monitoring CRUD."""
    action: str = Field(default="status")
    supplier: str = Field(default="", max_length=256)
    watch: list[str] | None = Field(default=None, max_length=10)
    notes: str | None = Field(default=None, max_length=4096)

    @field_validator("action")
    @classmethod
    def valid_action(cls, v: str) -> str:
        if v not in _VALID_SUPPLIER_MONITOR_ACTIONS:
            raise ValueError(f"action must be one of {_VALID_SUPPLIER_MONITOR_ACTIONS}")
        return v


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
    "firm_security_scan":       SecurityScanInput,
    "firm_sandbox_audit":       SandboxAuditInput,
    "firm_session_config_check": SessionConfigCheckInput,
    "firm_rate_limit_check":    RateLimitCheckInput,
    # acp_bridge (C4, H3, H4, H5)
    "acp_session_persist":          AcpSessionPersistInput,
    "acp_session_restore":          AcpSessionRestoreInput,
    "acp_session_list_active":      AcpSessionListActiveInput,
    "fleet_session_inject_env":     FleetSessionInjectEnvInput,
    "fleet_cron_schedule":          FleetCronScheduleInput,
    "firm_workspace_lock":      WorkspaceLockInput,
    "firm_acpx_version_check":   AcpxVersionCheckInput,
    # reliability_probe (H6, H7, M1, M5, M6)
    "firm_gateway_probe":       GatewayProbeInput,
    "firm_doc_sync_check":      DocSyncCheckInput,
    "firm_channel_audit":       ChannelAuditInput,
    "firm_adr_generate":            AdrGenerateInput,
    # gateway_hardening (H2, M3, M4, M7, M8)
    "firm_gateway_auth_check":        GatewayAuthCheckInput,
    "firm_credentials_check":         CredentialsCheckInput,
    "firm_webhook_sig_check":         WebhookSigCheckInput,
    "firm_log_config_check":          LogConfigCheckInput,
    "firm_workspace_integrity_check": WorkspaceIntegrityCheckInput,
    # runtime_audit (C5, C6, H9, H10, H11, M15, M16)
    "firm_node_version_check":        NodeVersionCheckInput,
    "firm_secrets_workflow_check":    SecretsWorkflowCheckInput,
    "firm_http_headers_check":        HttpHeadersCheckInput,
    "firm_nodes_commands_check":      NodesCommandsCheckInput,
    "firm_trusted_proxy_check":       TrustedProxyCheckInput,
    "firm_session_disk_budget_check": SessionDiskBudgetCheckInput,
    "firm_dm_allowlist_check":        DmAllowlistCheckInput,
    # advanced_security (C7, C8, C9, H12, H13, H14, H15, H16)
    "firm_secrets_lifecycle_check":       SecretsLifecycleCheckInput,
    "firm_channel_auth_canon_check":      ChannelAuthCanonCheckInput,
    "firm_exec_approval_freeze_check":    ExecApprovalFreezeCheckInput,
    "firm_hook_session_routing_check":    HookSessionRoutingCheckInput,
    "firm_config_include_check":          ConfigIncludeCheckInput,
    "firm_config_prototype_check":        ConfigPrototypeCheckInput,
    "firm_safe_bins_profile_check":       SafeBinsProfileCheckInput,
    "firm_group_policy_default_check":    GroupPolicyDefaultCheckInput,
    # config_migration (H17, H18, H19, M17, M21)
    "firm_shell_env_check":              ShellEnvCheckInput,
    "firm_plugin_integrity_check":       PluginIntegrityCheckInput,
    "firm_token_separation_check":       TokenSeparationCheckInput,
    "firm_otel_redaction_check":         OtelRedactionCheckInput,
    "firm_rpc_rate_limit_check":         RpcRateLimitCheckInput,
    # observability (T1, T6)
    "firm_observability_pipeline":          ObservabilityPipelineInput,
    "firm_ci_pipeline_check":               CiPipelineCheckInput,
    # memory_audit (T3, T9)
    "firm_pgvector_memory_check":            PgvectorMemoryCheckInput,
    "firm_knowledge_graph_check":            KnowledgeGraphCheckInput,
    # hebbian_memory
    "firm_hebbian_harvest":                  HebbianHarvestInput,
    "firm_hebbian_weight_update":            HebbianWeightUpdateInput,
    "firm_hebbian_analyze":                  HebbianAnalyzeInput,
    "firm_hebbian_status":                   HebbianStatusInput,
    "firm_hebbian_layer_validate":           HebbianLayerValidateInput,
    "firm_hebbian_pii_check":                HebbianPiiCheckInput,
    "firm_hebbian_decay_config_check":       HebbianDecayConfigCheckInput,
    "firm_hebbian_drift_check":              HebbianDriftCheckInput,
    # agent_orchestration (T4)
    "firm_agent_team_orchestrate":           AgentTeamOrchestrateInput,
    "firm_agent_team_status":                AgentTeamStatusInput,
    # i18n_audit (T5)
    "firm_i18n_audit":                       I18nAuditInput,
    # skill_loader (T7)
    "firm_skill_lazy_loader":                SkillLazyLoaderInput,
    "firm_skill_search":                     SkillSearchInput,
    # n8n_bridge (T8)
    "firm_n8n_workflow_export":              N8nWorkflowExportInput,
    "firm_n8n_workflow_import":              N8nWorkflowImportInput,
    # browser_audit (T10)
    "firm_browser_context_check":            BrowserContextCheckInput,
    # a2a_bridge (G1-G8)
    "firm_a2a_card_generate":                A2aCardGenerateInput,
    "firm_a2a_card_validate":                A2aCardValidateInput,
    "firm_a2a_task_send":                    A2aTaskSendInput,
    "firm_a2a_task_status":                  A2aTaskStatusInput,
    "firm_a2a_cancel_task":                  A2aCancelTaskInput,
    "firm_a2a_subscribe_task":               A2aSubscribeTaskInput,
    "firm_a2a_push_config":                  A2aPushConfigInput,
    "firm_a2a_discovery":                    A2aDiscoveryInput,
    # platform_audit (G12-G20)
    "firm_secrets_v2_audit":                 SecretsV2AuditInput,
    "firm_agent_routing_check":              AgentRoutingCheckInput,
    "firm_voice_security_check":             VoiceSecurityCheckInput,
    "firm_trust_model_check":                TrustModelCheckInput,
    "firm_autoupdate_check":                 AutoupdateCheckInput,
    "firm_plugin_sdk_check":                 PluginSdkCheckInput,
    "firm_content_boundary_check":           ContentBoundaryCheckInput,
    "firm_sqlite_vec_check":                 SqliteVecCheckInput,
    "firm_adaptive_thinking_check":            AdaptiveThinkingCheckInput,
    # ecosystem_audit (G21-G27)
    "firm_mcp_firewall_check":               McpFirewallCheckInput,
    "firm_rag_pipeline_check":               RagPipelineCheckInput,
    "firm_sandbox_exec_check":               SandboxExecCheckInput,
    "firm_context_health_check":             ContextHealthCheckInput,
    "firm_provenance_tracker":               ProvenanceTrackerInput,
    "firm_cost_analytics":                   CostAnalyticsInput,
    "firm_token_budget_optimizer":           TokenBudgetOptimizerInput,
    # spec_compliance (S4, S5, S6, H3, H5, H6, H7)
    "firm_elicitation_audit":                ElicitationAuditInput,
    "firm_tasks_audit":                      TasksAuditInput,
    "firm_resources_prompts_audit":           ResourcesPromptsAuditInput,
    "firm_audio_content_audit":              AudioContentAuditInput,
    "firm_json_schema_dialect_check":        JsonSchemaDialectCheckInput,
    "firm_sse_transport_audit":              SseTransportAuditInput,
    "firm_icon_metadata_audit":              IconMetadataAuditInput,
    # prompt_security (H2)
    "firm_prompt_injection_check":           PromptInjectionCheckInput,
    "firm_prompt_injection_batch":           PromptInjectionBatchInput,
    # auth_compliance (H4)
    "firm_oauth_oidc_audit":                 OAuthOidcAuditInput,
    "firm_token_scope_check":                TokenScopeCheckInput,
    # compliance_medium (M1–M6)
    "firm_tool_deprecation_audit":           ToolDeprecationAuditInput,
    "firm_circuit_breaker_audit":            CircuitBreakerAuditInput,
    "firm_gdpr_residency_audit":             GdprResidencyAuditInput,
    "firm_agent_identity_audit":             AgentIdentityAuditInput,
    "firm_model_routing_audit":              ModelRoutingAuditInput,
    "firm_resource_links_audit":             ResourceLinksAuditInput,
    # market_research (6 tools)
    "firm_market_competitive_analysis":       MarketCompetitiveAnalysisInput,
    "firm_market_sizing":                     MarketSizingInput,
    "firm_market_financial_benchmark":         MarketFinancialBenchmarkInput,
    "firm_market_web_research":                MarketWebResearchInput,
    "firm_market_report_generate":             MarketReportGenerateInput,
    "firm_market_research_monitor":            MarketResearchMonitorInput,
    # legal_status (5 tools)
    "firm_legal_status_compare":              LegalStatusCompareInput,
    "firm_legal_tax_simulate":                LegalTaxSimulateInput,
    "firm_legal_social_protection":           LegalSocialProtectionInput,
    "firm_legal_governance_audit":            LegalGovernanceAuditInput,
    "firm_legal_creation_checklist":          LegalCreationChecklistInput,
    # location_strategy (5 tools)
    "firm_location_geo_analysis":             LocationGeoAnalysisInput,
    "firm_location_real_estate":              LocationRealEstateInput,
    "firm_location_site_score":               LocationSiteScoreInput,
    "firm_location_incentives":               LocationIncentivesInput,
    "firm_location_tco_simulate":             LocationTcoSimulateInput,
    # supplier_management (5 tools)
    "firm_supplier_search":                   SupplierSearchInput,
    "firm_supplier_evaluate":                 SupplierEvaluateInput,
    "firm_supplier_tco_analyze":              SupplierTcoAnalyzeInput,
    "firm_supplier_contract_check":           SupplierContractCheckInput,
    "firm_supplier_risk_monitor":             SupplierRiskMonitorInput,
}
