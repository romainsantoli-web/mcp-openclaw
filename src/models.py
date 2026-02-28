"""
models.py — Pydantic v2 input models for all 16 MCP tools.

Validated in main.py before dispatching to handlers.
ValidationError is caught and returned as a structured tool error.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field, field_validator, model_validator


# ════════════════════════════════════════════════════════════
# vs_bridge — 4 tools
# ════════════════════════════════════════════════════════════

class VsContextPushInput(BaseModel):
    session_id: Annotated[str, Field(min_length=1, max_length=256)]
    workspace_path: Annotated[str, Field(min_length=1, max_length=4096)]
    open_files: list[str] = Field(default_factory=list, max_length=200)
    active_file: str | None = None
    selection: str | None = Field(default=None, max_length=16_384)
    diagnostics: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    language_id: str | None = Field(default=None, max_length=64)
    metadata: dict[str, Any] | None = None

    @field_validator("session_id")
    @classmethod
    def no_newlines(cls, v: str) -> str:
        if "\n" in v or "\r" in v:
            raise ValueError("session_id must not contain newlines")
        return v


class VsContextPullInput(BaseModel):
    session_id: Annotated[str, Field(min_length=1, max_length=256)]


class VsSessionLinkInput(BaseModel):
    workspace_path: Annotated[str, Field(min_length=1, max_length=4096)]
    session_id: Annotated[str, Field(min_length=1, max_length=256)]


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
    def no_path_traversal(cls, v: str | None) -> str | None:
        if v is not None and ".." in v:
            raise ValueError("output_path must not contain path traversal (..)")
        return v


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
    def no_traversal(cls, v: str) -> str:
        if ".." in v:
            raise ValueError("target_path must not contain path traversal (..)")
        return v


class SandboxAuditInput(BaseModel):
    config_path: Annotated[str, Field(min_length=1, max_length=4096)]

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str) -> str:
        if ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class SessionConfigCheckInput(BaseModel):
    env_file_path: str | None = Field(default=None, max_length=4096)
    compose_file_path: str | None = Field(default=None, max_length=4096)

    @field_validator("env_file_path", "compose_file_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v is not None and ".." in v:
            raise ValueError("Path must not contain path traversal (..)")
        return v


class RateLimitCheckInput(BaseModel):
    gateway_config_path: Annotated[str, Field(min_length=1, max_length=4096)]
    check_funnel: bool = True

    @field_validator("gateway_config_path")
    @classmethod
    def no_traversal(cls, v: str) -> str:
        if ".." in v:
            raise ValueError("gateway_config_path must not contain path traversal (..)")
        return v


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
    def no_traversal(cls, v: str) -> str:
        if ".." in v:
            raise ValueError("path must not contain path traversal (..)")
        return v


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
    def no_traversal(cls, v: str) -> str:
        if ".." in v:
            raise ValueError("package_json_path must not contain path traversal (..)")
        return v


class ChannelAuditInput(BaseModel):
    package_json_path: Annotated[str, Field(min_length=1, max_length=4096)]
    readme_path: Annotated[str, Field(min_length=1, max_length=4096)]

    @field_validator("package_json_path", "readme_path")
    @classmethod
    def no_traversal(cls, v: str) -> str:
        if ".." in v:
            raise ValueError("Path must not contain path traversal (..)")
        return v


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

class GatewayAuthCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class CredentialsCheckInput(BaseModel):
    credentials_dir: str | None = Field(default=None, max_length=4096)
    max_age_days: int = Field(default=30, ge=1, le=365)

    @field_validator("credentials_dir")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("credentials_dir must not contain path traversal (..)")
        return v


class WebhookSigCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)
    channel: str | None = Field(default=None, max_length=64)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class LogConfigCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class WorkspaceIntegrityCheckInput(BaseModel):
    workspace_dir: str | None = Field(default=None, max_length=4096)
    stale_days: int = Field(default=30, ge=1, le=365)

    @field_validator("workspace_dir")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("workspace_dir must not contain path traversal (..)")
        return v


# ════════════════════════════════════════════════════════════
# runtime_audit (C5, C6, H9, H10, H11, M15, M16)
# ════════════════════════════════════════════════════════════

class NodeVersionCheckInput(BaseModel):
    node_binary: str | None = Field(default=None, max_length=4096)

    @field_validator("node_binary")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("node_binary must not contain path traversal (..)")
        return v


class SecretsWorkflowCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class HttpHeadersCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class NodesCommandsCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class TrustedProxyCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class SessionDiskBudgetCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class DmAllowlistCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


# ════════════════════════════════════════════════════════════
# advanced_security (C7, C8, C9, H12, H13, H14, H15, H16)
# ════════════════════════════════════════════════════════════


class SecretsLifecycleCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class ChannelAuthCanonCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class ExecApprovalFreezeCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class HookSessionRoutingCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class ConfigIncludeCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class ConfigPrototypeCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class SafeBinsProfileCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class GroupPolicyDefaultCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


# ════════════════════════════════════════════════════════════
# config_migration (H17, H18, H19, M17, M21)
# ════════════════════════════════════════════════════════════


class ShellEnvCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class PluginIntegrityCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class TokenSeparationCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class OtelRedactionCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
        return v


class RpcRateLimitCheckInput(BaseModel):
    config_path: str | None = Field(default=None, max_length=4096)

    @field_validator("config_path")
    @classmethod
    def no_traversal(cls, v: str | None) -> str | None:
        if v and ".." in v:
            raise ValueError("config_path must not contain path traversal (..)")
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
}
