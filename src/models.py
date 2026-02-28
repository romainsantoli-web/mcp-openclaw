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
# Registry: tool name → Pydantic model class
# ════════════════════════════════════════════════════════════

TOOL_MODELS: dict[str, type[BaseModel]] = {
    # vs_bridge
    "vs_context_push":             VsContextPushInput,
    "vs_context_pull":             VsContextPullInput,
    "vs_session_link":             VsSessionLinkInput,
    "vs_session_status":           VsSessionStatusInput,
    # gateway_fleet
    "firm_gateway_fleet_status":   FleetStatusInput,
    "firm_gateway_fleet_add":      FleetAddInput,
    "firm_gateway_fleet_remove":   FleetRemoveInput,
    "firm_gateway_fleet_broadcast": FleetBroadcastInput,
    "firm_gateway_fleet_sync":     FleetSyncInput,
    "firm_gateway_fleet_list":     FleetListInput,
    # delivery_export
    "firm_export_github_pr":       ExportGithubPrInput,
    "firm_export_jira_ticket":     ExportJiraTicketInput,
    "firm_export_linear_issue":    ExportLinearIssueInput,
    "firm_export_slack_digest":    ExportSlackDigestInput,
    "firm_export_document":        ExportDocumentInput,
    "firm_export_auto":            ExportAutoInput,
}
