# Changelog

All notable changes to `mcp-openclaw-extensions` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.1] — 2026-03-04

### Fixed
- VS Code Copilot MCP tool schema validation failures by ensuring every `type: "array"` field declares `items` (notably `vs_context_push.recent_changes`, plus remaining output schemas in legal/location/supplier modules)
- Resolved Python stdlib shadowing issue by replacing `src/platform.py` with `src/platform_compat.py`

### Added
- `src/stdio_bridge.py`: official MCP SDK stdio bridge (`Server`, `stdio_server`) for Copilot/VS Code compatibility

### Changed
- Version bumped to **4.1.1**

## [3.3.0] — 2026-03-08

### Added — OpenClaw 2026.3.1 Alignment
- **P0 BREAKING** `systemRunPlan` check in `openclaw_exec_approval_freeze_check` — `tools.exec.host=node` with active approvals now requires systemRunPlan payload (advanced_security.py)
- **P0 BREAKING** Canonical path (realpath) validation in `openclaw_nodes_commands_check` — non-canonical (token-form) allowCommands entries flagged as CRITICAL (runtime_audit.py)
- **P1** HTTP health endpoint probing (`/health`, `/healthz`, `/ready`, `/readyz`) in `openclaw_gateway_probe` — new `check_health_endpoints` param + async `_check_health_endpoints` helper (reliability_probe.py)
- **P2** `requireTopic` Telegram DM check in `openclaw_dm_allowlist_check` — detects missing `channels.telegram.direct.requireTopic` and empty `topicAllowlist` (runtime_audit.py)
- **P2** New tool `openclaw_acpx_version_check` — validates ACPX plugin pin ≥0.1.15 and `final_only` streaming mode (acp_bridge.py)
- **P2** New tool `openclaw_adaptive_thinking_check` — detects Claude 4.6 models with disabled/low thinking mode, validates per-agent overrides (platform_audit.py)
- **P3** Discord thread lifecycle check in `openclaw_channel_audit` — flags missing `threads.idleHours` and `threads.maxAgeHours` (reliability_probe.py)
- **P3** `OPENCLAW_SHELL` env marker check in `openclaw_shell_env_check` — detects missing marker env var for 2026.3.1 managed-shell detection (config_migration.py)

### Changed
- Version bumped to **3.3.0** (main.py `__version__`)
- Pydantic models: `AcpxVersionCheckInput`, `AdaptiveThinkingCheckInput` added; `GatewayProbeInput.check_health_endpoints` field added
- `TOOL_MODELS` registry: 2 new entries for acpx + adaptive thinking
- Tool count: 136 → **138** total tools

### Fixed
- Pre-existing test import: `openclaw_a2a_subscribe` → `openclaw_a2a_subscribe_task` (test_cov_100f.py)
- Pre-existing test: push_config tests now populate `_TASKS` before asserting (test_cov_100f.py)

### Tests
- New `test_patch_3_1.py` — 30 tests covering all 8 patches (P0×2, P1×1, P2×3, P3×2 + Pydantic validations)
- All 1915 tests pass at 92% coverage (excluding integration tests requiring aiohttp fixture)

## [3.0.0] — 2026-03-07

### Added
- **MCP 2025-11-25 icons** on all 113 tools via category-based emoji mapping (M-C1)
- **`structuredContent`** in all tool call responses alongside `content` (M-C2)
- **Resources capability** with `resources/list` and `resources/read` (M-C3)
- **Prompts capability** with 4 audit prompt templates (M-H1)
- **`listChanged: True`** in tools capability for dynamic tool loading (M-H4)
- Centralized **SSRF guard** in `config_helpers.py` — `check_ssrf()` (I-H3)
- Centralized **path traversal guard** in `config_helpers.py` — `no_path_traversal()` (I-H4)
- `py.typed` marker for PEP 561 type stub support (I-M3)
- `__all__` exports in `src/__init__.py` (I-M2)
- A2A bridge upgraded to **RC v1.0** with new data model, extensions, SubscribeToTask
- Per-module test files with unit tests (T-C1)
- `conftest.py` with shared fixtures and filesystem mocks (T-H4)
- `pytest-cov` configuration with 80% threshold (T-H3)
- MCP **elicitation** support (M-H2)
- MCP **tasks / durable requests** support (M-H3)
- SSE **polling / resumption** (M-H6)
- `MCP-Protocol-Version` header enforcement (M-M1)
- **Resource links** in tool responses mapping tools to related resources (M-H5)
- New skills: `firm-spec-compliance-pack`, `firm-prompt-security-pack` (E-M2)

### Changed
- **BREAKING**: Version bumped to 3.0.0 — major protocol upgrades
- **BREAKING**: A2A bridge rewritten from v0.4.0 to RC v1.0 data model
- DRY refactor: `_load_config` removed from 6 modules, delegates to `config_helpers.load_config` (I-C1)
- Handler naming normalized: all 17 `handle_*` prefixes removed (I-H1)
- `serverInfo.description` updated to reflect full tool inventory (M-M4)
- Large modules split into sub-modules for maintainability (I-H2)

### Fixed
- `gateway_hardening` and `security_audit` now use shared config loading

## [2.2.0] — 2026-03-06

### Added
- MCP 2025-11-25 spec compliance: 20/20 items implemented
- 4 new modules: `spec_compliance.py`, `prompt_security.py`, `auth_compliance.py`, `compliance_medium.py`
- Title + annotations + outputSchema on all 113 tools
- A2A bridge aligned to v0.4.0

## [2.0.0] — 2026-03-05

### Added
- Phase 7 disruption: `a2a_bridge.py`, `platform_audit.py`, `ecosystem_audit.py`
- 21 new tools (A2A Protocol, platform alignment, ecosystem differentiation)
- `firm-a2a-bridge` SKILL.md published

## [1.0.0] — 2026-03-04

### Added
- Initial release: 67 tools across 17 modules
- Security audit, ACP bridge, reliability, gateway hardening
- Hebbian memory, agent orchestration, observability
- n8n workflow bridge, browser audit, i18n audit
- 160 smoke tests, all passing
