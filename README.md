# mcp-openclaw-extensions

> Python MCP server (port **8012**) that bridges VS Code Copilot agents to the
> [OpenClaw](https://github.com/openclaw/openclaw) Gateway ecosystem.
> Companion to [setup-vs-agent-firm](https://github.com/romainsantoli-web/setup-vs-agent-firm).

## Tools (115)

| Module | Tool | Description | Gaps |
|--------|------|-------------|------|
| vs_bridge | `vs_context_push` | Push VS Code context → OpenClaw session | — |
| vs_bridge | `vs_context_pull` | Pull OpenClaw session state → VS Code | — |
| vs_bridge | `vs_session_link` | Associate workspace path ↔ session ID | — |
| vs_bridge | `vs_session_status` | Bridge health check | — |
| gateway_fleet | `firm_gateway_fleet_status` | Parallel health-check all instances | — |
| gateway_fleet | `firm_gateway_fleet_add` | Register a Gateway instance | — |
| gateway_fleet | `firm_gateway_fleet_remove` | Remove a Gateway instance | — |
| gateway_fleet | `firm_gateway_fleet_broadcast` | Broadcast to all instances | — |
| gateway_fleet | `firm_gateway_fleet_sync` | Sync config+skills to all instances | — |
| gateway_fleet | `firm_gateway_fleet_list` | List instances | — |
| delivery_export | `firm_export_github_pr` | Create draft PR on GitHub | — |
| delivery_export | `firm_export_jira_ticket` | Create Jira ticket (ADF) | — |
| delivery_export | `firm_export_linear_issue` | Create Linear issue (GraphQL) | — |
| delivery_export | `firm_export_slack_digest` | Post Slack digest (Block Kit) | — |
| delivery_export | `firm_export_document` | Write local Markdown deliverable | — |
| delivery_export | `firm_export_auto` | Auto-route by `delivery_format` | — |
| security_audit | `openclaw_security_scan` | Scan files for SQL injection + XSS patterns | C1 |
| security_audit | `openclaw_sandbox_audit` | Detect `sandbox.mode: off` → CRITICAL | C2 |
| security_audit | `openclaw_session_config_check` | Detect ephemeral SESSION_SECRET in .env/compose | C3 |
| security_audit | `openclaw_rate_limit_check` | Detect Funnel without rate limiter → CRITICAL | H8 |
| acp_bridge | `acp_session_persist` | Persist ACP session to `~/.openclaw/acp_sessions.json` | C4 |
| acp_bridge | `acp_session_restore` | Restore persisted ACP session by run_id | C4 |
| acp_bridge | `acp_session_list_active` | List ACP sessions active in last N hours | C4 |
| acp_bridge | `fleet_session_inject_env` | Inject env vars to spawned sessions (allowlist) | H3 |
| acp_bridge | `fleet_cron_schedule` | Schedule cron with sandbox enforcement | H4 |
| acp_bridge | `openclaw_workspace_lock` | Advisory file lock with owner tracking (`fcntl`) | H5 |
| reliability_probe | `openclaw_gateway_probe` | WS probe with backoff — detects close 1006, returns `launchctl` | H6/H7 |
| reliability_probe | `openclaw_doc_sync_check` | Detect version drift in docs vs package.json | M5 |
| reliability_probe | `openclaw_channel_audit` | Detect zombie channel SDK deps (LINE, Baileys…) | M1 |
| reliability_probe | `firm_adr_generate` | Generate MADR + commit path for architecture decisions | M6 |
| gateway_hardening | `openclaw_gateway_auth_check` | Verify Gateway auth config — CRITICAL if Funnel without password | H2 |
| gateway_hardening | `openclaw_credentials_check` | Check Baileys/channel credential integrity and freshness | M3 |
| gateway_hardening | `openclaw_webhook_sig_check` | Verify HMAC signing secrets for all inbound webhook channels | M4 |
| gateway_hardening | `openclaw_log_config_check` | Detect debug/trace logging and missing redactPatterns | M7 |
| gateway_hardening | `openclaw_workspace_integrity_check` | Validate ~/.openclaw/workspace (AGENTS.md, SOUL.md, staleness) | M8 |
| runtime_audit | `openclaw_node_version_check` | Verify Node.js ≥ 22.12.0 (CVE-2025-59466, CVE-2026-21636) | C5 |
| runtime_audit | `openclaw_secrets_workflow_check` | Detect hardcoded secrets in openclaw.json (migrate to `openclaw secrets`) | C6 |
| runtime_audit | `openclaw_http_headers_check` | Verify HTTP security headers (HSTS, X-Content-Type-Options, Referrer-Policy) | H9 |
| runtime_audit | `openclaw_nodes_commands_check` | Detect dangerous gateway.nodes.allowCommands override | H10 |
| runtime_audit | `openclaw_trusted_proxy_check` | Verify trusted-proxy config coherence (bind + trustedProxies + auth mode) | H11 |
| runtime_audit | `openclaw_session_disk_budget_check` | Verify session.maintenance.maxDiskBytes / highWaterBytes configured | M15 |
| runtime_audit | `openclaw_dm_allowlist_check` | Detect dmPolicy=allowlist with empty allowFrom (fail-closed) across 9 channels | M16 |
| advanced_security | `openclaw_secrets_lifecycle_check` | Verify External Secrets lifecycle (audit/configure/apply/reload) | C7 |
| advanced_security | `openclaw_channel_auth_canon_check` | Verify channel auth path canonicalization (encoded traversal) | C8 |
| advanced_security | `openclaw_exec_approval_freeze_check` | Verify exec approval plan immutability (symlink cwd rebind) | C9 |
| advanced_security | `openclaw_hook_session_routing_check` | Verify hook session-key routing hardening | H12 |
| advanced_security | `openclaw_config_include_check` | Verify $include hardlink escape + file-size guardrails | H13 |
| advanced_security | `openclaw_config_prototype_check` | Detect prototype pollution (__proto__, constructor, prototype) in config | H14 |
| advanced_security | `openclaw_safe_bins_profile_check` | Verify safeBins entries have explicit profiles | H15 |
| advanced_security | `openclaw_group_policy_default_check` | Verify group policy default is fail-closed (allowlist) | H16 |
| config_migration | `openclaw_shell_env_check` | Verify shell env sanitization (LD_PRELOAD, DYLD_*, ZDOTDIR) | H17 |
| config_migration | `openclaw_plugin_integrity_check` | Verify plugin install integrity/pin + drift detection | H18 |
| config_migration | `openclaw_token_separation_check` | Verify hooks.token ≠ gateway.auth.token | H19 |
| config_migration | `openclaw_otel_redaction_check` | Verify OTEL secret redaction in diagnostics export | M17 |
| config_migration | `openclaw_rpc_rate_limit_check` | Verify control-plane RPC rate limiting config | M21 |
| observability | `openclaw_observability_pipeline` | Ingest JSONL traces into SQLite for offline analysis | T1 |
| observability | `openclaw_ci_pipeline_check` | Validate CI workflow completeness (lint, test, secrets) | T6 |
| memory_audit | `openclaw_pgvector_memory_check` | Verify pgvector config (HNSW index, dimensions, distance metrics) | T3 |
| memory_audit | `openclaw_knowledge_graph_check` | Audit knowledge graph integrity (orphan nodes, cycles, TTL) | T9 |
| agent_orchestration | `openclaw_agent_team_orchestrate` | Task DAG execution with topological sort + parallel layers | T4 |
| agent_orchestration | `openclaw_agent_team_status` | Check orchestration status by ID or list all | T4 |
| i18n_audit | `openclaw_i18n_audit` | Scan locale files for missing keys, empty values, interpolation mismatches | T5 |
| skill_loader | `openclaw_skill_lazy_loader` | Lazy-load SKILL.md metadata (YAML front-matter, 5min cache) | T7 |
| skill_loader | `openclaw_skill_search` | Keyword/tag search across cached skills with relevance scoring | T7 |
| n8n_bridge | `openclaw_n8n_workflow_export` | Export agent pipeline as n8n-compatible workflow JSON | T8 |
| n8n_bridge | `openclaw_n8n_workflow_import` | Validate & import n8n workflow JSON into workspace | T8 |
| browser_audit | `openclaw_browser_context_check` | Validate Playwright/Puppeteer headless config for agents | T10 |
| hebbian_memory | `openclaw_hebbian_harvest` | Ingest JSONL session logs → SQLite (PII stripped) — CDC §4.1 | — |
| hebbian_memory | `openclaw_hebbian_weight_update` | Compute/apply Hebbian weight updates on Layer 2 — CDC §4.3 | — |
| hebbian_memory | `openclaw_hebbian_analyze` | Co-activation pattern analysis (Jaccard similarity) — CDC §4.3 | — |
| hebbian_memory | `openclaw_hebbian_status` | Dashboard: weights, atrophy, promotions — CDC §7 | — |
| hebbian_memory | `openclaw_hebbian_layer_validate` | Validate 4-layer Claude.md structure — CDC §3.3 | — |
| hebbian_memory | `openclaw_hebbian_pii_check` | Audit PII stripping config — CDC §5.2 | — |
| hebbian_memory | `openclaw_hebbian_decay_config_check` | Validate learning rate, decay, thresholds — CDC §4.3 | — |
| hebbian_memory | `openclaw_hebbian_drift_check` | Cosine similarity drift detection vs baseline — CDC §5.1 | — |
| a2a_bridge | `openclaw_a2a_card_generate` | Generate agent-card.json from SOUL.md (RC v1.0) | G1 |
| a2a_bridge | `openclaw_a2a_card_validate` | Validate A2A Agent Card against RC v1.0 spec | G2 |
| a2a_bridge | `openclaw_a2a_task_send` | Send message/task to an A2A agent (SendMessage) | G3 |
| a2a_bridge | `openclaw_a2a_task_status` | Get task status or list tasks (RC v1.0) | G4 |
| a2a_bridge | `openclaw_a2a_cancel_task` | Cancel a running A2A task (CancelTask) | G5 |
| a2a_bridge | `openclaw_a2a_subscribe_task` | Subscribe to task updates via SSE | G6 |
| a2a_bridge | `openclaw_a2a_push_config` | CRUD for push notification webhooks (RC v1.0) | G7 |
| a2a_bridge | `openclaw_a2a_discovery` | Discover agents via Agent Cards or SOUL.md scan | G8 |
| platform_audit | `openclaw_secrets_v2_audit` | Audit OpenClaw secrets v2 lifecycle (2026.2+) | G9 |
| platform_audit | `openclaw_agent_routing_check` | Validate agent routing bindings | G10 |
| platform_audit | `openclaw_voice_security_check` | TTS/voice channel security audit | G11 |
| platform_audit | `openclaw_trust_model_check` | Validate trust model and multi-user heuristics | G12 |
| platform_audit | `openclaw_autoupdate_check` | Self-update supply chain integrity check | G13 |
| platform_audit | `openclaw_plugin_sdk_check` | Plugin SDK integrity validation | G14 |
| platform_audit | `openclaw_content_boundary_check` | Content boundary & anti-prompt-injection audit | G15 |
| platform_audit | `openclaw_sqlite_vec_check` | SQLite-vec memory backend validation | G16 |
| ecosystem_audit | `openclaw_mcp_firewall_check` | MCP Gateway firewall policy audit | G17 |
| ecosystem_audit | `openclaw_rag_pipeline_check` | RAG pipeline health & config audit | G18 |
| ecosystem_audit | `openclaw_sandbox_exec_check` | Sandbox execution isolation audit | G19 |
| ecosystem_audit | `openclaw_context_health_check` | Context rot / cognitive health detection | G20 |
| ecosystem_audit | `openclaw_provenance_tracker` | Cryptographic audit trail / provenance tracking | G21 |
| ecosystem_audit | `openclaw_cost_analytics` | Usage/cost tracking and analysis | G22 |
| ecosystem_audit | `openclaw_token_budget_optimizer` | Token optimization analysis | G23 |
| spec_compliance | `openclaw_elicitation_audit` | Audit MCP elicitation capability compliance | S4 |
| spec_compliance | `openclaw_tasks_audit` | Audit MCP Tasks capability compliance | S5 |
| spec_compliance | `openclaw_resources_prompts_audit` | Audit MCP Resources & Prompts compliance | S6 |
| spec_compliance | `openclaw_audio_content_audit` | Audit MCP audio content support | H3 |
| spec_compliance | `openclaw_json_schema_dialect_check` | Audit JSON Schema dialect compliance | H5 |
| spec_compliance | `openclaw_sse_transport_audit` | Audit Streamable HTTP / SSE transport | H6 |
| spec_compliance | `openclaw_icon_metadata_audit` | Audit icon metadata support | H7 |
| prompt_security | `openclaw_prompt_injection_check` | Scan text for 16 injection/jailbreak patterns | H2 |
| prompt_security | `openclaw_prompt_injection_batch` | Batch scan multiple texts for injection patterns | H2 |
| auth_compliance | `openclaw_oauth_oidc_audit` | Audit OAuth 2.1 / OIDC Discovery compliance | H4 |
| auth_compliance | `openclaw_token_scope_check` | Check OAuth scopes restrict tool access properly | H4 |
| compliance_medium | `openclaw_tool_deprecation_audit` | Audit tool deprecation lifecycle | M1 |
| compliance_medium | `openclaw_circuit_breaker_audit` | Audit circuit breaker / resilience config | M2 |
| compliance_medium | `openclaw_gdpr_residency_audit` | Audit GDPR compliance and data residency | M3 |
| compliance_medium | `openclaw_agent_identity_audit` | Audit agent DID (decentralized identity) | M4 |
| compliance_medium | `openclaw_model_routing_audit` | Audit multi-model routing and fallback chain | M5 |
| compliance_medium | `openclaw_resource_links_audit` | Audit MCP resource links in tool results | M6 |

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in tokens
bash scripts/start.sh
```

Add to VS Code `settings.json`:
```json
"mcp.servers": {
  "openclaw-extensions": { "url": "http://127.0.0.1:8012/mcp" }
}
```

## Scripts

```bash
bash scripts/start.sh    # start in background
bash scripts/stop.sh     # graceful stop
bash scripts/status.sh   # PID + HTTP + tool count
```

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests/test_smoke.py -v
```

**486 tests** (168 unit + 318 integration), covering:
- Server starts and answers `ping`
- `initialize` returns correct capabilities + `__version__`
- All 115 tools registered with valid `inputSchema`
- `vs_context_push` degrades gracefully without Gateway
- `firm_export_document` writes local file
- Unknown method returns JSON-RPC error -32601
- Unknown tool returns descriptive error
- Timing-safe auth (I21), SQL injection guard (I24), session_id regex (I41)
- ConfigPathInput traversal blocking across all 21 config-path models (I27)
- Health/healthz endpoints return correct tool count + version (I35)
- Shared `config_helpers`: `load_config`, `get_nested`, `mask_secret` (I25)
- Hebbian memory: harvest PII stripping, weight update dry-run, layer validation, drift detection, Pydantic traversal guards

## Security

- **Auth**: timing-safe `hmac.compare_digest` on Bearer token — no timing side-channel (I21)
- **Request limit**: `client_max_size=2MB` on aiohttp `Application` (I22)
- **Tool timeout**: `asyncio.wait_for` with `TOOL_TIMEOUT_S` (default 120s) on all async tool calls (I23)
- **SQL injection guard**: `table_name` validated by Pydantic regex `^[a-zA-Z_][a-zA-Z0-9_]{0,127}$` + runtime whitelist in handler (I24)
- **Session ID regex**: `^[a-zA-Z0-9_\-:.]+$` on all `session_id` fields — no injection (I41)
- **Centralized version**: `__version__` in `main.py` — single source of truth (I37)
- **DRY helpers**: `config_helpers.py` — shared `load_config`, `get_nested`, `mask_secret` (I25)
- **ConfigPathInput base**: 21 models inherit traversal guard from single base class (I27)
- **Hebbian PII stripping**: 9 regex patterns (email, phone, IP, API keys, SSN, JWT, AWS keys) applied before any session storage — CDC §5.2
- **Hebbian drift detection**: TF-IDF cosine similarity vs baseline (no external API) — CDC §5.1
- **Hebbian weight caps**: auto-update capped at 0.95, atrophy floor at 0.0, dry_run=True default — CDC §4.3
- GitHub PRs always created as **drafts** with `needs-review` label
- Tokens masked in logs (last 4 chars only) via `mask_secret()`
- Context capped at 32 KB per WS payload
- `fleet.json` and `acp_sessions.json` written atomically (`os.replace`)
- Workspace lock via `fcntl.LOCK_EX | LOCK_NB` (advisory, crash-safe)
- `fleet_session_inject_env`: allowlist regex — only known provider keys accepted
- `fleet_cron_schedule`: command allowlist regex + blocklist (`rm`, `dd`, `mkfs`…)
- Path traversal guard (`..`) on all file-path Pydantic fields
- All AI outputs carry human-review disclaimer

## Gap coverage (OpenClaw audit)

| ID | Severity | Description | Coverage |
|----|----------|-------------|----------|
| C1 | CRITICAL | SQL injection in API endpoints | `openclaw_security_scan` |
| C2 | CRITICAL | Sandbox disabled (`mode: off`) | `openclaw_sandbox_audit` |
| C3 | CRITICAL | SESSION_SECRET ephemeral / in config | `openclaw_session_config_check` |
| C4 | CRITICAL | ACP sessions lost on restart (in-memory) | `acp_session_persist/restore` |
| H1 | HIGH | `@buape/carbon` frozen at 0.0.0-beta | `firm_adr_generate` + CTO SOUL.md |
| H2 | HIGH | Gateway Funnel without auth.mode=password | `openclaw_gateway_auth_check` |
| H3 | HIGH | Spawned sessions get no env vars | `fleet_session_inject_env` |
| H4 | HIGH | Cron not blocked in sandbox | `fleet_cron_schedule` |
| H5 | HIGH | Race condition on workspace lock | `openclaw_workspace_lock` |
| H6 | HIGH | Gateway silently drops on macOS sleep | `openclaw_gateway_probe` |
| H7 | HIGH | WS close code 1006 not handled | `openclaw_gateway_probe` |
| H8 | HIGH | No rate limiting on Tailscale Funnel | `openclaw_rate_limit_check` |
| M1 | MEDIUM | `@line/bot-sdk` zombie dependency | `openclaw_channel_audit` |
| M2 | MEDIUM | Test coverage threshold 70% | factory 80% threshold + CTO SOUL.md |
| M3 | MEDIUM | Baileys creds.json no integrity/age check | `openclaw_credentials_check` |
| M4 | MEDIUM | Webhook HMAC signature verification missing | `openclaw_webhook_sig_check` |
| M5 | MEDIUM | Docs version stale vs package.json | `openclaw_doc_sync_check` |
| M6 | MEDIUM | No ADRs for architecture decisions | `firm_adr_generate` |
| M7 | MEDIUM | Logging verbose / no redactPatterns | `openclaw_log_config_check` |
| M8 | MEDIUM | ~/.openclaw/workspace integrity unchecked | `openclaw_workspace_integrity_check` |
| C5 | CRITICAL | Node.js < 22.12.0 (CVE-2025-59466, CVE-2026-21636) | `openclaw_node_version_check` |
| C6 | CRITICAL | Hardcoded secrets in openclaw.json (no secrets workflow) | `openclaw_secrets_workflow_check` |
| H9 | HIGH | HTTP security headers absent (HSTS, X-Content-Type-Options) | `openclaw_http_headers_check` |
| H10 | HIGH | gateway.nodes.allowCommands dangerous override | `openclaw_nodes_commands_check` |
| H11 | HIGH | Trusted-proxy misconfigured (bind+proxies+auth mode) | `openclaw_trusted_proxy_check` |
| M15 | MEDIUM | Session disk budget not configured (maxDiskBytes) | `openclaw_session_disk_budget_check` |
| M16 | MEDIUM | dmPolicy=allowlist with empty allowFrom (fail-open) | `openclaw_dm_allowlist_check` |
| C7 | CRITICAL | External Secrets lifecycle not validated (inline creds) | `openclaw_secrets_lifecycle_check` |
| C8 | CRITICAL | Plugin channel HTTP auth bypass (path canonicalization) | `openclaw_channel_auth_canon_check` |
| C9 | CRITICAL | Exec approval plan mutability (symlink cwd rebind) | `openclaw_exec_approval_freeze_check` |
| H12 | HIGH | Hook session-key routing unrestricted | `openclaw_hook_session_routing_check` |
| H13 | HIGH | Config $include hardlink escape + file-size | `openclaw_config_include_check` |
| H14 | HIGH | Prototype pollution in config merge | `openclaw_config_prototype_check` |
| H15 | HIGH | SafeBins without explicit profile = unrestricted interpreter | `openclaw_safe_bins_profile_check` |
| H16 | HIGH | Group policy default not fail-closed | `openclaw_group_policy_default_check` |
| H17 | HIGH | Shell env not sanitized (LD_PRELOAD, DYLD_*) | `openclaw_shell_env_check` |
| H18 | HIGH | Plugin install integrity/pin not tracked | `openclaw_plugin_integrity_check` |
| H19 | HIGH | hooks.token = gateway.auth.token (reuse) | `openclaw_token_separation_check` |
| M17 | MEDIUM | OTEL secret redaction missing in diagnostics | `openclaw_otel_redaction_check` |
| M21 | MEDIUM | Control-plane RPC rate limiting absent | `openclaw_rpc_rate_limit_check` |
| T1 | TOOL | No observability pipeline for JSONL traces | `openclaw_observability_pipeline` |
| T3 | TOOL | pgvector memory config unchecked | `openclaw_pgvector_memory_check` |
| T4 | TOOL | No parallel agent orchestration (task DAG) | `openclaw_agent_team_orchestrate` |
| T5 | TOOL | No i18n/localization audit | `openclaw_i18n_audit` |
| T6 | TOOL | No CI pipeline completeness check | `openclaw_ci_pipeline_check` |
| T7 | TOOL | Skills loaded eagerly (no lazy loading) | `openclaw_skill_lazy_loader` + `openclaw_skill_search` |
| T8 | TOOL | No n8n workflow automation bridge | `openclaw_n8n_workflow_export` + `openclaw_n8n_workflow_import` |
| T9 | TOOL | Knowledge graph integrity unchecked | `openclaw_knowledge_graph_check` |
| T10 | TOOL | Browser automation config unchecked | `openclaw_browser_context_check` |

> ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
