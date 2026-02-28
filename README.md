# mcp-openclaw-extensions

> Python MCP server (port **8012**) that bridges VS Code Copilot agents to the
> [OpenClaw](https://github.com/openclaw/openclaw) Gateway ecosystem.
> Companion to [setup-vs-agent-firm](https://github.com/romainsantoli-web/setup-vs-agent-firm).

## Tools (35)

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

## Security

- GitHub PRs always created as **drafts** with `needs-review` label
- Tokens masked in logs (last 4 chars only) via `_mask_secret()`
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

> ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
