# mcp-openclaw-extensions

> Python MCP server (port **8012**) that bridges VS Code Copilot agents to the
> [OpenClaw](https://github.com/openclaw/openclaw) Gateway ecosystem.
> Companion to [setup-vs-agent-firm](https://github.com/romainsantoli-web/setup-vs-agent-firm).

## Tools (16)

| Module | Tool | Description |
|--------|------|-------------|
| vs_bridge | `vs_context_push` | Push VS Code context → OpenClaw session |
| vs_bridge | `vs_context_pull` | Pull OpenClaw session state → VS Code |
| vs_bridge | `vs_session_link` | Associate workspace path ↔ session ID |
| vs_bridge | `vs_session_status` | Bridge health check |
| gateway_fleet | `firm_gateway_fleet_status` | Parallel health-check all instances |
| gateway_fleet | `firm_gateway_fleet_add` | Register a Gateway instance |
| gateway_fleet | `firm_gateway_fleet_remove` | Remove a Gateway instance |
| gateway_fleet | `firm_gateway_fleet_broadcast` | Broadcast to all instances |
| gateway_fleet | `firm_gateway_fleet_sync` | Sync config+skills to all instances |
| gateway_fleet | `firm_gateway_fleet_list` | List instances |
| delivery_export | `firm_export_github_pr` | Create draft PR on GitHub |
| delivery_export | `firm_export_jira_ticket` | Create Jira ticket (ADF) |
| delivery_export | `firm_export_linear_issue` | Create Linear issue (GraphQL) |
| delivery_export | `firm_export_slack_digest` | Post Slack digest (Block Kit) |
| delivery_export | `firm_export_document` | Write local Markdown deliverable |
| delivery_export | `firm_export_auto` | Auto-route by `delivery_format` |

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
- Tokens masked in logs (last 4 chars only)
- Context capped at 32 KB per WS payload
- `fleet.json` written atomically
- All AI outputs carry human-review disclaimer
