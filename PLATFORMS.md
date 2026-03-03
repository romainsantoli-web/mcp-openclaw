# Platform Configuration Examples

> How to configure `mcp-openclaw-extensions` (Firm MCP Server) with different AI platforms.
> All platforms use the same server — just different config files.

## Claude Code

Add to `~/.claude/mcp_servers.json`:

```json
{
  "firm-mcp-server": {
    "command": "mcp-firm",
    "args": [],
    "env": {
      "FIRM_DIR": "~/.firm",
      "FIRM_PLATFORM": "claude-code",
      "LOG_LEVEL": "INFO"
    }
  }
}
```

Or with `claude mcp add`:
```bash
claude mcp add firm-mcp-server -- mcp-firm
```

## OpenAI Codex

Add to `codex_config.yaml`:

```yaml
mcp_servers:
  - name: firm-mcp-server
    command: mcp-firm
    env:
      FIRM_DIR: ~/.firm
      FIRM_PLATFORM: codex
```

## VS Code (GitHub Copilot)

Add to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "firm-mcp-server": {
      "command": "mcp-firm",
      "args": [],
      "env": {
        "FIRM_DIR": "${userHome}/.firm",
        "FIRM_PLATFORM": "vscode"
      }
    }
  }
}
```

Or in VS Code settings (`settings.json`):
```json
{
  "mcp.servers": {
    "firm-mcp-server": {
      "command": "mcp-firm",
      "args": [],
      "env": {
        "FIRM_PLATFORM": "vscode"
      }
    }
  }
}
```

## Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "firm-mcp-server": {
      "command": "mcp-firm",
      "args": [],
      "env": {
        "FIRM_DIR": "~/.firm",
        "FIRM_PLATFORM": "cursor"
      }
    }
  }
}
```

## Windsurf

Add to `~/.windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "firm-mcp-server": {
      "command": "mcp-firm",
      "env": {
        "FIRM_DIR": "~/.firm",
        "FIRM_PLATFORM": "windsurf"
      }
    }
  }
}
```

## Antigravity

Add to `antigravity.config.json`:

```json
{
  "mcp_servers": {
    "firm-mcp-server": {
      "command": "mcp-firm",
      "transport": "stdio",
      "env": {
        "FIRM_DIR": "~/.firm",
        "FIRM_PLATFORM": "antigravity"
      }
    }
  }
}
```

## SSE / HTTP Transport (any platform)

For platforms supporting HTTP/SSE transport instead of stdio:

```bash
# Start the server on port 8012
MCP_EXT_PORT=8012 FIRM_PLATFORM=generic mcp-firm

# Or with Docker
docker run -p 8012:8012 -e FIRM_PLATFORM=generic firm-mcp-server
```

Then configure your client to connect to `http://localhost:8012/mcp`.

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `FIRM_DIR` | `~/.firm` | Base data directory |
| `FIRM_CONFIG` | `~/.firm/config.json` | Config file path |
| `FIRM_PLATFORM` | `generic` | Platform hint (claude-code, codex, vscode, cursor, windsurf, antigravity) |
| `FIRM_TOOL_PREFIX` | `firm` | Tool name prefix (e.g. `firm_security_scan`) |
| `FIRM_URI_SCHEME` | `firm` | URI scheme for MCP resources |
| `FIRM_GATEWAY_URL` | `ws://127.0.0.1:18789` | Gateway WebSocket URL |
| `FIRM_GATEWAY_HTTP` | `http://127.0.0.1:18789` | Gateway HTTP URL |
| `FIRM_GATEWAY_TOKEN` | *(none)* | Auth token for gateway |
| `MCP_EXT_HOST` | `127.0.0.1` | Server bind host |
| `MCP_EXT_PORT` | `8012` | Server bind port |
| `MCP_AUTH_TOKEN` | *(none)* | Bearer auth for MCP endpoint |
| `LOG_LEVEL` | `INFO` | Logging level |

## Backward Compatibility

All `OPENCLAW_*` environment variables still work and map to their `FIRM_*` equivalents:
- `OPENCLAW_DIR` → `FIRM_DIR`
- `OPENCLAW_CONFIG` → `FIRM_CONFIG`
- `OPENCLAW_GATEWAY_URL` → `FIRM_GATEWAY_URL`
- etc.

The old CLI entrypoint `mcp-openclaw` still works alongside the new `mcp-firm`.
