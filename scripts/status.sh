#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$ROOT_DIR/.mcp_ext.pid"

[[ -f .env ]] && source .env 2>/dev/null || true
HOST="${MCP_EXT_HOST:-127.0.0.1}"
PORT="${MCP_EXT_PORT:-8012}"

echo "=== firm-mcp-server status ==="

# PID
if [[ -f "$PID_FILE" ]]; then
  PID=$(cat "$PID_FILE")
  if kill -0 "$PID" 2>/dev/null; then
    echo "Process : RUNNING (PID $PID)"
  else
    echo "Process : DEAD (stale PID $PID)"
  fi
else
  echo "Process : STOPPED"
fi

# HTTP health
if curl -sf --max-time 2 -X POST "http://$HOST:$PORT/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' | grep -q '"result"'; then
  echo "HTTP    : OK  — http://$HOST:$PORT/mcp"
else
  echo "HTTP    : UNREACHABLE — http://$HOST:$PORT/mcp"
fi

# Tool count
COUNT=$(curl -sf --max-time 3 -X POST "http://$HOST:$PORT/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['result']['tools']))" 2>/dev/null || echo "?")
echo "Tools   : $COUNT registered"
