#!/usr/bin/env bash
# Start mcp-openclaw-extensions in background
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$ROOT_DIR/.mcp_ext.pid"
LOG_FILE="$ROOT_DIR/.mcp_ext.log"

if [[ -f "$PID_FILE" ]]; then
  PID=$(cat "$PID_FILE")
  if kill -0 "$PID" 2>/dev/null; then
    echo "Already running (PID $PID). Use stop.sh first."
    exit 1
  fi
  rm -f "$PID_FILE"
fi

cd "$ROOT_DIR"

# Load .env if present
[[ -f .env ]] && export $(grep -v '^#' .env | grep -v '^$' | xargs)

# Check venv
if [[ -f ".venv/bin/python" ]]; then
  PYTHON=".venv/bin/python"
elif command -v python3 &>/dev/null; then
  PYTHON="python3"
else
  echo "Python not found. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

nohup "$PYTHON" -m src.main >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

sleep 1

if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "Started mcp-openclaw-extensions (PID $(cat "$PID_FILE"))"
  echo "  MCP : http://${MCP_EXT_HOST:-127.0.0.1}:${MCP_EXT_PORT:-8012}/mcp"
  echo "  Log : $LOG_FILE"
else
  echo "Failed to start. Check $LOG_FILE"
  rm -f "$PID_FILE"
  exit 1
fi
