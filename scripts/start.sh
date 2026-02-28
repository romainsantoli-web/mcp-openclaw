#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PID_FILE="$ROOT_DIR/.mcp-openclaw.pid"
LOG_FILE="$ROOT_DIR/.mcp-openclaw.log"

if [[ -f "$PID_FILE" ]]; then
  PID="$(cat "$PID_FILE")"
  if kill -0 "$PID" >/dev/null 2>&1; then
    echo "Service déjà démarré (PID $PID)"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

cd "$ROOT_DIR"

if [[ -f ".env" ]]; then
  set -a
  source .env
  set +a
fi

: "${MCP_TRANSPORT:=streamable-http}"
: "${MCP_HOST:=127.0.0.1}"
: "${MCP_PORT:=8011}"

nohup /opt/homebrew/bin/python3.11 -m src.main >"$LOG_FILE" 2>&1 &
PID=$!
echo "$PID" > "$PID_FILE"

sleep 1
if kill -0 "$PID" >/dev/null 2>&1; then
  echo "Service démarré (PID $PID) sur ${MCP_HOST}:${MCP_PORT}"
  echo "Logs: $LOG_FILE"
else
  echo "Échec du démarrage, voir logs: $LOG_FILE"
  exit 1
fi
