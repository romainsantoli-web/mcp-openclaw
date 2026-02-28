#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$ROOT_DIR/.mcp_ext.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "Not running (no PID file)."
  exit 0
fi

PID=$(cat "$PID_FILE")

if kill -0 "$PID" 2>/dev/null; then
  echo "Stopping mcp-openclaw-extensions (PID $PID)..."
  kill -TERM "$PID"
  for i in $(seq 1 10); do
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.5
  done
  if kill -0 "$PID" 2>/dev/null; then
    echo "Graceful stop timed out — sending SIGKILL"
    kill -KILL "$PID" 2>/dev/null || true
  fi
  echo "Stopped."
else
  echo "Process $PID not running (stale PID)."
fi

rm -f "$PID_FILE"
