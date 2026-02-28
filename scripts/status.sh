#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PID_FILE="$ROOT_DIR/.mcp-openclaw.pid"
LOG_FILE="$ROOT_DIR/.mcp-openclaw.log"

if [[ -f "$PID_FILE" ]]; then
  PID="$(cat "$PID_FILE")"
  if kill -0 "$PID" >/dev/null 2>&1; then
    echo "Service actif (PID $PID)"
  else
    echo "PID file présent mais process absent"
  fi
else
  echo "Service arrêté"
fi

if [[ -f "$LOG_FILE" ]]; then
  echo "--- Dernières lignes log ---"
  tail -n 20 "$LOG_FILE"
fi
