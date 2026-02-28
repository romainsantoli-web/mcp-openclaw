#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PID_FILE="$ROOT_DIR/.mcp-openclaw.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "Aucun PID trouvé, service probablement arrêté"
  exit 0
fi

PID="$(cat "$PID_FILE")"
if kill -0 "$PID" >/dev/null 2>&1; then
  kill "$PID"
  echo "Arrêt demandé pour PID $PID"
else
  echo "PID $PID introuvable, nettoyage du pidfile"
fi

rm -f "$PID_FILE"
