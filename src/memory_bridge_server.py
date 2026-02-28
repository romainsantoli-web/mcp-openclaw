from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


_TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-]+")


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in _TOKEN_RE.findall(text)}


def _flatten(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(f"{key}: {_flatten(item)}" for key, item in value.items())
    if isinstance(value, list):
        return "\n".join(_flatten(item) for item in value)
    return str(value)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class MemoryBridgeSettings:
    repo_path: Path
    events_path: Path


class MemoryBridgeIndex:
    def __init__(self, settings: MemoryBridgeSettings) -> None:
        self._settings = settings

    def query(self, text: str, limit: int) -> dict[str, Any]:
        limit = max(1, limit)
        events = self._read_event_rows()
        mirror_items = self._read_mirror_rows()

        event_hits = self._rank_rows(events, text, limit)
        mirror_hits = self._rank_rows(mirror_items, text, limit)

        return {
            "ok": True,
            "query": text,
            "timestamp": _utc_now_iso(),
            "sources": {
                "events_jsonl": {
                    "count": len(event_hits),
                    "items": event_hits,
                },
                "mirror_files": {
                    "count": len(mirror_hits),
                    "items": mirror_hits,
                },
            },
            "items": (event_hits + mirror_hits)[: limit * 2],
        }

    def _rank_rows(self, rows: list[dict[str, Any]], query: str, limit: int) -> list[dict[str, Any]]:
        query_tokens = _tokens(query)
        scored: list[tuple[int, int, dict[str, Any]]] = []
        for index, row in enumerate(rows):
            content = " ".join(
                [
                    str(row.get("key", "")),
                    str(row.get("kind", "")),
                    str(row.get("tool", "")),
                    str(row.get("summary", "")),
                    _flatten(row.get("value", {})),
                ]
            )
            tokens = _tokens(content)
            overlap = len(query_tokens.intersection(tokens)) if query_tokens else 0
            recency = index // 40
            score = overlap * 10 + recency
            if score > 0 or not query_tokens:
                scored.append((score, index, row))

        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [item[2] for item in scored[:limit]]

    def _read_event_rows(self) -> list[dict[str, Any]]:
        if not self._settings.events_path.exists():
            return []

        rows: list[dict[str, Any]] = []
        with self._settings.events_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(data, dict):
                    rows.append(data)
        return rows

    def _read_mirror_rows(self) -> list[dict[str, Any]]:
        mirror_dir = self._settings.repo_path / "pdfs" / "mcp_openclaw_events"
        if not mirror_dir.exists():
            return []

        rows: list[dict[str, Any]] = []
        for txt_file in sorted(mirror_dir.glob("*.txt"))[-800:]:
            try:
                content = txt_file.read_text(encoding="utf-8")
            except OSError:
                continue
            rows.append(
                {
                    "key": "mirror/file",
                    "kind": "mirror",
                    "tool": "memory_bridge",
                    "summary": content[:3000],
                    "value": {"path": str(txt_file), "content": content[:3000]},
                }
            )
        return rows


def start_memory_bridge(
    host: str,
    port: int,
    query_path: str,
    index: MemoryBridgeIndex,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    normalized_path = query_path if query_path.startswith("/") else f"/{query_path}"

    class MemoryBridgeHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != normalized_path:
                self.send_response(404)
                self.end_headers()
                return

            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except ValueError:
                length = 0
            raw = self.rfile.read(max(0, length)).decode("utf-8") if length > 0 else "{}"
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = {}

            query = str(payload.get("query", "")).strip()
            limit = payload.get("limit", 16)
            try:
                parsed_limit = int(limit)
            except (TypeError, ValueError):
                parsed_limit = 16

            result = index.query(query, parsed_limit)
            body = json.dumps(result, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path in {"/", "/healthz"}:
                payload = b"ok\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format_string: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), MemoryBridgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
