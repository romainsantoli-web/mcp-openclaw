from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable


SnapshotProvider = Callable[[], dict[str, Any]]


def _sanitize_metric_label(value: str) -> str:
    return value.replace('\\', '\\\\').replace('"', '\\"')


def format_prometheus_text(snapshot: dict[str, Any]) -> str:
    lines: list[str] = []

    enabled = bool(snapshot.get("enabled", False))
    lines.append("# HELP mcp_openclaw_telemetry_enabled Telemetry collector enabled flag")
    lines.append("# TYPE mcp_openclaw_telemetry_enabled gauge")
    lines.append(f"mcp_openclaw_telemetry_enabled {1 if enabled else 0}")

    counters = snapshot.get("counters", {})
    lines.append("# HELP mcp_openclaw_counter Generic counter values emitted by the server")
    lines.append("# TYPE mcp_openclaw_counter gauge")
    for counter_name, counter_value in counters.items():
        safe_name = _sanitize_metric_label(str(counter_name))
        lines.append(
            f'mcp_openclaw_counter{{name="{safe_name}"}} {int(counter_value)}'
        )

    latencies = snapshot.get("latencies", {})
    lines.append("# HELP mcp_openclaw_latency_count Latency observation count by metric")
    lines.append("# TYPE mcp_openclaw_latency_count gauge")
    lines.append("# HELP mcp_openclaw_latency_avg_ms Average latency in milliseconds")
    lines.append("# TYPE mcp_openclaw_latency_avg_ms gauge")
    lines.append("# HELP mcp_openclaw_latency_max_ms Maximum latency in milliseconds")
    lines.append("# TYPE mcp_openclaw_latency_max_ms gauge")
    for latency_name, latency_data in latencies.items():
        safe_name = _sanitize_metric_label(str(latency_name))
        count = int(latency_data.get("count", 0))
        avg_ms = float(latency_data.get("avg_ms", 0.0))
        max_ms = float(latency_data.get("max_ms", 0.0))
        lines.append(f'mcp_openclaw_latency_count{{name="{safe_name}"}} {count}')
        lines.append(f'mcp_openclaw_latency_avg_ms{{name="{safe_name}"}} {avg_ms}')
        lines.append(f'mcp_openclaw_latency_max_ms{{name="{safe_name}"}} {max_ms}')

    return "\n".join(lines) + "\n"


def start_prometheus_exporter(
    host: str,
    port: int,
    path: str,
    snapshot_provider: SnapshotProvider,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    normalized_path = path if path.startswith("/") else f"/{path}"
    started_at = time.monotonic()

    class MetricsHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == normalized_path:
                payload = format_prometheus_text(snapshot_provider()).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            if self.path in {"/", "/healthz"}:
                uptime_seconds = int(time.monotonic() - started_at)
                payload = f"ok uptime_seconds={uptime_seconds}\n".encode("utf-8")
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

    server = ThreadingHTTPServer((host, port), MetricsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
