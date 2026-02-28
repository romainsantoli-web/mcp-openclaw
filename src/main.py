from __future__ import annotations

import logging

from .config import load_settings
from .memory_bridge_server import (
    MemoryBridgeIndex,
    MemoryBridgeSettings,
    start_memory_bridge,
)
from .prometheus_exporter import start_prometheus_exporter
from .tools import build_server


def main() -> None:
    settings = load_settings()
    logging.basicConfig(level=settings.log_level)

    server = build_server(settings)

    if settings.memory_bridge_enabled:
        start_memory_bridge(
            host=settings.memory_bridge_host,
            port=settings.memory_bridge_port,
            query_path=settings.memory_bridge_query_path,
            index=MemoryBridgeIndex(
                MemoryBridgeSettings(
                    repo_path=settings.memory_os_ai_repo_path,
                    events_path=settings.memory_os_ai_events_path,
                )
            ),
        )
        logging.getLogger(__name__).info(
            "Memory bridge active on %s:%s%s",
            settings.memory_bridge_host,
            settings.memory_bridge_port,
            settings.memory_bridge_query_path,
        )

    if settings.prometheus_exporter_enabled:
        snapshot_provider = getattr(server, "_openclaw_metrics_snapshot", None)
        if callable(snapshot_provider):
            start_prometheus_exporter(
                host=settings.prometheus_exporter_host,
                port=settings.prometheus_exporter_port,
                path=settings.prometheus_exporter_path,
                snapshot_provider=snapshot_provider,
            )
            logging.getLogger(__name__).info(
                "Prometheus exporter active on %s:%s%s",
                settings.prometheus_exporter_host,
                settings.prometheus_exporter_port,
                settings.prometheus_exporter_path,
            )

    server.run(
        transport=settings.mcp_transport,
        mount_path=settings.mcp_mount_path,
    )


if __name__ == "__main__":
    main()
