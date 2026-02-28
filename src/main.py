from __future__ import annotations

import logging

from .config import load_settings
from .tools import build_server


def main() -> None:
    settings = load_settings()
    logging.basicConfig(level=settings.log_level)

    server = build_server(settings)
    server.run(
        transport=settings.mcp_transport,
        mount_path=settings.mcp_mount_path,
    )


if __name__ == "__main__":
    main()
