from __future__ import annotations

import argparse

import anyio
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def run_smoke(url: str) -> None:
    async with streamable_http_client(url) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            tool_names = [tool.name for tool in tools.tools]
            print("tool_count:", len(tool_names))
            print("tools:", tool_names)

            status = await session.call_tool("firm_repo_status", {})
            print("firm_repo_status:", status.structuredContent)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8011/mcp")
    args = parser.parse_args()
    anyio.run(run_smoke, args.url)


if __name__ == "__main__":
    main()
