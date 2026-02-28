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

            routing = await session.call_tool(
                "routing_preview",
                {
                    "objective": "Créer une campagne social media B2B IA",
                    "task_family": "marketing",
                    "quality_tier": "high",
                    "latency_budget_ms": 15000,
                },
            )
            print("routing_profile:", routing.structuredContent.get("routing", {}).get("model_profile"))

            workflow = await session.call_tool(
                "firm_run_delivery_workflow",
                {
                    "objective": "Smoke test delivery workflow",
                    "departments": ["communications", "social-media"],
                    "task_family": "marketing",
                    "quality_tier": "high",
                    "push_to_openclaw": False,
                },
            )
            workflow_content = workflow.structuredContent
            print("workflow_ok:", workflow_content.get("ok"))
            print(
                "workflow_departments:",
                workflow_content.get("selected_departments", []),
            )
            print(
                "workflow_model_profile:",
                workflow_content.get("routing", {}).get("model_profile"),
            )

            dispatch = await session.call_tool(
                "firm_run_delivery_and_dispatch",
                {
                    "objective": "Smoke test delivery+dispatch",
                    "departments": ["communications"],
                    "task_family": "research",
                    "require_openclaw_success": False,
                },
            )
            dispatch_content = dispatch.structuredContent
            print("dispatch_ok:", dispatch_content.get("dispatch_ok"))
            print(
                "dispatch_request_id:",
                dispatch_content.get("openclaw_request_id"),
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8011/mcp")
    args = parser.parse_args()
    anyio.run(run_smoke, args.url)


if __name__ == "__main__":
    main()
