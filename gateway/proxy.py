"""Thin HTTP client that forwards an already-approved tool call to the real
upstream server. Swap this for an MCP ClientSession over stdio/SSE (using
the official `mcp` SDK) to talk to genuine MCP servers instead of this
demo HTTP stand-in - the rest of the gateway doesn't need to change."""
from __future__ import annotations
import httpx
from gateway.config import settings


async def forward_tool_call(upstream: str, tool_name: str, arguments: dict) -> dict:
    base_url = settings.UPSTREAM_SERVERS.get(upstream)
    if not base_url:
        return {"success": False, "error": f"Unknown upstream '{upstream}'"}

    async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
        resp = await client.post(
            f"{base_url}/invoke",
            json={"tool_name": tool_name, "arguments": arguments},
        )
        resp.raise_for_status()
        return resp.json()
