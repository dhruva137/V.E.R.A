"""VERA MCP server — the same tools, spoken over the Model Context Protocol.

WHAT THIS IS
------------
A thin Model Context Protocol adapter so any MCP-aware agent (Claude Desktop,
Claude Code, and a growing set of others) can call VERA's tools natively, with
no custom client code. It does not re-implement anything: it forwards every call
to a running VERA instance's ``/api/v1`` integration surface, which dispatches
through the same control plane, honours the same limits, and writes the same
audit log as the built-in agent. The MCP client receives conclusions; the engine
that produces them never leaves the server.

WHY A PROXY, NOT AN EMBEDDED ENGINE
-----------------------------------
State (the scanned estate, the fitted survival curve, the audit log) lives inside
a running VERA process. Pointing this adapter at that process over HTTP means
an MCP client and the dashboard share one live state and one governance boundary,
rather than this process holding a second, divergent copy.

RUN IT
------
  pip install "mcp>=1.2.0"            # httpx is already an VERA dependency
  export VERA_BASE_URL=http://127.0.0.1:8000
  export VERA_API_KEY=<a key issued in Settings -> API access>
  python backend/mcp_server.py

Then register it with an MCP client, e.g. in Claude Desktop config:

  "mcpServers": {
    "vera": {
      "command": "python",
      "args": ["/abs/path/backend/mcp_server.py"],
      "env": { "VERA_BASE_URL": "http://127.0.0.1:8000", "VERA_API_KEY": "..." }
    }
  }

A read-scoped key exposes the read tools; the single write tool (migrate_asset)
requires a write-scoped key and still returns "awaiting approval" until a human
approves it inside the dashboard.
"""

from __future__ import annotations

import json
import os
import sys

import httpx

BASE_URL = os.environ.get("VERA_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
API_KEY = os.environ.get("VERA_API_KEY", "")
TIMEOUT = float(os.environ.get("VERA_MCP_TIMEOUT", "30"))


def _headers() -> dict:
    if not API_KEY:
        raise SystemExit(
            "VERA_API_KEY is not set. Issue a key in the VERA dashboard under "
            "Settings -> API access, then export it as VERA_API_KEY."
        )
    return {"Authorization": f"Bearer {API_KEY}"}


def _fetch_tool_schemas() -> list[dict]:
    """Pull the live tool catalogue from the running VERA instance."""
    resp = httpx.get(f"{BASE_URL}/api/v1/tools", headers=_headers(), timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json().get("tools", [])


def _invoke(name: str, arguments: dict) -> dict:
    resp = httpx.post(
        f"{BASE_URL}/api/v1/tools/{name}",
        headers=_headers(),
        json=arguments or {},
        timeout=TIMEOUT,
    )
    # A governed refusal comes back as a 200 with a refusal body; a 4xx is a real
    # protocol error (bad key, unknown tool). Surface both to the model as text.
    if resp.status_code >= 400:
        return {"error": f"HTTP {resp.status_code}", "detail": resp.text}
    return resp.json()


def build_server():
    """Construct the MCP server. Imported lazily so the module loads without mcp."""
    from mcp.server import Server
    from mcp.types import TextContent, Tool

    server = Server("vera")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        tools = []
        for schema in _fetch_tool_schemas():
            fn = schema.get("function", {})
            tools.append(
                Tool(
                    name=fn.get("name", ""),
                    description=fn.get("description", ""),
                    inputSchema=fn.get("parameters", {"type": "object", "properties": {}}),
                )
            )
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        result = _invoke(name, arguments or {})
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    return server


def main() -> None:
    try:
        import mcp  # noqa: F401
    except ImportError:
        raise SystemExit(
            "The 'mcp' package is not installed. Run: pip install \"mcp>=1.2.0\""
        )

    import anyio
    from mcp.server.stdio import stdio_server

    server = build_server()

    async def _run():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    # Fail fast with a readable message if the instance is unreachable.
    try:
        httpx.get(f"{BASE_URL}/api/health", timeout=5).raise_for_status()
    except Exception as exc:  # noqa: BLE001
        print(f"[vera-mcp] cannot reach VERA at {BASE_URL}: {exc}", file=sys.stderr)

    anyio.run(_run)


if __name__ == "__main__":
    main()
