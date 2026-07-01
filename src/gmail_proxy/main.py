"""Entrypoint: run the MCP endpoint and the admin UI on separate ports.

Both share a single :class:`AppContext` so config changes made in the admin UI
take effect for the agent-facing MCP endpoint immediately.
"""

from __future__ import annotations

import asyncio

import uvicorn

from .admin.app import build_admin_app
from .config import Settings
from .context import build_context
from .mcp_server import build_mcp_app


async def _serve(settings: Settings) -> None:
    ctx = build_context(settings)
    mcp_app = build_mcp_app(ctx)
    admin_app = build_admin_app(ctx)

    mcp_server = uvicorn.Server(
        uvicorn.Config(mcp_app, host=settings.mcp_host, port=settings.mcp_port, log_level="info")
    )
    admin_server = uvicorn.Server(
        uvicorn.Config(admin_app, host=settings.admin_host, port=settings.admin_port, log_level="info")
    )
    print(f"MCP   endpoint : http://{settings.mcp_host}:{settings.mcp_port}/mcp")
    print(f"Admin UI       : http://{settings.admin_host}:{settings.admin_port}/")
    if ctx.admin_token_generated:
        bar = "=" * 72
        print(bar)
        print("ADMIN_TOKEN was not set — generated a random admin-UI login token:")
        print(f"    {ctx.settings.admin_token}")
        print("Log in with this token. It is persisted at <data_dir>/keys/admin_token")
        print("(back it up with the data volume); set ADMIN_TOKEN to pin your own.")
        print(bar)
    await asyncio.gather(mcp_server.serve(), admin_server.serve())


def main() -> None:
    asyncio.run(_serve(Settings.from_env()))


if __name__ == "__main__":
    main()
