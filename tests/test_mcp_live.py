"""Live MCP round-trip: real client over Streamable HTTP + bearer auth."""

import threading
import time

import pytest
import uvicorn

from gmail_proxy.config import Policy, Settings
from gmail_proxy.context import build_context
from gmail_proxy.gmail.mock_client import sample_backend
from gmail_proxy.mcp_server import build_mcp_app


@pytest.fixture
def live_server(tmp_path):
    ctx = build_context(
        Settings(data_dir=str(tmp_path), gmail_backend="mock"),
        backend=sample_backend(),
        policy=Policy(allowed_categories=["promotions", "social"]),
    )
    _, token = ctx.credentials.issue("agent")
    server = uvicorn.Server(
        uvicorn.Config(build_mcp_app(ctx), host="127.0.0.1", port=8791, log_level="error")
    )
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield "http://127.0.0.1:8791/mcp", token
    server.should_exit = True
    t.join(timeout=5)


async def test_authed_list_and_deny(live_server):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, token = live_server
    async with streamablehttp_client(url, headers={"Authorization": f"Bearer {token}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tl = await s.list_tools()
            names = {t.name for t in tl.tools}
            assert "gmail_list_messages" in names and "gmail_get_message" in names
            res = await s.call_tool("gmail_list_messages", {"category": "promotions"})
            blob = str(res.structuredContent) + (res.content[0].text if res.content else "")
            assert "m001" in blob or "messages" in blob
            deny = await s.call_tool("gmail_get_message", {"id": "m010"})
            dblob = str(deny.structuredContent) + (deny.content[0].text if deny.content else "")
            assert "not_eligible" in dblob


async def test_bad_token_rejected(live_server):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = live_server
    with pytest.raises(Exception):
        async with streamablehttp_client(url, headers={"Authorization": "Bearer nope"}) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
