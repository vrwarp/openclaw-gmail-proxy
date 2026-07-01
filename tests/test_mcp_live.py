"""Live MCP round-trip: real client over Streamable HTTP + per-agent auth.

Also regression-tests that identity/mode are resolved PER REQUEST (a read-only
credential cannot mutate, even sharing the endpoint with a read-write one).
"""

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
    _, rw_token = ctx.credentials.issue("rw-agent", mode="read_write")
    _, ro_token = ctx.credentials.issue("ro-agent", mode="read_only")
    server = uvicorn.Server(
        uvicorn.Config(build_mcp_app(ctx), host="127.0.0.1", port=8791, log_level="error")
    )
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield "http://127.0.0.1:8791/mcp", rw_token, ro_token
    server.should_exit = True
    t.join(timeout=5)


async def _call(url, token, tool, args):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    async with streamablehttp_client(url, headers={"Authorization": f"Bearer {token}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(tool, args)
            return str(res.structuredContent) + (res.content[0].text if res.content else "")


async def test_authed_list_and_deny(live_server):
    url, rw, _ = live_server
    ok = await _call(url, rw, "gmail_list_messages", {"category": "promotions"})
    assert "m001" in ok or "messages" in ok
    deny = await _call(url, rw, "gmail_get_message", {"id": "m010"})  # personal
    assert "not_eligible" in deny


async def test_read_only_credential_cannot_mutate(live_server):
    url, _rw, ro = live_server
    out = await _call(url, ro, "gmail_modify_labels", {"id": "m001", "remove_labels": ["UNREAD"]})
    assert "mutation_not_allowed" in out


async def test_read_write_credential_can_mutate(live_server):
    url, rw, _ = live_server
    out = await _call(url, rw, "gmail_modify_labels", {"id": "m002", "remove_labels": ["UNREAD"]})
    assert "mutation_not_allowed" not in out and "error" not in out.lower() or "labels" in out


async def test_bad_token_rejected(live_server):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _rw, _ro = live_server
    with pytest.raises(Exception):
        async with streamablehttp_client(url, headers={"Authorization": "Bearer nope"}) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
