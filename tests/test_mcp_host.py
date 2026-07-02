"""MCP DNS-rebinding / Host-header handling.

Regression: the MCP SDK allow-lists the Host header and defaults to localhost
only, so an agent reaching the endpoint by its VM-facing hostname/IP got a 421.
By default we disable that; MCP_ALLOWED_HOSTS re-enables strict validation.
"""

import threading
import time

import httpx
import uvicorn

from gmail_proxy.config import Policy, Settings
from gmail_proxy.context import build_context
from gmail_proxy.gmail.mock_client import sample_backend
from gmail_proxy.mcp_server import build_mcp_app


def _ctx(tmp_path, **kw):
    ctx = build_context(
        Settings(data_dir=str(tmp_path), gmail_backend="mock", **kw),
        backend=sample_backend(), policy=Policy(allowed_categories=["promotions"]),
    )
    _, token = ctx.credentials.issue("agent", mode="read_write")
    return ctx, token


def _serve(ctx, port):
    server = uvicorn.Server(
        uvicorn.Config(build_mcp_app(ctx), host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return server, t


def _get_status(port, token, host):
    # Stream so we read only the response status (headers arrive immediately) and
    # never drain the SSE body that a passing Host opens. The Host check runs
    # before any session handling, so a rejected host is a clean 421.
    with httpx.stream("GET", f"http://127.0.0.1:{port}/mcp",
                      headers={"Host": host, "Authorization": f"Bearer {token}",
                               "Accept": "text/event-stream"}, timeout=5) as r:
        return r.status_code


def test_non_local_host_allowed_by_default(tmp_path):
    ctx, token = _ctx(tmp_path)
    server, t = _serve(ctx, 8793)
    try:
        assert _get_status(8793, token, "gmail-proxy.home.example.com:52443") != 421
    finally:
        server.should_exit = True
        t.join(timeout=5)


def test_mcp_allowed_hosts_enforces_pinning(tmp_path):
    ctx, token = _ctx(tmp_path, mcp_allowed_hosts="allowed.example:*")
    server, t = _serve(ctx, 8794)
    try:
        assert _get_status(8794, token, "evil.example:52443") == 421
        assert _get_status(8794, token, "allowed.example:52443") != 421
    finally:
        server.should_exit = True
        t.join(timeout=5)
