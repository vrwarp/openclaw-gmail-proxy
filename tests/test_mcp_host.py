"""MCP Host-header allow-list (DNS-rebinding handling).

The MCP SDK's static guard defaults to localhost only, which 421-rejected agents
connecting by hostname/IP. We disable that and enforce our own live allow-list
(policy-driven, UI-editable): empty = accept any; entries pin specific hosts.
"""

import threading
import time

import httpx
import uvicorn

from gmail_proxy.config import Policy, Settings
from gmail_proxy.context import build_context
from gmail_proxy.gmail.mock_client import sample_backend
from gmail_proxy.mcp_server import _host_allowed, build_mcp_app, effective_allowed_hosts


# --- unit: matcher + precedence (fast) ---------------------------------------
def test_host_matcher_syntaxes():
    assert _host_allowed("anything:1234", [])                      # empty = open
    assert _host_allowed("localhost:8443", ["only.example"])       # localhost always ok
    assert _host_allowed("[::1]:8443", ["only.example"])
    assert _host_allowed("h.lan:52443", ["h.lan"])                 # bare host = any port
    assert _host_allowed("h.lan:52443", ["h.lan:*"])               # :* = any port
    assert _host_allowed("h.lan:52443", ["h.lan:52443"])           # exact host:port
    assert _host_allowed("h.lan:9", ["*"])                         # wildcard
    assert not _host_allowed("evil.lan:52443", ["h.lan"])
    assert not _host_allowed("h.lan:52443", ["h.lan:8443"])        # wrong exact port
    assert not _host_allowed(None, ["h.lan"])


def test_policy_hosts_take_precedence_over_env(tmp_path):
    ctx = build_context(
        Settings(data_dir=str(tmp_path), gmail_backend="mock", mcp_allowed_hosts="from-env"),
        backend=sample_backend(),
        policy=Policy(allowed_categories=["promotions"], mcp_allowed_hosts=["from-policy"]),
    )
    assert effective_allowed_hosts(ctx) == ["from-policy"]
    ctx.policy.mcp_allowed_hosts = []
    assert effective_allowed_hosts(ctx) == ["from-env"]  # env is the fallback


# --- integration: live server enforces the Host header -----------------------
def _ctx(tmp_path, policy_hosts=None):
    ctx = build_context(
        Settings(data_dir=str(tmp_path), gmail_backend="mock"),
        backend=sample_backend(),
        policy=Policy(allowed_categories=["promotions"], mcp_allowed_hosts=policy_hosts or []),
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


def _status(port, token, host):
    # Stream so we read only the status (headers arrive immediately) and never
    # drain the SSE body a passing Host opens.
    with httpx.stream("GET", f"http://127.0.0.1:{port}/mcp",
                      headers={"Host": host, "Authorization": f"Bearer {token}",
                               "Accept": "text/event-stream"}, timeout=5) as r:
        return r.status_code


def test_non_local_host_allowed_by_default(tmp_path):
    ctx, token = _ctx(tmp_path)
    server, t = _serve(ctx, 8793)
    try:
        assert _status(8793, token, "gmail-proxy.home.example.com:52443") != 421
    finally:
        server.should_exit = True
        t.join(timeout=5)


def test_policy_allowed_hosts_enforced(tmp_path):
    ctx, token = _ctx(tmp_path, policy_hosts=["allowed.example"])
    server, t = _serve(ctx, 8794)
    try:
        assert _status(8794, token, "evil.example:52443") == 421
        assert _status(8794, token, "allowed.example:52443") != 421
        assert _status(8794, token, "127.0.0.1:8794") != 421  # localhost always ok
    finally:
        server.should_exit = True
        t.join(timeout=5)
