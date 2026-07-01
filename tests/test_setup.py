"""Tests for web-UI Gmail setup: not-connected state + OAuth connect flow."""

from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

from gmail_proxy import errors, tools
from gmail_proxy.admin.app import build_admin_app
from gmail_proxy.config import Policy, Settings
from gmail_proxy.context import build_context
from gmail_proxy.gmail.mock_client import sample_backend
from gmail_proxy.gmail.oauth import OAuthClient, OAuthClientStore


def _google_ctx(tmp_path):
    settings = Settings(data_dir=str(tmp_path), gmail_backend="google", admin_token="s",
                        token_store_path=str(tmp_path / "token.json"))
    return build_context(settings, policy=Policy(allowed_categories=["promotions", "social"]))


class _FakeGoogle:
    """Stand-in for GoogleGmail: delegates to the in-memory sample backend."""

    def __init__(self, store, client_id, client_secret):
        self._inner = sample_backend()

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_not_connected_backend_denies(tmp_path):
    ctx = _google_ctx(tmp_path)
    assert ctx.gmail_status()["connected"] is False
    with pytest.raises(errors.ProxyError) as ei:
        tools.call_tool(ctx, "c", "read_write", "gmail_list_messages", {"category": "promotions"})
    assert ei.value.reason == "upstream_error"


def test_oauth_client_store_roundtrip(tmp_path):
    store = OAuthClientStore(tmp_path / "c.json")
    assert store.load() is None
    store.save(OAuthClient("cid", "sec", "http://x/cb"))
    c = store.load()
    assert c.client_id == "cid" and c.client_secret == "sec" and c.redirect_uri == "http://x/cb"


def test_encryption_key_auto_generated_and_token_roundtrips(tmp_path):
    ctx = _google_ctx(tmp_path)
    assert (tmp_path / "keys" / "token_fernet.key").exists()  # generated at build
    ctx.token_store().save({"refresh_token": "r", "scopes": ["s"]})
    raw = (tmp_path / "token.json").read_bytes()
    assert b"refresh_token" not in raw  # encrypted at rest
    assert ctx.token_store().load()["refresh_token"] == "r"


def test_full_connect_flow_via_admin_ui(tmp_path, monkeypatch):
    monkeypatch.setattr("gmail_proxy.gmail.google_client.GoogleGmail", _FakeGoogle)
    monkeypatch.setattr(
        "gmail_proxy.gmail.oauth.exchange_code",
        lambda client, code, verifier: {
            "access_token": "a", "refresh_token": "r",
            "token_uri": "t", "scopes": ["https://www.googleapis.com/auth/gmail.modify"]},
    )
    ctx = _google_ctx(tmp_path)
    assert ctx.gmail_status()["connected"] is False
    client = TestClient(build_admin_app(ctx))
    client.post("/login", data={"token": "s"})

    # 1. save the OAuth client
    r = client.post("/setup/gmail/client", data={
        "client_id": "cid", "client_secret": "sec",
        "redirect_uri": "http://localhost:8081/setup/gmail/callback"}, follow_redirects=False)
    assert r.status_code == 303
    assert ctx.oauth_client_store().load().client_id == "cid"

    # 2. start the OAuth flow
    r = client.get("/setup/gmail/connect", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("https://accounts.google.com/")
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["access_type"] == ["offline"] and "gmail.modify" in q["scope"][0]
    state = q["state"][0]

    # 3. callback -> exchange -> connect
    r = client.get(f"/setup/gmail/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 303 and "connected=1" in r.headers["location"]

    # now connected, and tools work against the (fake) live backend
    st = ctx.gmail_status()
    assert st["connected"] is True and st["email"] == "vrwarp@gmail.com"
    res = tools.call_tool(ctx, "c", "read_write", "gmail_list_messages", {"category": "promotions"})
    assert res["_control"]["count"] >= 1

    # 4. disconnect
    r = client.post("/setup/gmail/disconnect", follow_redirects=False)
    assert r.status_code == 303
    assert ctx.gmail_status()["connected"] is False


def test_setup_page_renders(tmp_path):
    ctx = _google_ctx(tmp_path)
    client = TestClient(build_admin_app(ctx))
    client.post("/login", data={"token": "s"})
    body = client.get("/setup").text
    assert "not connected" in body and "Google OAuth client" in body
