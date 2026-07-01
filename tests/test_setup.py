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


class _FakeGoogleApiDisabled(_FakeGoogle):
    """GoogleGmail whose first real call fails because the Gmail API is off."""

    def get_profile(self):
        from gmail_proxy.gmail.client import GmailError
        raise GmailError('<HttpError 403 "Gmail API has not been used in project '
                         '123456 before or it is disabled." reason: "accessNotConfigured">')


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


def test_connect_flow_on_default_mock_backend(tmp_path, monkeypatch):
    """Regression: on the default (mock) backend, saving an OAuth client must
    leave demo mode and surface the connect flow — previously mock reported
    itself 'connected' and hid the Connect button entirely."""
    monkeypatch.setattr("gmail_proxy.gmail.google_client.GoogleGmail", _FakeGoogle)
    monkeypatch.setattr(
        "gmail_proxy.gmail.oauth.exchange_code",
        lambda client, code, verifier: {
            "access_token": "a", "refresh_token": "r",
            "token_uri": "t", "scopes": ["https://www.googleapis.com/auth/gmail.modify"]},
    )
    # No gmail_backend -> defaults to "mock".
    settings = Settings(data_dir=str(tmp_path), admin_token="s",
                        token_store_path=str(tmp_path / "token.json"))
    ctx = build_context(settings, policy=Policy(allowed_categories=["promotions"]))
    assert ctx.gmail_status()["demo"] is True  # pristine mock = demo
    client = TestClient(build_admin_app(ctx))
    client.post("/login", data={"token": "s"})

    # Saving a real client exits demo mode and shows the Connect button.
    client.post("/setup/gmail/client", data={
        "client_id": "cid", "client_secret": "sec",
        "redirect_uri": "http://localhost:8081/setup/gmail/callback"})
    st = ctx.gmail_status()
    assert st["demo"] is False and st["connected"] is False
    assert "Connect Gmail" in client.get("/setup").text

    # And the connect flow actually wires up real Gmail (no GMAIL_BACKEND change).
    r = client.get("/setup/gmail/connect", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    r = client.get(f"/setup/gmail/callback?code=abc&state={state}", follow_redirects=False)
    assert "connected=1" in r.headers["location"]
    assert ctx.gmail_status()["connected"] is True
    res = tools.call_tool(ctx, "c", "read_write", "gmail_list_messages", {"category": "promotions"})
    assert res["_control"]["count"] >= 1


def test_connect_surfaces_gmail_api_disabled(tmp_path, monkeypatch):
    """A 403 AccessNotConfigured on the first Gmail call must be shown to the
    operator (with the Enable-the-API hint), not silently hidden."""
    monkeypatch.setattr("gmail_proxy.gmail.google_client.GoogleGmail", _FakeGoogleApiDisabled)
    monkeypatch.setattr(
        "gmail_proxy.gmail.oauth.exchange_code",
        lambda client, code, verifier: {
            "access_token": "a", "refresh_token": "r",
            "token_uri": "t", "scopes": ["https://www.googleapis.com/auth/gmail.modify"]},
    )
    ctx = _google_ctx(tmp_path)
    client = TestClient(build_admin_app(ctx))
    client.post("/login", data={"token": "s"})
    client.post("/setup/gmail/client", data={
        "client_id": "cid", "client_secret": "sec",
        "redirect_uri": "http://localhost:8081/setup/gmail/callback"})
    r = client.get("/setup/gmail/connect", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    r = client.get(f"/setup/gmail/callback?code=abc&state={state}", follow_redirects=False)

    # Token exchange succeeded but the API is off -> not marked connected.
    assert r.status_code == 303 and r.headers["location"] == "/setup"
    st = ctx.gmail_status()
    assert st["connected"] is False
    assert "not enabled" in st["error_hint"] and "accessNotConfigured" in st["error"]
    # And the Setup page shows the actionable error + enable link.
    body = client.get("/setup").text
    assert "Enable the Gmail API" in body and "accessNotConfigured" in body


def test_setup_page_renders(tmp_path):
    ctx = _google_ctx(tmp_path)
    client = TestClient(build_admin_app(ctx))
    client.post("/login", data={"token": "s"})
    body = client.get("/setup").text
    assert "not connected" in body and "Google OAuth client" in body
