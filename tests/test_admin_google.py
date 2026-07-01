"""Google (OIDC) admin-login tests, restricted to the proxied account.

The Google network round-trip is mocked (like the Gmail backend) -- we patch
GoogleOIDC.exchange_and_verify to return canned verified claims.
"""

from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

from gmail_proxy.admin import google_auth
from gmail_proxy.admin.app import build_admin_app
from gmail_proxy.config import Policy, Settings
from gmail_proxy.context import build_context
from gmail_proxy.gmail.mock_client import sample_backend


@pytest.fixture
def gclient(tmp_path):
    settings = Settings(
        data_dir=str(tmp_path), gmail_backend="mock", admin_token="secret",
        admin_oauth_client_id="cid", admin_oauth_client_secret="csecret",
        admin_oauth_redirect_uri="http://localhost:8081/auth/callback",
    )
    ctx = build_context(settings, backend=sample_backend(),
                        policy=Policy(allowed_categories=["promotions", "social"]))
    # proxied account (mock profile) -> vrwarp@gmail.com is the only allowed login
    return TestClient(build_admin_app(ctx))


def _begin(client):
    r = client.get("/auth/google", follow_redirects=False)
    assert r.status_code == 303
    loc = r.headers["location"]
    assert loc.startswith("https://accounts.google.com/")
    state = parse_qs(urlparse(loc).query)["state"][0]
    assert "oauth_tx" in r.cookies or "oauth_tx" in client.cookies
    return state


def test_login_page_offers_google(gclient):
    assert "Sign in with Google" in gclient.get("/login").text


def test_google_login_matching_account(gclient, monkeypatch):
    monkeypatch.setattr(google_auth.GoogleOIDC, "exchange_and_verify",
                        lambda self, code, verifier, nonce: {
                            "email": "vrwarp@gmail.com", "email_verified": True, "sub": "sub-123"})
    state = _begin(gclient)
    r = gclient.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert gclient.get("/").status_code == 200  # session granted


def test_google_login_wrong_account_rejected(gclient, monkeypatch):
    monkeypatch.setattr(google_auth.GoogleOIDC, "exchange_and_verify",
                        lambda self, code, verifier, nonce: {
                            "email": "attacker@gmail.com", "email_verified": True, "sub": "x"})
    state = _begin(gclient)
    r = gclient.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 403
    assert gclient.get("/", follow_redirects=False).status_code == 303  # no session


def test_google_login_unverified_email_rejected(gclient, monkeypatch):
    monkeypatch.setattr(google_auth.GoogleOIDC, "exchange_and_verify",
                        lambda self, code, verifier, nonce: {
                            "email": "vrwarp@gmail.com", "email_verified": False, "sub": "s"})
    state = _begin(gclient)
    r = gclient.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 403


def test_callback_state_mismatch_rejected(gclient, monkeypatch):
    monkeypatch.setattr(google_auth.GoogleOIDC, "exchange_and_verify",
                        lambda self, code, verifier, nonce: {"email": "vrwarp@gmail.com",
                                                             "email_verified": True})
    _begin(gclient)
    r = gclient.get("/auth/callback?code=abc&state=forged", follow_redirects=False)
    assert r.status_code == 403


def test_token_breakglass_still_works_when_google_enabled(gclient):
    r = gclient.post("/login", data={"token": "secret"}, follow_redirects=False)
    assert r.status_code == 303
    assert gclient.get("/").status_code == 200


def test_pkce_and_authorization_url():
    v, c = google_auth.new_pkce()
    assert v and c and v != c
    oidc = google_auth.GoogleOIDC("cid", "sec", "http://localhost:8081/auth/callback")
    url = oidc.authorization_url("st", "no", c)
    assert "code_challenge_method=S256" in url and "scope=openid" in url and "state=st" in url
