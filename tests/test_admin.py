"""Admin UI tests via Starlette TestClient (fast, no browser)."""

import pytest
from starlette.testclient import TestClient

from gmail_proxy.admin.app import build_admin_app


@pytest.fixture
def client(ctx):
    ctx.settings.admin_token = "secret"
    return TestClient(build_admin_app(ctx))


def _login(client):
    return client.post("/login", data={"token": "secret"}, follow_redirects=False)


def test_requires_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_bad_token_rejected(client):
    r = client.post("/login", data={"token": "nope"})
    assert r.status_code == 401


def test_login_and_dashboard(client):
    _login(client)
    r = client.get("/")
    assert r.status_code == 200 and "Dashboard" in r.text


def test_config_save_reloads_policy(client, ctx):
    _login(client)
    r = client.post("/config", data={
        "mode": "read_only", "allowed_categories": ["promotions"],
        "mutable_labels": "UNREAD", "max_body_bytes": "1024", "max_results_cap": "10",
        "per_minute": "30", "per_day": "1000",
    }, follow_redirects=False)
    assert r.status_code == 303
    assert ctx.policy.mode == "read_only"
    assert ctx.policy.allowed_categories == ["promotions"]


def test_config_rejects_invalid(client, ctx):
    _login(client)
    r = client.post("/config", data={
        "mode": "read_write", "allowed_categories": ["promotions"],
        "mutable_labels": "CATEGORY_PROMOTIONS",  # immutable -> rejected
        "max_body_bytes": "1024", "max_results_cap": "10",
        "per_minute": "30", "per_day": "1000",
    }, follow_redirects=False)
    assert "error=" in r.headers["location"]


def test_playground_runs_tool(client):
    _login(client)
    r = client.post("/playground", data={"tool": "gmail_counts"})
    assert r.status_code == 200 and "unread_by_category" in r.text


def test_explain(client):
    _login(client)
    r = client.get("/explain?id=m010")  # personal -> not eligible
    assert "NOT ELIGIBLE" in r.text


def test_freeze_unfreeze(client, ctx):
    _login(client)
    client.post("/freeze", follow_redirects=False)
    assert ctx.killswitch.is_frozen()
    client.post("/unfreeze", follow_redirects=False)
    assert not ctx.killswitch.is_frozen()


def test_credentials_issue(client, ctx):
    _login(client)
    before = len(ctx.credentials.list())
    r = client.post("/credentials/issue", data={"name": "vm-2", "mode": "read_write"},
                    follow_redirects=False)
    assert "new_token=ocgp_" in r.headers["location"]
    assert len(ctx.credentials.list()) == before + 1


def test_healthz_unauthenticated(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"
