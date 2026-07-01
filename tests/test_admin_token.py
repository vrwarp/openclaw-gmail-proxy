"""When ADMIN_TOKEN is unset, a random token is generated, persisted, and used."""

from starlette.testclient import TestClient

from gmail_proxy.admin.app import build_admin_app
from gmail_proxy.config import Policy, Settings
from gmail_proxy.context import build_context
from gmail_proxy.gmail.mock_client import sample_backend


def _ctx(tmp_path, **settings_kw):
    settings = Settings(data_dir=str(tmp_path), gmail_backend="mock", **settings_kw)
    return build_context(settings, backend=sample_backend(),
                         policy=Policy(allowed_categories=["promotions"]))


def test_env_token_used_verbatim(tmp_path):
    ctx = _ctx(tmp_path, admin_token="pinned")
    assert ctx.admin_token_generated is False
    assert ctx.settings.admin_token == "pinned"
    assert not (tmp_path / "keys" / "admin_token").exists()


def test_unset_token_is_generated_and_persisted(tmp_path):
    ctx = _ctx(tmp_path)  # no admin_token
    assert ctx.admin_token_generated is True
    token = ctx.settings.admin_token
    assert token and len(token) >= 32
    # Persisted to disk so it survives restarts / can be retrieved from logs.
    keyfile = tmp_path / "keys" / "admin_token"
    assert keyfile.read_text().strip() == token


def test_generated_token_is_stable_across_rebuilds(tmp_path):
    first = _ctx(tmp_path).settings.admin_token
    second = _ctx(tmp_path).settings.admin_token  # same data_dir -> same token
    assert first == second


def test_login_requires_the_generated_token(tmp_path):
    ctx = _ctx(tmp_path)
    client = TestClient(build_admin_app(ctx))
    # The old insecure default no longer works.
    assert client.post("/login", data={"token": "dev-insecure"},
                       follow_redirects=False).status_code == 401
    # The generated token does.
    r = client.post("/login", data={"token": ctx.settings.admin_token},
                    follow_redirects=False)
    assert r.status_code == 303
