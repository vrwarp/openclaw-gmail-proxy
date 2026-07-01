"""Tests for the per-agent credential store and rate limiter."""

from gmail_proxy.auth import CredentialStore, RateLimiter


def test_issue_verify_revoke(tmp_path):
    store = CredentialStore(tmp_path / "creds.json")
    cred, token = store.issue("agent-1")
    assert store.verify(token).id == cred.id
    assert store.verify("wrong") is None
    assert store.verify(None) is None
    store.revoke(cred.id)
    assert store.verify(token) is None


def test_token_stored_hashed(tmp_path):
    path = tmp_path / "creds.json"
    store = CredentialStore(path)
    _, token = store.issue("agent")
    assert token not in path.read_text()  # plaintext never persisted


def test_rotate_invalidates_old(tmp_path):
    store = CredentialStore(tmp_path / "creds.json")
    cred, token = store.issue("agent")
    new = store.rotate(cred.id)
    assert store.verify(token) is None
    assert store.verify(new).id == cred.id


def test_persistence_reload(tmp_path):
    path = tmp_path / "creds.json"
    store = CredentialStore(path)
    cred, token = store.issue("agent")
    store2 = CredentialStore(path)  # reload from disk
    assert store2.verify(token).id == cred.id


def test_rate_limiter_minute():
    rl = RateLimiter(per_minute=3, per_day=1000)
    assert all(rl.check("a", now=100.0 + i) for i in range(3))
    assert rl.check("a", now=103.0) is False
    # a different actor is independent
    assert rl.check("b", now=103.0) is True
    # window slides
    assert rl.check("a", now=200.0) is True
