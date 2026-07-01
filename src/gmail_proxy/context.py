"""Application context: bundles policy, backend, and the operational services."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLog
from .auth import CredentialStore, RateLimiter
from .config import Policy, Settings, load_policy
from .gmail.client import GmailBackend
from .gmail.mock_client import sample_backend
from .killswitch import KillSwitch


def _persisted_secret(path: Path, nbytes: int = 32) -> bytes:
    if path.exists():
        return bytes.fromhex(path.read_text().strip())
    path.parent.mkdir(parents=True, exist_ok=True)
    val = secrets.token_bytes(nbytes)
    path.write_text(val.hex())
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return val


@dataclass
class AppContext:
    settings: Settings
    policy: Policy
    backend: GmailBackend
    audit: AuditLog
    credentials: CredentialStore
    ratelimiter: RateLimiter
    killswitch: KillSwitch
    sender_salt: bytes

    def reload_policy(self) -> None:
        self.policy = load_policy(self.settings.policy_path)
        self.ratelimiter = RateLimiter(
            self.policy.rate_limits.per_minute, self.policy.rate_limits.per_day
        )


def _make_backend(settings: Settings) -> GmailBackend:
    if settings.gmail_backend == "google":
        from .gmail.google_client import GoogleGmail
        from .gmail.token_store import TokenStore

        secret = ""
        if settings.google_client_secret_file:
            secret = Path(settings.google_client_secret_file).read_text().strip()
        store = TokenStore(settings.token_store_path, settings.token_encryption_key)
        return GoogleGmail(store, settings.google_client_id or "", secret)
    return sample_backend()


def build_context(
    settings: Settings,
    *,
    backend: GmailBackend | None = None,
    policy: Policy | None = None,
) -> AppContext:
    data = Path(settings.data_dir)
    data.mkdir(parents=True, exist_ok=True)
    policy = policy or load_policy(settings.policy_path)
    keys = data / "keys"
    audit_key = _persisted_secret(keys / "audit_hmac.key")
    sender_salt = _persisted_secret(keys / "sender_salt.key")
    return AppContext(
        settings=settings,
        policy=policy,
        backend=backend or _make_backend(settings),
        audit=AuditLog(data / "audit.log", hmac_key=audit_key),
        credentials=CredentialStore(data / "credentials.json"),
        ratelimiter=RateLimiter(policy.rate_limits.per_minute, policy.rate_limits.per_day),
        killswitch=KillSwitch(data / "FROZEN"),
        sender_salt=sender_salt,
    )
