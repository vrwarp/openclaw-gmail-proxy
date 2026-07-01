"""Application context: bundles policy, backend, and the operational services."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLog
from .auth import CredentialStore, RateLimiter
from .cache import CachingGmailBackend
from .config import Policy, Settings, load_policy
from .gmail.client import GmailBackend, NotConnectedBackend
from .gmail.mock_client import sample_backend
from .gmail.oauth import OAuthClientStore
from .gmail.token_store import TokenStore
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


def _resolve_admin_token(settings: Settings, data: Path) -> tuple[str, bool]:
    """The admin-UI login token. Returns ``(token, generated)``.

    Uses ``ADMIN_TOKEN`` when set; otherwise generates a random token, persists
    it under the data dir (so sessions survive restarts and the operator can
    always retrieve it), and flags it as generated so startup prints it."""
    if settings.admin_token:
        return settings.admin_token, False
    path = data / "keys" / "admin_token"
    if path.exists():
        return path.read_text().strip(), True
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return token, True


def _resolve_encryption_key(settings: Settings, data: Path) -> str:
    """The Fernet key for the token store: the env value (out-of-band, stronger),
    or an auto-generated key persisted under the data dir (convenient default)."""
    if settings.token_encryption_key:
        return settings.token_encryption_key
    keyfile = data / "keys" / "token_fernet.key"
    if keyfile.exists():
        return keyfile.read_text().strip()
    key = TokenStore.generate_key()
    keyfile.parent.mkdir(parents=True, exist_ok=True)
    keyfile.write_text(key)
    try:
        keyfile.chmod(0o600)
    except OSError:
        pass
    return key


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
    data_dir: Path
    admin_token_generated: bool = False

    # --- policy -----------------------------------------------------------
    def reload_policy(self) -> None:
        self.policy = load_policy(self.settings.policy_path)
        self.ratelimiter = RateLimiter(
            self.policy.rate_limits.per_minute, self.policy.rate_limits.per_day
        )
        if isinstance(self.backend, CachingGmailBackend):
            self.backend.reconfigure(self.policy.cache)

    # --- Gmail connection (web-UI setup) ---------------------------------
    def token_store(self) -> TokenStore:
        return TokenStore(self.settings.token_store_path,
                          _resolve_encryption_key(self.settings, self.data_dir))

    def oauth_client_store(self) -> OAuthClientStore:
        return OAuthClientStore(self.data_dir / "gmail_oauth.json")

    def gmail_client_creds(self) -> tuple[str | None, str | None]:
        """(client_id, client_secret) from the stored OAuth client, else env."""
        return _resolve_client_creds(self.settings, self.data_dir)

    def rebuild_backend(self) -> None:
        self.backend = CachingGmailBackend(
            _make_backend(self.settings, self.data_dir), self.policy.cache
        )

    def connect_gmail(self, token: dict) -> None:
        self.token_store().save(token)
        self.rebuild_backend()

    def disconnect_gmail(self) -> None:
        p = Path(self.settings.token_store_path)
        if p.exists():
            p.unlink()
        self.rebuild_backend()

    def gmail_status(self) -> dict:
        s = self.settings
        client_id, client_secret = self.gmail_client_creds()
        client_configured = bool(client_id and client_secret)
        # Demo mode: mock backend with no real OAuth client configured. As soon
        # as a client is configured we present the real-Gmail connection flow so
        # the operator can connect from the Setup page.
        demo = s.gmail_backend != "google" and not client_configured
        status = {
            "backend": s.gmail_backend,
            "demo": demo,
            "client_configured": client_configured,
            "token_present": self.token_store().exists(),
            "connected": False,
            "email": None,
            "scopes": [],
            "error": None,
            "error_hint": None,
        }
        if demo:
            status.update(connected=True, email="(mock backend)")
            return status
        if client_configured and status["token_present"]:
            try:
                profile = self.backend.get_profile()
                status.update(connected=True, email=profile.get("emailAddress"))
                tok = self.token_store().load()
                status["scopes"] = tok.get("scopes", [])
            except Exception as e:  # noqa: BLE001 - surface, don't hide
                msg = str(e)
                status["error"] = msg[:400]
                status["error_hint"] = _gmail_error_hint(msg)
        return status


def _gmail_error_hint(msg: str) -> str:
    """Turn a raw Gmail API error into an actionable one-liner for the UI."""
    low = msg.lower()
    if ("accessnotconfigured" in low or "has not been used in project" in low
            or ("gmail api" in low and "disabl" in low)):
        return ("The Gmail API is not enabled for this OAuth client's Google Cloud "
                "project. Open the API Library, enable “Gmail API”, wait a minute, "
                "then click Connect Gmail again.")
    if "invalid_grant" in low or "expired or revoked" in low:
        return "The Google authorization expired or was revoked — click Connect Gmail to re-authorize."
    if "insufficient" in low and "scope" in low:
        return "The granted scopes are insufficient — reconnect and approve the requested Gmail access."
    if "access_denied" in low or "accessdenied" in low:
        return ("Google denied access. If the app is in “Testing”, add your account as a test user on "
                "the OAuth consent screen, and confirm the Gmail API is enabled.")
    return ""


def _resolve_client_creds(settings: Settings, data: Path) -> tuple[str | None, str | None]:
    """(client_id, client_secret) from the stored OAuth client, else env/file."""
    client = OAuthClientStore(data / "gmail_oauth.json").load()
    if client:
        return client.client_id, client.client_secret
    client_secret = None
    if settings.google_client_secret_file and Path(settings.google_client_secret_file).exists():
        client_secret = Path(settings.google_client_secret_file).read_text().strip()
    return settings.google_client_id, client_secret


def _make_backend(settings: Settings, data: Path) -> GmailBackend:
    client_id, client_secret = _resolve_client_creds(settings, data)
    client_configured = bool(client_id and client_secret)

    # Demo mode: the mock backend with NO real OAuth client configured. Once a
    # client is configured (or GMAIL_BACKEND=google), switch to real Gmail so the
    # whole connection can be driven from the Setup page even on the default
    # (mock) image.
    if settings.gmail_backend != "google" and not client_configured:
        return sample_backend()

    store = TokenStore(settings.token_store_path, _resolve_encryption_key(settings, data))
    if not (client_configured and store.exists()):
        return NotConnectedBackend()

    from .gmail.google_client import GoogleGmail
    try:
        return GoogleGmail(store, client_id, client_secret)
    except Exception:  # noqa: BLE001 - bad/partial token -> present as not connected
        return NotConnectedBackend()


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
    settings.admin_token, admin_token_generated = _resolve_admin_token(settings, data)
    return AppContext(
        settings=settings,
        policy=policy,
        backend=CachingGmailBackend(backend or _make_backend(settings, data), policy.cache),
        audit=AuditLog(data / "audit.log", hmac_key=audit_key),
        credentials=CredentialStore(data / "credentials.json"),
        ratelimiter=RateLimiter(policy.rate_limits.per_minute, policy.rate_limits.per_day),
        killswitch=KillSwitch(data / "FROZEN"),
        sender_salt=sender_salt,
        data_dir=data,
        admin_token_generated=admin_token_generated,
    )
