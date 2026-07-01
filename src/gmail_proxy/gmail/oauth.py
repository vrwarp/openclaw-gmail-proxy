"""Gmail *data* OAuth: connect the mailbox from the admin UI.

This is the offline Authorization-Code + PKCE flow that yields a **refresh
token** for the Gmail API (scope ``gmail.modify`` or ``gmail.readonly``) -- the
credential the proxy uses to call Gmail. It is distinct from the admin *login*
OIDC flow. The Google client id/secret are supplied once (via the Setup page)
and stored under the data dir; the resulting token is stored encrypted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlencode

import httpx

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"

SCOPE_MODIFY = "https://www.googleapis.com/auth/gmail.modify"
SCOPE_READONLY = "https://www.googleapis.com/auth/gmail.readonly"


def new_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


@dataclass
class OAuthClient:
    client_id: str
    client_secret: str
    redirect_uri: str


class OAuthClientStore:
    """Persists the Google OAuth *client* config (id/secret/redirect) as JSON."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> OAuthClient | None:
        if not self.path.exists():
            return None
        data = json.loads(self.path.read_text())
        return OAuthClient(**data)

    def save(self, client: OAuthClient) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(client), indent=2))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)


def authorization_url(client: OAuthClient, state: str, code_challenge: str,
                      scope: str = SCOPE_MODIFY) -> str:
    params = {
        "client_id": client.client_id,
        "redirect_uri": client.redirect_uri,
        "response_type": "code",
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",   # ask for a refresh token
        "prompt": "consent",        # force a refresh token even on re-consent
        "include_granted_scopes": "false",
    }
    return f"{AUTH_ENDPOINT}?{urlencode(params)}"


def exchange_code(client: OAuthClient, code: str, code_verifier: str) -> dict:
    """Exchange an auth code for tokens. Returns a token dict for TokenStore.

    Raises if no refresh token is returned (re-consent required).
    """
    resp = httpx.post(
        TOKEN_ENDPOINT,
        data={
            "code": code,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "redirect_uri": client.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        },
        timeout=15,
    )
    resp.raise_for_status()
    body = resp.json()
    if not body.get("refresh_token"):
        raise ValueError(
            "Google did not return a refresh token. Revoke prior access at "
            "https://myaccount.google.com/permissions and try again."
        )
    return {
        "access_token": body.get("access_token"),
        "refresh_token": body["refresh_token"],
        "token_uri": TOKEN_ENDPOINT,
        "scopes": (body.get("scope") or "").split(),
    }
