"""Google OIDC ("Sign in with Google") for the admin UI.

A separate, interactive Authorization-Code + PKCE flow — distinct from the Gmail
*data* grant. On callback the ID token is verified (signature via Google's certs,
`iss`/`aud`/`exp`, `email_verified`, `nonce`) and the login is accepted ONLY if
the account matches the proxied mailbox's pinned email/sub.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import urlencode

import httpx

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
SCOPES = "openid email profile"


def new_pkce() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` for PKCE S256."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def random_token() -> str:
    return secrets.token_urlsafe(24)


class GoogleOIDC:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "online",
            "prompt": "select_account",
        }
        return f"{AUTH_ENDPOINT}?{urlencode(params)}"

    def exchange_and_verify(self, code: str, code_verifier: str, expected_nonce: str) -> dict:
        """Exchange the auth code and verify the ID token. Returns verified claims.

        Raises on any failure (network, invalid token, nonce mismatch).
        """
        resp = httpx.post(
            TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "redirect_uri": self.redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": code_verifier,
            },
            timeout=15,
        )
        resp.raise_for_status()
        id_token_str = resp.json()["id_token"]

        from google.auth.transport import requests as ga_requests
        from google.oauth2 import id_token as ga_id_token

        claims = ga_id_token.verify_oauth2_token(
            id_token_str, ga_requests.Request(), audience=self.client_id
        )
        if claims.get("nonce") != expected_nonce:
            raise ValueError("nonce mismatch")
        return claims
