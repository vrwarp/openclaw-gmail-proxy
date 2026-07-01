#!/usr/bin/env python3
"""One-time OAuth bootstrap: obtain an encrypted refresh token for the proxy.

Run this ONCE on the proxy host with a Desktop-app OAuth client from your Google
Cloud project (Gmail API enabled).  It opens a browser, you approve the scope,
and the refresh token is written encrypted to the token store.  The VM never
sees any of this.

    python scripts/oauth_bootstrap.py --client-secret ./secrets/client_secret.json \
        --out ./secrets/token.json --encryption-key "$TOKEN_ENCRYPTION_KEY"
"""

from __future__ import annotations

import argparse
import os
import sys

SCOPE_MODIFY = "https://www.googleapis.com/auth/gmail.modify"
SCOPE_READONLY = "https://www.googleapis.com/auth/gmail.readonly"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--client-secret", required=True, help="path to Desktop OAuth client_secret.json")
    ap.add_argument("--out", default="./secrets/token.json")
    ap.add_argument("--encryption-key", default=os.environ.get("TOKEN_ENCRYPTION_KEY"))
    ap.add_argument("--readonly", action="store_true", help="request gmail.readonly instead of gmail.modify")
    args = ap.parse_args()

    from google_auth_oauthlib.flow import InstalledAppFlow

    from gmail_proxy.gmail.token_store import TokenStore

    scopes = [SCOPE_READONLY if args.readonly else SCOPE_MODIFY]
    flow = InstalledAppFlow.from_client_secrets_file(args.client_secret, scopes=scopes)
    creds = flow.run_local_server(port=0, access_type="offline", prompt="consent")

    if not creds.refresh_token:
        print("ERROR: no refresh token returned. Revoke the prior grant at "
              "https://myaccount.google.com/permissions and retry.", file=sys.stderr)
        return 1

    token = {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "scopes": list(creds.scopes or scopes),
    }
    if not args.encryption_key:
        print("WARNING: no --encryption-key/TOKEN_ENCRYPTION_KEY; token will be stored in PLAINTEXT.",
              file=sys.stderr)
    TokenStore(args.out, args.encryption_key).save(token)
    print(f"Saved {'encrypted ' if args.encryption_key else ''}token to {args.out}")
    print(f"Scopes: {token['scopes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
