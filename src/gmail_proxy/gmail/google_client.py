"""Real Gmail backend built on ``google-api-python-client``.

Requires a bootstrapped, encrypted refresh token (see ``scripts/oauth_bootstrap.py``).
Not exercised by the credential-free test run, but wired for production.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from ..models import Attachment, Label, Message, Thread
from .client import GmailBackend, GmailError
from .token_store import TokenStore

SCOPES_MODIFY = ["https://www.googleapis.com/auth/gmail.modify"]
SCOPES_READONLY = ["https://www.googleapis.com/auth/gmail.readonly"]

_META_HEADERS = ["From", "Subject", "Date"]


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class GoogleGmail(GmailBackend):
    def __init__(self, token_store: TokenStore, client_id: str, client_secret: str) -> None:
        from google.oauth2.credentials import Credentials  # lazy import

        token = token_store.load()
        self._store = token_store
        self._creds = Credentials(
            token=token.get("access_token"),
            refresh_token=token["refresh_token"],
            token_uri=token.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=client_id,
            client_secret=client_secret,
            scopes=token.get("scopes", SCOPES_MODIFY),
        )
        from googleapiclient.discovery import build  # lazy import

        self._svc = build("gmail", "v1", credentials=self._creds, cache_discovery=False)

    def _persist_token(self) -> None:
        self._store.save(
            {
                "access_token": self._creds.token,
                "refresh_token": self._creds.refresh_token,
                "token_uri": self._creds.token_uri,
                "scopes": list(self._creds.scopes or []),
            }
        )

    # --- mapping helpers --------------------------------------------------
    def _headers(self, payload: dict) -> dict[str, str]:
        return {h["name"]: h["value"] for h in payload.get("headers", [])}

    def _extract_body(self, payload: dict) -> tuple[str, str, list[Attachment]]:
        text, html, atts = "", "", []

        def walk(part: dict) -> None:
            nonlocal text, html
            mime = part.get("mimeType", "")
            body = part.get("body", {})
            filename = part.get("filename") or ""
            if filename:
                atts.append(Attachment(filename, mime, int(body.get("size", 0))))
            elif mime == "text/plain" and body.get("data"):
                text += _b64url_decode(body["data"]).decode("utf-8", "replace")
            elif mime == "text/html" and body.get("data"):
                html += _b64url_decode(body["data"]).decode("utf-8", "replace")
            for sub in part.get("parts", []) or []:
                walk(sub)

        walk(payload)
        return text, html, atts

    def _to_message(self, raw: dict) -> Message:
        payload = raw.get("payload", {})
        headers = self._headers(payload)
        text, html, atts = self._extract_body(payload)
        internal = raw.get("internalDate")
        iso = (
            datetime.fromtimestamp(int(internal) / 1000, tz=timezone.utc).isoformat()
            if internal
            else ""
        )
        return Message(
            id=raw["id"], thread_id=raw.get("threadId", raw["id"]),
            label_ids=list(raw.get("labelIds", [])), headers=headers,
            body_text=text, body_html=html, snippet=raw.get("snippet", ""),
            history_id=int(raw.get("historyId", 0)), internal_date=iso, attachments=atts,
        )

    # --- backend interface ------------------------------------------------
    def list_message_ids(self, q, max_results, page_token):
        try:
            resp = (
                self._svc.users().messages()
                .list(userId="me", q=q, maxResults=max_results, pageToken=page_token,
                      includeSpamTrash=False)
                .execute()
            )
        except Exception as e:  # noqa: BLE001 - fail closed
            raise GmailError(str(e)) from e
        ids = [m["id"] for m in resp.get("messages", [])]
        return ids, resp.get("nextPageToken")

    def get_message(self, message_id):
        try:
            raw = self._svc.users().messages().get(userId="me", id=message_id, format="full").execute()
        except Exception as e:  # noqa: BLE001
            raise GmailError(str(e)) from e
        return self._to_message(raw)

    def get_message_metadata(self, message_id):
        try:
            raw = (
                self._svc.users().messages()
                .get(userId="me", id=message_id, format="metadata", metadataHeaders=_META_HEADERS)
                .execute()
            )
        except Exception as e:  # noqa: BLE001
            raise GmailError(str(e)) from e
        return self._to_message(raw)

    def get_thread(self, thread_id):
        try:
            raw = self._svc.users().threads().get(userId="me", id=thread_id, format="full").execute()
        except Exception as e:  # noqa: BLE001
            raise GmailError(str(e)) from e
        msgs = [self._to_message(m) for m in raw.get("messages", [])]
        return Thread(id=thread_id, messages=msgs, history_id=int(raw.get("historyId", 0)))

    def modify_labels(self, message_id, add_ids, remove_ids):
        try:
            raw = (
                self._svc.users().messages()
                .modify(userId="me", id=message_id,
                        body={"addLabelIds": add_ids, "removeLabelIds": remove_ids})
                .execute()
            )
        except Exception as e:  # noqa: BLE001
            raise GmailError(str(e)) from e
        return self._to_message(raw)

    def trash(self, message_id):
        try:
            raw = self._svc.users().messages().trash(userId="me", id=message_id).execute()
        except Exception as e:  # noqa: BLE001
            raise GmailError(str(e)) from e
        return self._to_message(raw)

    def list_labels(self):
        try:
            resp = self._svc.users().labels().list(userId="me").execute()
        except Exception as e:  # noqa: BLE001
            raise GmailError(str(e)) from e
        return [
            Label(id=l["id"], name=l["name"], type=l.get("type", "user"))
            for l in resp.get("labels", [])
        ]

    def get_profile(self):
        try:
            return self._svc.users().getProfile(userId="me").execute()
        except Exception as e:  # noqa: BLE001
            raise GmailError(str(e)) from e
