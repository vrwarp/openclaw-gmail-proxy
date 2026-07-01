"""Output formatting: header allowlist, body minimization, untrusted framing.

Two ideas carry over from the design (right-sized -- no Ed25519 signing):

1. **Minimization.** Only allowlisted headers are returned; other recipients
   (To/Cc/Bcc/...) are dropped; HTML is sanitized to text; attachments are
   stripped and replaced with a marker; the body is truncated to a byte cap.
2. **Untrusted framing.** Every attacker-derived field (From/Subject/body) is
   wrapped as ``{"untrusted": true, "provenance": ..., "content": ...}`` so the
   agent's skill instructions can treat it as data, never as instructions.
"""

from __future__ import annotations

import hashlib
import hmac
import re

import bleach

from .config import Policy
from .models import Message


def sender_token(addr: str, salt: bytes) -> str:
    return "sender:" + hmac.new(salt, addr.strip().lower().encode(), hashlib.sha256).hexdigest()[:12]


def untrusted(content: str, provenance: str) -> dict:
    encoded = content.encode("utf-8", "replace")
    return {
        "untrusted": True,
        "provenance": provenance,
        "content_len": len(encoded),
        "content": content,
    }


def _html_to_text(html: str) -> str:
    # Drop raw-text elements entirely FIRST: bleach with strip=True removes the
    # <script>/<style> tags but KEEPS their text content, which must not surface.
    html = re.sub(r"(?is)<(script|style|template|noscript|head)\b[^>]*>.*?</\1>", " ", html)
    text = bleach.clean(html, tags=[], attributes={}, strip=True)
    return " ".join(text.split())


def minimize_headers(msg: Message, policy: Policy, salt: bytes) -> dict:
    out: dict[str, object] = {}
    for name in policy.return_headers:
        val = msg.header(name)
        if val is None:
            continue
        if name == "From":
            if policy.redact_sender_address:
                out["from"] = untrusted(sender_token(val, salt), "gmail_from_token")
            else:
                out["from"] = untrusted(val, "gmail_from")
        elif name == "Subject":
            out["subject"] = untrusted(val, "gmail_subject")
        elif name == "Date":
            out["date"] = val  # trusted-ish; a structured date
        else:
            out[name.lower()] = untrusted(val, "gmail_header")
    return out


def minimize_body(msg: Message, policy: Policy) -> tuple[dict, dict]:
    """Return ``(body_block, flags)``."""
    text = msg.body_text or (_html_to_text(msg.body_html) if msg.body_html else "")
    had_attachments = bool(msg.attachments)
    encoded = text.encode("utf-8", "replace")
    truncated = len(encoded) > policy.max_body_bytes
    if truncated:
        text = encoded[: policy.max_body_bytes].decode("utf-8", "ignore")
    if had_attachments:
        text = text + "\n[attachments removed]"
    return untrusted(text, "gmail_message_body"), {
        "truncated": truncated,
        "had_attachments": had_attachments,
    }


def format_summary(msg: Message, policy: Policy, salt: bytes) -> dict:
    headers = minimize_headers(msg, policy, salt)
    return {"id": msg.id, "thread_id": msg.thread_id, **headers,
            "snippet": untrusted(msg.snippet, "gmail_snippet")}


def format_detail(msg: Message, policy: Policy, salt: bytes) -> dict:
    headers = minimize_headers(msg, policy, salt)
    body, flags = minimize_body(msg, policy)
    result = {"id": msg.id, "thread_id": msg.thread_id, **headers, "body": body}
    result["_flags"] = flags
    if policy.allow_attachments and msg.attachments:
        result["attachments"] = [
            {"filename": a.filename, "mime_type": a.mime_type, "size": a.size}
            for a in msg.attachments
        ]
    return result
