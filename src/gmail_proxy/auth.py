"""Per-agent credential store + rate limiting.

Each OpenClaw instance authenticates to the proxy with its own high-entropy
bearer token.  Tokens are stored **hashed** (SHA-256) at rest; the plaintext is
shown exactly once at issue time.  Per-credential identity gives us audit
attribution, independent revocation, and per-credential rate limits.

(mTLS is the recommended stronger option in production; this bearer scheme is
the simpler default and is what the test suite exercises.)
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class Credential:
    id: str
    name: str
    token_sha256: str
    created: str
    revoked: bool = False
    mode: str = "read_write"  # per-credential cap: "read_only" narrows this agent
    note: str = ""


class CredentialStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._creds: dict[str, Credential] = {}
        self._by_hash: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            for row in json.loads(self.path.read_text() or "[]"):
                c = Credential(**row)
                self._creds[c.id] = c
                self._by_hash[c.token_sha256] = c.id

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps([asdict(c) for c in self._creds.values()], indent=2))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def issue(self, name: str, mode: str = "read_write", note: str = "") -> tuple[Credential, str]:
        """Create a credential; returns ``(cred, plaintext_token)`` (token shown once)."""
        token = "ocgp_" + secrets.token_urlsafe(32)
        cred = Credential(
            id="cred_" + secrets.token_hex(6),
            name=name,
            token_sha256=_hash_token(token),
            created=datetime.now(timezone.utc).isoformat(),
            mode=mode,
            note=note,
        )
        with self._lock:
            self._creds[cred.id] = cred
            self._by_hash[cred.token_sha256] = cred.id
            self._persist()
        return cred, token

    def revoke(self, cred_id: str) -> bool:
        with self._lock:
            c = self._creds.get(cred_id)
            if not c:
                return False
            c.revoked = True
            self._persist()
            return True

    def rotate(self, cred_id: str) -> str | None:
        """Issue a new token for an existing credential; returns new plaintext."""
        with self._lock:
            c = self._creds.get(cred_id)
            if not c or c.revoked:
                return None
            self._by_hash.pop(c.token_sha256, None)
            token = "ocgp_" + secrets.token_urlsafe(32)
            c.token_sha256 = _hash_token(token)
            self._by_hash[c.token_sha256] = c.id
            self._persist()
            return token

    def verify(self, token: str | None) -> Credential | None:
        """Constant-time-ish verification of a presented bearer token."""
        if not token:
            return None
        cid = self._by_hash.get(_hash_token(token))
        if cid is None:
            return None
        cred = self._creds[cid]
        return None if cred.revoked else cred

    def list(self) -> list[Credential]:
        return list(self._creds.values())


class RateLimiter:
    """Per-credential sliding-window limiter (in-memory, single process)."""

    def __init__(self, per_minute: int, per_day: int) -> None:
        self.per_minute = per_minute
        self.per_day = per_day
        self._minute: dict[str, deque[float]] = {}
        self._day: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, actor: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        with self._lock:
            m = self._minute.setdefault(actor, deque())
            d = self._day.setdefault(actor, deque())
            while m and now - m[0] > 60:
                m.popleft()
            while d and now - d[0] > 86400:
                d.popleft()
            if len(m) >= self.per_minute or len(d) >= self.per_day:
                return False
            m.append(now)
            d.append(now)
            return True
