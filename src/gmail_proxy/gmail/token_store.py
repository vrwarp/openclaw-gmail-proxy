"""Encrypted-at-rest OAuth token store.

The refresh token is the crown jewel: whoever holds it can read the whole
mailbox.  It lives only on the proxy host, encrypted with a Fernet key supplied
out of band (``TOKEN_ENCRYPTION_KEY``).  It is never exposed to the VM.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet


class TokenStore:
    def __init__(self, path: str | os.PathLike[str], encryption_key: str | None) -> None:
        self.path = Path(path)
        self._fernet = Fernet(encryption_key.encode()) if encryption_key else None

    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode()

    def save(self, token: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(token).encode()
        data = self._fernet.encrypt(raw) if self._fernet else raw
        # 0600, atomic write.
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def load(self) -> dict:
        data = self.path.read_bytes()
        raw = self._fernet.decrypt(data) if self._fernet else data
        return json.loads(raw)

    def exists(self) -> bool:
        return self.path.exists()
