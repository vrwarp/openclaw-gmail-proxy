"""Append-only, hash-chained audit log.

Every tool call -- allowed or denied -- is recorded with the calling identity,
the tool, sanitized arguments, the decision + enum reason, and the message ids
touched.  Each record carries an HMAC over ``(prev_hash || record)`` forming a
tamper-evident chain: an operator can detect truncation/edits after the fact.

This is intentionally simple (a JSONL file), not the rev-14 anti-rollback store.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | os.PathLike[str], hmac_key: bytes | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = hmac_key
        self._lock = threading.Lock()
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = "0" * 64
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line).get("hash", last)
                    except json.JSONDecodeError:
                        continue
        return last

    def record(
        self,
        *,
        actor: str,
        tool: str,
        decision: str,          # "allow" | "deny"
        reason: str | None = None,
        args: dict | None = None,
        message_ids: list[str] | None = None,
        detail: str | None = None,
    ) -> dict:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "tool": tool,
            "decision": decision,
            "reason": reason,
            "args": args or {},
            "message_ids": message_ids or [],
            "detail": detail,
        }
        with self._lock:
            entry["prev"] = self._last_hash
            body = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
            if self._key:
                digest = hmac.new(self._key, self._last_hash.encode() + body, hashlib.sha256).hexdigest()
            else:
                digest = hashlib.sha256(self._last_hash.encode() + body).hexdigest()
            entry["hash"] = digest
            self._last_hash = digest
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        return entry

    def tail(self, limit: int = 200) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines[-limit:]:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return list(reversed(out))

    def verify_chain(self) -> bool:
        """Recompute the chain and confirm no record was altered/removed."""
        prev = "0" * 64
        if not self.path.exists():
            return True
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            stored = rec.pop("hash")
            if rec.get("prev") != prev:
                return False
            body = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
            if self._key:
                digest = hmac.new(self._key, prev.encode() + body, hashlib.sha256).hexdigest()
            else:
                digest = hashlib.sha256(prev.encode() + body).hexdigest()
            if digest != stored:
                return False
            prev = stored
        return True
