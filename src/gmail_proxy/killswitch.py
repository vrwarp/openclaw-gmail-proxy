"""Persisted kill-switch (global freeze).

When frozen, every tool call fails closed with ``frozen``.  Toggled from the
admin UI; survives restarts via a flag file.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class KillSwitch:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def is_frozen(self) -> bool:
        return self.path.exists()

    def freeze(self, reason: str = "manual") -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"reason": reason, "since": datetime.now(timezone.utc).isoformat()})
        )

    def unfreeze(self) -> None:
        if self.path.exists():
            self.path.unlink()

    def status(self) -> dict:
        if not self.is_frozen():
            return {"frozen": False}
        try:
            data = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            data = {}
        return {"frozen": True, **data}
