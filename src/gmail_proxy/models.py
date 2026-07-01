"""Internal data models shared by the Gmail backends and the tool layer."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Attachment:
    filename: str
    mime_type: str
    size: int


@dataclass
class Message:
    """Backend-neutral representation of a Gmail message.

    Both the mock backend and the real ``googleapis`` client materialize into
    this shape so the policy/tool layer never touches raw Gmail JSON.
    """

    id: str
    thread_id: str
    label_ids: list[str]
    headers: dict[str, str] = field(default_factory=dict)  # canonical name -> value
    body_text: str = ""
    body_html: str = ""
    snippet: str = ""
    history_id: int = 0
    internal_date: str = ""  # ISO-8601 UTC
    attachments: list[Attachment] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        # case-insensitive lookup
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


@dataclass
class Thread:
    id: str
    messages: list[Message]
    history_id: int = 0


@dataclass
class Label:
    id: str
    name: str
    type: str  # "system" | "user"
