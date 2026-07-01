"""Abstract Gmail backend interface.

The tool layer only ever talks to this interface, never to raw Gmail JSON.  Two
implementations exist: :class:`~gmail_proxy.gmail.mock_client.MockGmail` (in
memory, for tests + the demo) and
:class:`~gmail_proxy.gmail.google_client.GoogleGmail` (the real API).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Label, Message, Thread


class GmailError(Exception):
    """Raised by a backend when an upstream Gmail call fails (fail-closed)."""


class NotConnectedError(GmailError):
    """Gmail has not been connected yet (complete setup in the admin UI)."""


class GmailBackend(ABC):
    @abstractmethod
    def list_message_ids(
        self, q: str, max_results: int, page_token: str | None
    ) -> tuple[list[str], str | None]:
        """Return ``(message_ids, next_page_token)`` for a sanitized query."""

    @abstractmethod
    def get_message(self, message_id: str) -> Message:
        """Full message (headers + body + labels).  Raises KeyError if absent."""

    @abstractmethod
    def get_message_metadata(self, message_id: str) -> Message:
        """Labels + minimal headers only -- used for the eligibility re-check."""

    @abstractmethod
    def get_thread(self, thread_id: str) -> Thread:
        ...

    @abstractmethod
    def modify_labels(
        self, message_id: str, add_ids: list[str], remove_ids: list[str]
    ) -> Message:
        ...

    @abstractmethod
    def trash(self, message_id: str) -> Message:
        ...

    @abstractmethod
    def list_labels(self) -> list[Label]:
        ...

    @abstractmethod
    def get_profile(self) -> dict:
        """``{"emailAddress": ..., "messagesTotal": ...}``."""


class NotConnectedBackend(GmailBackend):
    """Placeholder backend used before Gmail is connected. Every call fails
    closed with :class:`NotConnectedError` so tools deny cleanly; the admin UI
    reports the disconnected state and offers the connect flow."""

    def _fail(self):
        raise NotConnectedError("Gmail is not connected — finish setup in the admin UI")

    def list_message_ids(self, q, max_results, page_token):
        self._fail()

    def get_message(self, message_id):
        self._fail()

    def get_message_metadata(self, message_id):
        self._fail()

    def get_thread(self, thread_id):
        self._fail()

    def modify_labels(self, message_id, add_ids, remove_ids):
        self._fail()

    def trash(self, message_id):
        self._fail()

    def list_labels(self):
        self._fail()

    def get_profile(self):
        self._fail()
