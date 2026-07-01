"""Uniform, content-free error taxonomy for the proxy.

Every refusal raised by the policy engine or tool layer is a :class:`ProxyError`
carrying an HTTP-ish ``code`` and an *enumerated* ``reason``.  Reasons are drawn
from a fixed set so that no attacker-controlled substring is ever reflected back
to the agent (the raw detail goes only to the audit log).
"""

from __future__ import annotations

# --- Enumerated refusal reasons (stable wire values) -----------------------
REASONS: frozenset[str] = frozenset(
    {
        "not_eligible",          # message/thread not in an allowed category
        "query_rejected",        # search query failed sanitization
        "label_immutable",       # attempt to mutate a protected label
        "label_unresolvable",    # label name did not resolve to exactly one label
        "category_mutation_forbidden",  # attempt to add/remove a CATEGORY_* label
        "mutation_not_allowed",  # write attempted while in read-only mode
        "trash_not_allowed",     # trash tool disabled by policy
        "capability_denied",     # tool/param not exposed
        "unauthorized",          # missing/invalid agent credential
        "rate_limited",          # per-credential rate limit exceeded
        "frozen",                # kill-switch engaged
        "upstream_error",        # Gmail call failed; fail closed
        "internal_error",        # unexpected exception; fail closed, content-free
        "invalid_arguments",     # schema/validation failure
        "not_found",             # id not found (uniform, no oracle)
        "reclassified",          # message left scope between read and write
    }
)


class ProxyError(Exception):
    """A refusal with an HTTP-ish status code and an enumerated reason.

    ``detail`` is for the audit log / operator only and is NEVER returned to the
    agent verbatim.
    """

    def __init__(self, code: int, reason: str, detail: str | None = None) -> None:
        if reason not in REASONS:
            raise ValueError(f"unknown refusal reason: {reason!r}")
        self.code = code
        self.reason = reason
        self.detail = detail
        super().__init__(f"{code} {reason}" + (f": {detail}" if detail else ""))

    def to_public(self) -> dict[str, object]:
        """The agent-facing representation: code + enum reason only."""
        return {"code": self.code, "reason": self.reason}


# Convenience constructors -------------------------------------------------

def not_eligible(detail: str | None = None) -> ProxyError:
    return ProxyError(403, "not_eligible", detail)


def query_rejected(detail: str | None = None) -> ProxyError:
    return ProxyError(400, "query_rejected", detail)


def capability_denied(detail: str | None = None) -> ProxyError:
    return ProxyError(403, "capability_denied", detail)


def invalid_arguments(detail: str | None = None) -> ProxyError:
    return ProxyError(400, "invalid_arguments", detail)


def upstream_error(detail: str | None = None) -> ProxyError:
    return ProxyError(503, "upstream_error", detail)
