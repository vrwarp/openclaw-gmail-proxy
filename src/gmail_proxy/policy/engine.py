"""``is_eligible()`` -- the single security-critical confinement predicate.

A message is visible/actionable to the agent iff **every** ``CATEGORY_*`` label
it carries is within the operator-allowed set (and it has at least one, and it
is not spam/trash).  This is default-deny on the category dimension: an unknown
or future category, or a message that also lives in a disallowed category, fails
closed.

Inbox state (``INBOX``/``UNREAD``/``STARRED``/``IMPORTANT``/user labels) does
**not** affect eligibility -- confinement is about category, not inbox state.
This is deliberately *not* the "exclusive" rule (which would hide all inboxed
promotions): categories are what we scope on.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..categories import ALL_CATEGORY_ID_SET

#: Labels that make a message categorically ineligible no matter what.
HARD_DENY_LABELS: frozenset[str] = frozenset({"SPAM", "TRASH"})


def category_ids_of(label_ids: Iterable[str]) -> set[str]:
    """The subset of ``label_ids`` that are Gmail category labels."""
    return set(label_ids) & ALL_CATEGORY_ID_SET


def is_eligible(
    label_ids: Iterable[str] | None,
    allowed_category_ids: Iterable[str],
    allowed_label_ids: Iterable[str] = (),
    blocked_label_ids: Iterable[str] = (),
) -> bool:
    """Return True iff a message with these labels is in scope.

    In scope means: not spam/trash, NOT carrying a blocked label (which
    supersedes both allowlists), AND either it carries an operator-allowed label
    (``allowed_label_ids`` -- grants access regardless of category), OR it has at
    least one category label and every category label is within
    ``allowed_category_ids``.  Default-deny on ``None``/empty labels.
    """
    if not label_ids:
        return False
    labels = set(label_ids)
    if labels & HARD_DENY_LABELS:
        return False
    if labels & set(blocked_label_ids):
        return False  # blocklist supersedes every allowlist
    allowed_labels = set(allowed_label_ids)
    if allowed_labels and (labels & allowed_labels):
        return True  # a hand-applied allowed label grants access, any category
    cats = labels & ALL_CATEGORY_ID_SET
    if not cats:
        return False  # uncategorized and no allowed label -> deny
    return cats <= set(allowed_category_ids)


def eligibility_reason(
    label_ids: Iterable[str] | None,
    allowed_category_ids: Iterable[str],
    allowed_label_ids: Iterable[str] = (),
    blocked_label_ids: Iterable[str] = (),
) -> str:
    """Explain the eligibility verdict (for the admin 'policy explain' view)."""
    if not label_ids:
        return "denied: message has no labels (malformed / metadata unavailable)"
    labels = set(label_ids)
    blocked = labels & HARD_DENY_LABELS
    if blocked:
        return f"denied: message is in {', '.join(sorted(blocked))}"
    blocked_hit = labels & set(blocked_label_ids)
    if blocked_hit:
        return f"denied: carries blocked label(s) {', '.join(sorted(blocked_hit))} (supersedes allowlist)"
    matched = labels & set(allowed_label_ids)
    if matched:
        return f"allowed: carries allowed label(s) {', '.join(sorted(matched))}"
    cats = labels & ALL_CATEGORY_ID_SET
    if not cats:
        return "denied: message is uncategorized and carries no allowed label"
    allowed = set(allowed_category_ids)
    outside = cats - allowed
    if outside:
        return (
            f"denied: message is in disallowed category "
            f"{', '.join(sorted(outside))} (allowed: {', '.join(sorted(allowed)) or 'none'})"
        )
    return f"allowed: message categories {', '.join(sorted(cats))} are all within scope"
