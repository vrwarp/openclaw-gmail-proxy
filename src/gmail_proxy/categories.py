"""Canonical Gmail category taxonomy and name/token mappings.

Gmail's tabbed inbox assigns each message to at most one *category* system
label.  The proxy confines OpenClaw to a configurable subset of these
categories.  This module is the single source of truth for the mapping
between:

* the Gmail **label id** (e.g. ``CATEGORY_PROMOTIONS``),
* the short **name** used in the tool API / policy config (e.g. ``promotions``),
* the Gmail **search operator token** used in ``q`` (e.g. ``category:promotions``).

Note that ``CATEGORY_PERSONAL`` (the "Primary" tab) maps to the search token
``primary`` -- Gmail is inconsistent here, so we pin the mapping explicitly.
"""

from __future__ import annotations

# --- Canonical Gmail system category label ids -----------------------------
CATEGORY_PERSONAL = "CATEGORY_PERSONAL"  # the "Primary" tab
CATEGORY_SOCIAL = "CATEGORY_SOCIAL"
CATEGORY_PROMOTIONS = "CATEGORY_PROMOTIONS"
CATEGORY_UPDATES = "CATEGORY_UPDATES"
CATEGORY_FORUMS = "CATEGORY_FORUMS"

#: Every category label id, in tab order.
ALL_CATEGORY_IDS: tuple[str, ...] = (
    CATEGORY_PERSONAL,
    CATEGORY_SOCIAL,
    CATEGORY_PROMOTIONS,
    CATEGORY_UPDATES,
    CATEGORY_FORUMS,
)
ALL_CATEGORY_ID_SET: frozenset[str] = frozenset(ALL_CATEGORY_IDS)

#: short-name -> label id.  Accepts both ``primary`` and ``personal`` for Primary.
CATEGORY_ID_BY_NAME: dict[str, str] = {
    "primary": CATEGORY_PERSONAL,
    "personal": CATEGORY_PERSONAL,
    "social": CATEGORY_SOCIAL,
    "promotions": CATEGORY_PROMOTIONS,
    "updates": CATEGORY_UPDATES,
    "forums": CATEGORY_FORUMS,
}

#: label id -> canonical short name (used in tool API responses).
NAME_BY_CATEGORY_ID: dict[str, str] = {
    CATEGORY_PERSONAL: "primary",
    CATEGORY_SOCIAL: "social",
    CATEGORY_PROMOTIONS: "promotions",
    CATEGORY_UPDATES: "updates",
    CATEGORY_FORUMS: "forums",
}

#: label id -> Gmail ``category:`` search-operator token.
SEARCH_TOKEN_BY_CATEGORY_ID: dict[str, str] = {
    CATEGORY_PERSONAL: "primary",
    CATEGORY_SOCIAL: "social",
    CATEGORY_PROMOTIONS: "promotions",
    CATEGORY_UPDATES: "updates",
    CATEGORY_FORUMS: "forums",
}


def category_id_for_name(name: str) -> str | None:
    """Return the label id for a short category name, or ``None`` if unknown."""
    return CATEGORY_ID_BY_NAME.get(name.strip().lower())


def name_for_category_id(label_id: str) -> str | None:
    """Return the short name for a category label id, or ``None`` if unknown."""
    return NAME_BY_CATEGORY_ID.get(label_id)
