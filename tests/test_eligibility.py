"""Tests for is_eligible() -- the category-confinement predicate (the crux)."""

import pytest

from gmail_proxy.categories import (
    CATEGORY_PERSONAL,
    CATEGORY_PROMOTIONS,
    CATEGORY_SOCIAL,
    CATEGORY_UPDATES,
)
from gmail_proxy.policy.engine import is_eligible

ALLOWED = {CATEGORY_PROMOTIONS, CATEGORY_SOCIAL}


@pytest.mark.parametrize(
    "labels,expected",
    [
        # eligible: an allowed category, inbox state is irrelevant
        ([CATEGORY_PROMOTIONS, "INBOX", "UNREAD"], True),
        ([CATEGORY_SOCIAL], True),
        ([CATEGORY_PROMOTIONS, "STARRED", "IMPORTANT"], True),
        # archived (no INBOX) but still an allowed category -> eligible
        ([CATEGORY_PROMOTIONS], True),
        # disallowed category
        ([CATEGORY_PERSONAL, "INBOX"], False),
        ([CATEGORY_UPDATES], False),
        # mixed: one allowed + one disallowed -> deny (not a subset)
        ([CATEGORY_PROMOTIONS, CATEGORY_PERSONAL], False),
        # uncategorized -> deny
        (["INBOX", "UNREAD"], False),
        # spam / trash -> always deny even with an allowed category
        ([CATEGORY_PROMOTIONS, "SPAM"], False),
        ([CATEGORY_SOCIAL, "TRASH"], False),
        # malformed -> deny (no vacuous pass)
        ([], False),
        (None, False),
    ],
)
def test_is_eligible(labels, expected):
    assert is_eligible(labels, ALLOWED) is expected


def test_widening_allowed_set_admits_more():
    labels = [CATEGORY_UPDATES, "INBOX"]
    assert is_eligible(labels, ALLOWED) is False
    assert is_eligible(labels, ALLOWED | {CATEGORY_UPDATES}) is True


def test_future_unknown_category_fails_closed():
    # A category-shaped label the code does not know about is not a category
    # label (not in ALL_CATEGORY_ID_SET), so it is treated as a non-category
    # residual label and the message must still have a known allowed category.
    assert is_eligible(["CATEGORY_FUTURE_THING"], ALLOWED) is False
