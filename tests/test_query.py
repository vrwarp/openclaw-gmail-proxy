"""Tests for the query sanitizer -- category scope + injection resistance."""

import pytest

from gmail_proxy import errors
from gmail_proxy.categories import CATEGORY_PROMOTIONS, CATEGORY_SOCIAL
from gmail_proxy.policy.query import build_query

ALLOWED = {CATEGORY_PROMOTIONS, CATEGORY_SOCIAL}


def test_scopes_to_all_allowed_when_no_category():
    q = build_query(ALLOWED)
    assert q == "(category:promotions OR category:social) in:inbox"


def test_single_category_scope():
    q = build_query(ALLOWED, category="promotions")
    assert q == "(category:promotions) in:inbox"


def test_include_archived_drops_inbox_filter():
    assert build_query(ALLOWED, category="promotions", inbox_only=False) == "(category:promotions)"


def test_typed_params_are_field_bound_and_quoted():
    q = build_query(ALLOWED, category="social", unread_only=True, from_="alex@x.com",
                    subject="photo", newer_than="7d")
    assert q.startswith("(category:social) AND (")
    assert 'from:("alex@x.com")' in q
    assert 'subject:("photo")' in q
    assert "is:unread" in q and "newer_than:7d" in q


def test_category_not_in_allowed_set_is_rejected():
    with pytest.raises(errors.ProxyError) as ei:
        build_query(ALLOWED, category="updates")
    assert ei.value.reason == "not_eligible"


@pytest.mark.parametrize(
    "field_kw",
    [
        {"from_": 'x") OR category:primary ("'},   # try to escape the group
        {"subject": "a OR b"},                      # bare boolean
        {"from_": "label:INBOX"},                   # smuggle an operator
        {"subject": 'foo") ('},                     # paren injection
        {"from_": "a:b"},                           # colon in value
        {"subject": "x" * 200},                     # over length
    ],
)
def test_injection_attempts_are_rejected(field_kw):
    with pytest.raises(errors.ProxyError) as ei:
        build_query(ALLOWED, **field_kw)
    assert ei.value.reason == "query_rejected"


@pytest.mark.parametrize("bad_date", ["2026-07-01", "7days", "1w", "julyish"])
def test_bad_date_specs_rejected(bad_date):
    with pytest.raises(errors.ProxyError):
        build_query(ALLOWED, newer_than=bad_date)


def test_absolute_dates_ok():
    q = build_query(ALLOWED, after="2026/01/01", before="2026/07/01")
    assert "after:2026/01/01" in q and "before:2026/07/01" in q


def test_assembled_query_only_contains_allowlisted_operators():
    q = build_query(ALLOWED, category="promotions", unread_only=True, newer_than="1m")
    import re
    ops = set(re.findall(r"([A-Za-z_]+):", q))
    assert ops <= {"category", "is", "in", "newer_than", "from", "subject", "after", "before"}
