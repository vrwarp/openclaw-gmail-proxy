"""Tests for allowlisting by label (in addition to category)."""

import pytest

from gmail_proxy import errors, tools
from gmail_proxy.categories import CATEGORY_PROMOTIONS
from gmail_proxy.config import Policy
from gmail_proxy.policy.engine import is_eligible
from gmail_proxy.policy.query import build_query

CAT = {CATEGORY_PROMOTIONS}


def call(ctx, name, mode="read_write", **args):
    return tools.call_tool(ctx, "cred", mode, name, args)


# --- engine ---------------------------------------------------------------

def test_label_grants_access_regardless_of_category():
    assert is_eligible(["CATEGORY_UPDATES", "Label_1"], CAT, {"Label_1"}) is True
    assert is_eligible(["CATEGORY_UPDATES"], CAT, {"Label_1"}) is False
    # spam/trash still deny even with an allowed label
    assert is_eligible(["Label_1", "SPAM"], CAT, {"Label_1"}) is False
    # empty allowed-label set => pure category behavior
    assert is_eligible(["CATEGORY_UPDATES", "Label_1"], CAT, frozenset()) is False


# --- config validation ----------------------------------------------------

@pytest.mark.parametrize("bad", ["INBOX", "UNREAD", "CATEGORY_SOCIAL", "SPAM", "IMPORTANT"])
def test_reject_broad_allowed_labels(bad):
    with pytest.raises(Exception):
        Policy(allowed_categories=["promotions"], allowed_labels=[bad])


def test_require_categories_or_labels():
    with pytest.raises(Exception):
        Policy(allowed_categories=[], allowed_labels=[])
    Policy(allowed_categories=[], allowed_labels=["Receipts"])  # label-only is valid


# --- query ----------------------------------------------------------------

def test_query_ors_label_with_category():
    q = build_query(CAT, allowed_label_names=["Receipts"])
    assert "category:promotions" in q and "label:Receipts" in q and " OR " in q


def test_query_label_only():
    assert build_query(set(), allowed_label_names=["My Label"]) == "(label:My-Label) in:inbox"


# --- tool integration (mock backend has m007 = CATEGORY_UPDATES + Receipts) --

def test_label_grants_read_and_list(make_ctx):
    ctx = make_ctx(allowed_categories=["promotions", "social"], allowed_labels=["Receipts"])
    d = call(ctx, "gmail_get_message", id="m007")  # updates, but carries Receipts
    assert d["id"] == "m007"
    ids = [m["id"] for m in call(ctx, "gmail_list_messages")["messages"]]
    assert "m007" in ids


def test_non_labeled_out_of_scope_message_denied(make_ctx):
    ctx = make_ctx(allowed_categories=["promotions", "social"], allowed_labels=["Receipts"])
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_get_message", id="m008")  # updates, no Receipts label
    assert ei.value.reason == "not_eligible"


def test_cannot_remove_eligibility_label(make_ctx):
    ctx = make_ctx(allowed_categories=["promotions", "social"], allowed_labels=["Receipts"])
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_modify_labels", id="m007", remove_labels=["Receipts"])
    assert ei.value.reason == "label_immutable"


def test_cannot_add_eligibility_label_to_out_of_scope(make_ctx):
    ctx = make_ctx(allowed_categories=["promotions", "social"], allowed_labels=["Receipts"])
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_modify_labels", id="m010", add_labels=["Receipts"])  # personal msg
    assert ei.value.reason == "label_immutable"


def test_label_only_scoping(make_ctx):
    ctx = make_ctx(allowed_categories=[], allowed_labels=["Receipts"])
    ids = [m["id"] for m in call(ctx, "gmail_list_messages")["messages"]]
    assert ids == ["m007"]


def test_counts_include_labels(make_ctx):
    ctx = make_ctx(allowed_categories=["promotions"], allowed_labels=["Receipts"])
    c = call(ctx, "gmail_counts")
    assert "unread_by_label" in c and "Receipts" in c["unread_by_label"]
