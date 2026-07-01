"""Tests for the label blocklist (supersedes both allowlists)."""

import pytest

from gmail_proxy import errors, tools
from gmail_proxy.categories import CATEGORY_SOCIAL
from gmail_proxy.config import Policy
from gmail_proxy.policy.engine import is_eligible
from gmail_proxy.policy.query import build_query


def call(ctx, name, mode="read_write", **args):
    return tools.call_tool(ctx, "cred", mode, name, args)


# --- engine ---------------------------------------------------------------

def test_blocklist_supersedes_category():
    assert is_eligible(["CATEGORY_SOCIAL", "STARRED"], {CATEGORY_SOCIAL}, (), {"STARRED"}) is False
    assert is_eligible(["CATEGORY_SOCIAL"], {CATEGORY_SOCIAL}, (), {"STARRED"}) is True


def test_blocklist_supersedes_label_allowlist():
    assert is_eligible(["Label_1", "STARRED"], set(), {"Label_1"}, {"STARRED"}) is False
    assert is_eligible(["Label_1"], set(), {"Label_1"}, {"STARRED"}) is True


# --- config ---------------------------------------------------------------

def test_reject_label_in_both_allow_and_block():
    with pytest.raises(Exception):
        Policy(allowed_categories=["promotions"], allowed_labels=["X"], blocked_labels=["X"])


def test_blocked_may_be_a_system_label():
    # denylist only narrows, so any name (system or user) is allowed here
    Policy(allowed_categories=["promotions"], blocked_labels=["IMPORTANT", "Private"])


# --- query ----------------------------------------------------------------

def test_query_excludes_blocked_label():
    q = build_query({CATEGORY_SOCIAL}, blocked_label_names=["Private"])
    assert "-label:Private" in q and "category:social" in q


def test_query_blocked_applies_even_with_single_category():
    q = build_query({CATEGORY_SOCIAL}, category="social", blocked_label_names=["Private"])
    assert "-label:Private" in q


# --- tool integration (mock: m006 = CATEGORY_SOCIAL + STARRED) ------------

def test_blocked_message_denied_and_hidden(make_ctx):
    ctx = make_ctx(allowed_categories=["social"], blocked_labels=["STARRED"])
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_get_message", id="m006")  # social but STARRED-blocked
    assert ei.value.reason == "not_eligible"
    ids = [m["id"] for m in call(ctx, "gmail_list_messages")["messages"]]
    assert "m006" not in ids and "m004" in ids  # other social mail still visible


def test_block_supersedes_label_grant(make_ctx):
    ctx = make_ctx(allowed_categories=[], allowed_labels=["Receipts"], blocked_labels=["STARRED"])
    ctx.backend.inner.messages["m007"].label_ids.append("STARRED")  # Receipts-granted, now blocked
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_get_message", id="m007")
    assert ei.value.reason == "not_eligible"


def test_cannot_remove_blocked_label(make_ctx):
    # STARRED is normally mutable, but being blocked makes it immutable.
    ctx = make_ctx(allowed_categories=["social"], blocked_labels=["STARRED"])
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_modify_labels", id="m006", remove_labels=["STARRED"])
    assert ei.value.reason == "label_immutable"
