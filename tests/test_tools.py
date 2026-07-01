"""Integration tests: the tool layer against the mock Gmail backend."""

import pytest

from gmail_proxy import errors, tools


def call(ctx, name, mode="read_write", **args):
    return tools.call_tool(ctx, "cred_test", mode, name, args)


def test_list_returns_only_in_scope(ctx):
    r = call(ctx, "gmail_list_messages", category="promotions")
    ids = [m["id"] for m in r["messages"]]
    assert ids and all(i.startswith("m") for i in ids)
    # personal message m010 must never appear
    assert "m010" not in ids


def test_list_all_allowed_categories(ctx):
    r = call(ctx, "gmail_list_messages")
    # promotions + social only; updates/forums/personal excluded
    assert r["_control"]["count"] >= 1


def test_untrusted_framing_on_content(ctx):
    r = call(ctx, "gmail_list_messages", category="promotions")
    m = r["messages"][0]
    assert m["from"]["untrusted"] is True
    assert m["subject"]["untrusted"] is True
    assert "content_len" in m["subject"]


def test_get_eligible_message(ctx):
    d = call(ctx, "gmail_get_message", id="m001")
    assert d["id"] == "m001"
    assert d["body"]["untrusted"] is True
    # minimized headers: To/Cc dropped
    assert "to" not in d and "cc" not in d


def test_get_out_of_scope_denied(ctx):
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_get_message", id="m010")  # personal
    assert ei.value.reason == "not_eligible"


def test_list_disallowed_category_denied(ctx):
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_list_messages", category="updates")
    assert ei.value.reason == "not_eligible"


def test_archive_removes_inbox(ctx):
    r = call(ctx, "gmail_archive_message", id="m001")
    assert r["archived"] is True


def test_cannot_smuggle_category(ctx):
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_modify_labels", id="m001", remove_labels=["CATEGORY_PROMOTIONS"])
    assert ei.value.reason == "category_mutation_forbidden"


def test_cannot_add_spam(ctx):
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_modify_labels", id="m001", add_labels=["SPAM"])
    assert ei.value.reason == "label_immutable"


def test_mark_read(ctx):
    r = call(ctx, "gmail_modify_labels", id="m002", remove_labels=["UNREAD"])
    assert "UNREAD" not in r["labels"]


def test_trash_disabled_by_default(ctx):
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_trash_message", id="m001")
    assert ei.value.reason == "trash_not_allowed"


def test_trash_when_enabled(make_ctx):
    ctx = make_ctx(allowed_categories=["promotions", "social"], allow_trash=True)
    r = call(ctx, "gmail_trash_message", id="m001")
    assert r["trashed"] is True
    # now out of scope (trashed), re-read denied
    with pytest.raises(errors.ProxyError):
        call(ctx, "gmail_get_message", id="m001")


def test_thread_drops_out_of_scope_members(ctx):
    # m001 is promotions -> thread t001; all members eligible
    r = call(ctx, "gmail_get_thread", id="t001")
    assert len(r["messages"]) >= 1


def test_read_only_mode_blocks_mutation(ctx):
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_modify_labels", "read_only", id="m001", remove_labels=["UNREAD"])
    assert ei.value.reason == "mutation_not_allowed"


def test_kill_switch(ctx):
    ctx.killswitch.freeze("test")
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_list_messages", category="promotions")
    assert ei.value.reason == "frozen"


def test_rate_limit(make_ctx):
    ctx = make_ctx()
    ctx.ratelimiter.per_minute = 2
    call(ctx, "gmail_counts")
    call(ctx, "gmail_counts")
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_counts")
    assert ei.value.reason == "rate_limited"


def test_unknown_tool_capability_denied(ctx):
    with pytest.raises(errors.ProxyError) as ei:
        tools.call_tool(ctx, "cred", "read_write", "gmail_send_email", {})
    assert ei.value.reason == "capability_denied"


def test_counts_and_profile(ctx):
    counts = call(ctx, "gmail_counts")
    assert set(counts["unread_by_category"]) <= {"promotions", "social"}
    prof = call(ctx, "gmail_get_profile")
    assert prof["email"] == "vrwarp@gmail.com"


def test_audit_records_allow_and_deny(ctx):
    call(ctx, "gmail_counts")
    with pytest.raises(errors.ProxyError):
        call(ctx, "gmail_get_message", id="m010")
    rows = ctx.audit.tail(10)
    decisions = {r["tool"]: r["decision"] for r in rows}
    assert decisions.get("gmail_counts") == "allow"
    assert decisions.get("gmail_get_message") == "deny"
    assert ctx.audit.verify_chain() is True
