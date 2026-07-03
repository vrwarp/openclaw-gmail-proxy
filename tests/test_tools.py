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


def test_list_is_inbox_only_by_default(ctx):
    # m012 is an archived promotion (CATEGORY_PROMOTIONS, no INBOX).
    r = call(ctx, "gmail_list_messages", category="promotions")
    ids = [m["id"] for m in r["messages"]]
    assert "m012" not in ids
    assert r["_control"]["archived_included"] is False
    assert all(m["in_inbox"] is True for m in r["messages"])  # state flag exposed


def test_include_archived_returns_archived(ctx):
    r = call(ctx, "gmail_list_messages", category="promotions", include_archived=True)
    ids = [m["id"] for m in r["messages"]]
    assert "m012" in ids and r["_control"]["archived_included"] is True
    m012 = next(m for m in r["messages"] if m["id"] == "m012")
    assert m012["in_inbox"] is False


def test_archived_message_disappears_from_default_list(ctx):
    # The exact confusion for small models: archive -> gone from the default view.
    call(ctx, "gmail_archive_message", id="m001")
    default_ids = [m["id"] for m in call(ctx, "gmail_list_messages", category="promotions")["messages"]]
    assert "m001" not in default_ids
    all_ids = [m["id"] for m in
               call(ctx, "gmail_list_messages", category="promotions", include_archived=True)["messages"]]
    assert "m001" in all_ids  # still there, just archived


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


def test_response_taint_marks_cached(make_ctx):
    ctx = make_ctx()  # content cache on, metadata_ttl 0
    r1 = call(ctx, "gmail_get_message", id="m001")
    assert r1["_control"]["cached"] is False  # first fetch is live
    r2 = call(ctx, "gmail_get_message", id="m001")
    assert r2["_control"]["cached"] is True  # body served from the content cache


def test_fresh_forces_live_and_untaints(make_ctx):
    ctx = make_ctx()
    call(ctx, "gmail_get_message", id="m001")  # warm
    hits_before = ctx.backend.stats()["content"]["hits"]
    r = call(ctx, "gmail_get_message", id="m001", fresh=True)
    assert r["_control"]["cached"] is False  # forced live
    assert ctx.backend.stats()["content"]["hits"] == hits_before  # no cache hit consumed


def test_list_taint_with_ttl(make_ctx):
    from gmail_proxy.config import CacheConfig
    ctx = make_ctx(cache=CacheConfig(list_ttl_s=60))
    r1 = call(ctx, "gmail_list_messages", category="promotions")
    assert r1["_control"]["cached"] is False
    r2 = call(ctx, "gmail_list_messages", category="promotions")
    assert r2["_control"]["cached"] is True  # list served from cache -> whole response tainted
    r3 = call(ctx, "gmail_list_messages", category="promotions", fresh=True)
    assert r3["_control"]["cached"] is False  # fresh bypasses


def test_counts_excludes_multi_category_message(ctx):
    # A message in an allowed AND a disallowed category is ineligible (not a
    # subset) and must NOT be counted -- must match what gmail_list would show.
    from gmail_proxy.models import Message
    ctx.backend.inner.messages["mX"] = Message(
        id="mX", thread_id="tX",
        label_ids=["CATEGORY_PROMOTIONS", "CATEGORY_UPDATES", "UNREAD", "INBOX"],
        headers={"From": "x@y.com", "Subject": "multi", "Date": "2026-06-30T00:00:00+00:00"},
        internal_date="2026-06-30T00:00:00+00:00", history_id=1,
    )
    listed = call(ctx, "gmail_list_messages", category="promotions", unread_only=True)
    counted = call(ctx, "gmail_counts", category="promotions")["unread_by_category"]["promotions"]
    assert "mX" not in [m["id"] for m in listed["messages"]]  # list already excludes it
    assert counted == listed["_control"]["count"]             # counts must agree


def test_internal_error_is_fail_closed(ctx, monkeypatch):
    def boom(ctx, mode, args):
        raise RuntimeError("secret upstream detail")
    monkeypatch.setitem(tools.TOOLS, "gmail_counts", boom)
    with pytest.raises(errors.ProxyError) as ei:
        call(ctx, "gmail_counts")
    assert ei.value.code == 500 and ei.value.reason == "internal_error"
    assert "secret" not in str(ei.value.to_public())  # no raw detail to the agent
    row = ctx.audit.tail(1)[0]
    assert row["decision"] == "deny" and row["reason"] == "internal_error"


def test_audit_records_allow_and_deny(ctx):
    call(ctx, "gmail_counts")
    with pytest.raises(errors.ProxyError):
        call(ctx, "gmail_get_message", id="m010")
    rows = ctx.audit.tail(10)
    decisions = {r["tool"]: r["decision"] for r in rows}
    assert decisions.get("gmail_counts") == "allow"
    assert decisions.get("gmail_get_message") == "deny"
    assert ctx.audit.verify_chain() is True
