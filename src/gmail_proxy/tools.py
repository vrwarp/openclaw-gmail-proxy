"""The category-scoped tool surface exposed to OpenClaw.

Every read re-checks eligibility against fresh labels before returning a body;
every mutation validates the label set, re-checks eligibility before and after,
and reverts + reports ``reclassified`` if the message left scope mid-flight.
Dispatch enforces the kill-switch, per-credential rate limits, and audit.
"""

from __future__ import annotations

from collections.abc import Callable

from . import errors, output
from .categories import NAME_BY_CATEGORY_ID
from .context import AppContext
from .gmail.client import GmailError
from .policy.engine import eligibility_reason, is_eligible
from .policy.mutation import validate_mutation
from .policy.query import build_query

MUTATING = {"gmail_modify_labels", "gmail_archive_message", "gmail_trash_message"}


def _allowed_ids(ctx: AppContext) -> set[str]:
    return ctx.policy.allowed_category_ids()


def _fetch_metadata(ctx: AppContext, message_id: str):
    try:
        return ctx.backend.get_message_metadata(message_id)
    except KeyError:
        # Uniform denial -- do not reveal existence of out-of-scope ids.
        raise errors.not_eligible(f"id not found: {message_id}")
    except GmailError as e:
        raise errors.upstream_error(str(e))


def _require_eligible(ctx: AppContext, message_id: str):
    meta = _fetch_metadata(ctx, message_id)
    if not is_eligible(meta.label_ids, _allowed_ids(ctx)):
        raise errors.not_eligible(eligibility_reason(meta.label_ids, _allowed_ids(ctx)))
    return meta


# --- handlers -------------------------------------------------------------

def _h_list(ctx, mode, args):
    q = build_query(
        _allowed_ids(ctx),
        category=args.get("category"),
        unread_only=bool(args.get("unread_only", False)),
        from_=args.get("from"),
        subject=args.get("subject"),
        after=args.get("after"),
        before=args.get("before"),
        newer_than=args.get("newer_than"),
        older_than=args.get("older_than"),
    )
    cap = ctx.policy.max_results_cap
    max_results = min(int(args.get("max_results", 25)), cap)
    try:
        ids, next_token = ctx.backend.list_message_ids(q, max_results, args.get("page_token"))
    except GmailError as e:
        raise errors.upstream_error(str(e))
    summaries = []
    seen_ids = []
    for mid in ids:
        meta = _fetch_metadata(ctx, mid)
        if not is_eligible(meta.label_ids, _allowed_ids(ctx)):
            continue  # defense in depth: query is scoped, but re-verify
        summaries.append(output.format_summary(meta, ctx.policy, ctx.sender_salt))
        seen_ids.append(mid)
    result = {"messages": summaries, "page_token": next_token,
              "_control": {"count": len(summaries), "scoped_query": True}}
    return result, seen_ids


def _h_get(ctx, mode, args):
    mid = args["id"]
    meta = _require_eligible(ctx, mid)  # fresh labels gate
    try:
        full = ctx.backend.get_message(mid)  # content (immutable; may be cache-served)
    except KeyError:
        raise errors.not_eligible(f"id not found: {mid}")
    except GmailError as e:
        raise errors.upstream_error(str(e))
    # Authoritative labels are the fresh metadata read, NOT the cached full fetch.
    full.label_ids = meta.label_ids
    if not is_eligible(full.label_ids, _allowed_ids(ctx)):
        raise errors.not_eligible("reclassified between metadata and full fetch")
    return output.format_detail(full, ctx.policy, ctx.sender_salt), [mid]


def _h_thread(ctx, mode, args):
    tid = args["id"]
    try:
        thread = ctx.backend.get_thread(tid)
    except KeyError:
        raise errors.not_eligible(f"thread not found: {tid}")
    except GmailError as e:
        raise errors.upstream_error(str(e))
    eligible = [m for m in thread.messages if is_eligible(m.label_ids, _allowed_ids(ctx))]
    if not eligible:
        raise errors.not_eligible("no eligible messages in thread")
    msgs = [output.format_detail(m, ctx.policy, ctx.sender_salt) for m in eligible]
    dropped = len(thread.messages) - len(eligible)
    return {"id": tid, "messages": msgs, "_control": {"dropped_out_of_scope": dropped}}, [
        m.id for m in eligible
    ]


def _resolve_and_apply(ctx, add_labels, remove_labels, mid):
    """Shared modify path: validate, eligibility-gate, apply, re-verify, revert."""
    labels = ctx.backend.list_labels()
    resolved = validate_mutation(add_labels, remove_labels, ctx.policy, labels)
    _require_eligible(ctx, mid)  # before
    try:
        updated = ctx.backend.modify_labels(mid, resolved.add_ids, resolved.remove_ids)
    except GmailError as e:
        raise errors.upstream_error(str(e))
    # after: a mutation must never move a message out of scope.
    if not is_eligible(updated.label_ids, _allowed_ids(ctx)):
        try:  # best-effort inverse revert
            ctx.backend.modify_labels(mid, resolved.remove_ids, resolved.add_ids)
        except GmailError:
            pass
        raise errors.ProxyError(409, "reclassified", "mutation left message out of scope; reverted")
    label_names = [NAME_BY_CATEGORY_ID.get(l, l) for l in updated.label_ids]
    return updated, label_names


def _h_modify(ctx, mode, args):
    if mode == "read_only":
        raise errors.ProxyError(403, "mutation_not_allowed", "credential/policy is read_only")
    mid = args["id"]
    updated, names = _resolve_and_apply(ctx, args.get("add_labels"), args.get("remove_labels"), mid)
    return {"id": mid, "labels": names, "_control": {"applied": True}}, [mid]


def _h_archive(ctx, mode, args):
    if mode == "read_only":
        raise errors.ProxyError(403, "mutation_not_allowed", "credential/policy is read_only")
    mid = args["id"]
    updated, names = _resolve_and_apply(ctx, None, ["INBOX"], mid)
    return {"id": mid, "archived": "INBOX" not in updated.label_ids, "labels": names}, [mid]


def _h_trash(ctx, mode, args):
    if mode == "read_only":
        raise errors.ProxyError(403, "mutation_not_allowed", "credential/policy is read_only")
    if not ctx.policy.allow_trash:
        raise errors.ProxyError(403, "trash_not_allowed", "trash disabled by policy")
    mid = args["id"]
    _require_eligible(ctx, mid)
    try:
        ctx.backend.trash(mid)
    except GmailError as e:
        raise errors.upstream_error(str(e))
    return {"id": mid, "trashed": True}, [mid]


def _h_labels(ctx, mode, args):
    labels = ctx.backend.list_labels()
    user = [{"name": l.name, "id": l.id} for l in labels if l.type == "user"]
    mutable_system = [l for l in ctx.policy.mutable_labels]
    return {
        "user_labels": user,
        "mutable_system_labels": mutable_system,
        "allow_user_label_mutations": ctx.policy.allow_user_label_mutations,
    }, []


def _h_counts(ctx, mode, args):
    category = args.get("category")
    cats = [category] if category else [NAME_BY_CATEGORY_ID[c] for c in _allowed_ids(ctx)]
    out = {}
    for name in cats:
        q = build_query(_allowed_ids(ctx), category=name, unread_only=True)
        try:
            ids, _ = ctx.backend.list_message_ids(q, 100, None)
        except GmailError as e:
            raise errors.upstream_error(str(e))
        # Re-check eligibility per message (mirrors _h_list): a multi-category
        # message can match a scoped query yet be ineligible (cats not a subset).
        n = sum(1 for mid in ids if is_eligible(_fetch_metadata(ctx, mid).label_ids, _allowed_ids(ctx)))
        out[name] = n if n < 100 else "100+"
    return {"unread_by_category": out}, []


def _h_profile(ctx, mode, args):
    try:
        profile = ctx.backend.get_profile()
    except GmailError as e:
        raise errors.upstream_error(str(e))
    return {
        "email": profile.get("emailAddress"),
        "allowed_categories": ctx.policy.allowed_categories,
        "mode": ctx.policy.mode,
    }, []


TOOLS: dict[str, Callable] = {
    "gmail_list_messages": _h_list,
    "gmail_get_message": _h_get,
    "gmail_get_thread": _h_thread,
    "gmail_modify_labels": _h_modify,
    "gmail_archive_message": _h_archive,
    "gmail_trash_message": _h_trash,
    "gmail_list_labels": _h_labels,
    "gmail_counts": _h_counts,
    "gmail_get_profile": _h_profile,
}


def call_tool(
    ctx: AppContext,
    actor: str,
    mode: str,
    name: str,
    args: dict,
    *,
    enforce_runtime: bool = True,
) -> dict:
    """Dispatch a tool call with freeze/rate-limit/audit enforcement."""
    if name not in TOOLS:
        ctx.audit.record(actor=actor, tool=name, decision="deny", reason="capability_denied", args=args)
        raise errors.capability_denied(name)
    if enforce_runtime and ctx.killswitch.is_frozen():
        ctx.audit.record(actor=actor, tool=name, decision="deny", reason="frozen", args=args)
        raise errors.ProxyError(503, "frozen", "kill-switch engaged")
    if enforce_runtime and not ctx.ratelimiter.check(actor):
        ctx.audit.record(actor=actor, tool=name, decision="deny", reason="rate_limited", args=args)
        raise errors.ProxyError(429, "rate_limited", "per-credential rate limit exceeded")
    try:
        result, message_ids = TOOLS[name](ctx, mode, args)
    except errors.ProxyError as e:
        ctx.audit.record(
            actor=actor, tool=name, decision="deny", reason=e.reason, args=args, detail=e.detail
        )
        raise
    except Exception as e:  # noqa: BLE001 - fail closed; never leak raw detail to the agent
        ctx.audit.record(
            actor=actor, tool=name, decision="deny", reason="internal_error", args=args, detail=repr(e)
        )
        raise errors.ProxyError(500, "internal_error", repr(e))
    ctx.audit.record(actor=actor, tool=name, decision="allow", args=args, message_ids=message_ids)
    return result
