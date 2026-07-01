"""Query sanitization -- the canonical, injection-proof search builder.

The agent never supplies a raw Gmail ``q``.  It supplies *typed, validated*
narrowing fields, and this module emits a pinned, parenthesized grammar:

    (category:promotions OR category:social) AND (<field-bound value terms>)

The category group is mandatory and parenthesized, so no attacker value can
escape its group or raise operator precedence to drop the category constraint.
Every value term is regex-validated and field-bound; free-form operators, bare
booleans, and colons in values are rejected.
"""

from __future__ import annotations

import re
import unicodedata

from .. import errors
from ..categories import SEARCH_TOKEN_BY_CATEGORY_ID, category_id_for_name

# Operators the builder itself may emit.  A positive re-scan of the assembled
# query rejects any colon-operator not in this set (including future Gmail ops).
_ALLOWED_OPERATORS: frozenset[str] = frozenset(
    {"category", "from", "subject", "after", "before", "newer_than", "older_than", "is"}
)

# Validation patterns for typed params.
_RELATIVE_DATE = re.compile(r"^\d{1,4}[dmy]$")
_ABSOLUTE_DATE = re.compile(r"^\d{4}/\d{2}/\d{2}$")
# A conservative value charset for from/subject: letters, digits, spaces and a
# handful of email/name punctuation.  Notably excludes: " ( ) : and control
# chars, which are the injection primitives.
_SAFE_VALUE = re.compile(r"^[\w .,'@+\-/&]{1,128}$", re.UNICODE)
_OPERATOR_TOKEN = re.compile(r"([A-Za-z_]+):")


def _normalize(s: str) -> str:
    # NFKC to a fixpoint so confusable/compatibility forms cannot reintroduce
    # operator syntax after validation.
    prev = None
    cur = s
    for _ in range(4):
        if cur == prev:
            break
        prev, cur = cur, unicodedata.normalize("NFKC", cur)
    return cur


def _validate_value(field: str, raw: str) -> str:
    v = _normalize(raw).strip()
    if not v or not _SAFE_VALUE.match(v):
        raise errors.query_rejected(f"{field}: illegal characters or empty")
    # Reject bare boolean operators used as injection scaffolding.
    if re.search(r"(?i)(^|\s)(or|and|around)(\s|$)", v):
        raise errors.query_rejected(f"{field}: boolean operators are not allowed in values")
    return v


def build_query(
    allowed_category_ids: set[str],
    *,
    category: str | None = None,
    unread_only: bool = False,
    from_: str | None = None,
    subject: str | None = None,
    after: str | None = None,
    before: str | None = None,
    newer_than: str | None = None,
    older_than: str | None = None,
) -> str:
    """Assemble a scoped, sanitized Gmail ``q``.

    If ``category`` is given it must be within the allowed set and scopes to just
    that category; otherwise the query scopes to the union of allowed categories.
    """
    # --- category group ---------------------------------------------------
    if category is not None:
        cid = category_id_for_name(category)
        if cid is None or cid not in allowed_category_ids:
            raise errors.not_eligible(f"category not allowed: {category!r}")
        scope_ids = {cid}
    else:
        scope_ids = set(allowed_category_ids)
    if not scope_ids:
        raise errors.query_rejected("no categories in scope")
    tokens = sorted(f"category:{SEARCH_TOKEN_BY_CATEGORY_ID[c]}" for c in scope_ids)
    category_group = "(" + " OR ".join(tokens) + ")"

    # --- value group ------------------------------------------------------
    terms: list[str] = []
    if unread_only:
        terms.append("is:unread")  # proxy-chosen literal, never interpolated
    if from_ is not None:
        terms.append(f'from:("{_validate_value("from", from_)}")')
    if subject is not None:
        terms.append(f'subject:("{_validate_value("subject", subject)}")')
    for name, val in (("newer_than", newer_than), ("older_than", older_than)):
        if val is not None:
            if not _RELATIVE_DATE.match(val):
                raise errors.query_rejected(f"{name}: must match \\d{{1,4}}[dmy]")
            terms.append(f"{name}:{val}")
    for name, val in (("after", after), ("before", before)):
        if val is not None:
            if not _ABSOLUTE_DATE.match(val):
                raise errors.query_rejected(f"{name}: must match YYYY/MM/DD")
            terms.append(f"{name}:{val}")

    q = category_group if not terms else f"{category_group} AND (" + " ".join(terms) + ")"

    _assert_scoped(q, scope_ids)
    return q


def _assert_scoped(q: str, scope_ids: set[str]) -> None:
    """Positive re-scan: every colon-operator must be allowlisted, and the
    category tokens must be exactly those in scope."""
    for op in _OPERATOR_TOKEN.findall(q):
        if op not in _ALLOWED_OPERATORS:
            raise errors.query_rejected(f"disallowed operator in assembled query: {op!r}")
    found = set(re.findall(r"category:(\w+)", q))
    expected = {SEARCH_TOKEN_BY_CATEGORY_ID[c] for c in scope_ids}
    if found != expected:
        raise errors.ProxyError(
            500, "query_rejected", f"category-scope invariant violated: {found} != {expected}"
        )
