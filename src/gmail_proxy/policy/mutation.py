"""``validate_mutation()`` -- the label-mutation guard.

Callers supply label **names**.  This resolves them to concrete label ids and
enforces:

* ``CATEGORY_*`` labels can never be added or removed (that is how a message
  would be smuggled into/out of scope) -> ``category_mutation_forbidden``.
* ``SPAM`` / ``TRASH`` can never be toggled via labels (trash has its own gated
  tool) -> ``label_immutable``.
* System labels are mutable only if listed in ``policy.mutable_labels``
  (e.g. ``INBOX`` for archive, ``UNREAD`` for read-state, ``STARRED``).
* User labels are mutable only if ``policy.allow_user_label_mutations``.
* read-only mode forbids all mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import errors
from ..categories import ALL_CATEGORY_ID_SET
from ..config import Policy
from ..models import Label


@dataclass
class ResolvedMutation:
    add_ids: list[str] = field(default_factory=list)
    remove_ids: list[str] = field(default_factory=list)


def _resolve(name: str, labels: list[Label]) -> Label:
    by_id = {lb.id: lb for lb in labels}
    # A system label id (UPPERCASE enum, name == id) takes precedence.
    lab = by_id.get(name)
    if lab is not None and lab.type == "system":
        return lab
    # Otherwise resolve by display name, preferring exactly one user label.
    named = [lb for lb in labels if lb.name == name]
    user_named = [lb for lb in named if lb.type == "user"]
    if len(user_named) == 1:
        return user_named[0]
    if len(user_named) > 1:
        raise errors.ProxyError(400, "label_unresolvable", f"ambiguous label name: {name!r}")
    if len(named) == 1:
        return named[0]
    raise errors.ProxyError(400, "label_unresolvable", f"unknown label: {name!r}")


def _check_mutable(label: Label, policy: Policy, allowed_label_ids: frozenset[str]) -> None:
    if label.id in ALL_CATEGORY_ID_SET:
        raise errors.ProxyError(403, "category_mutation_forbidden", label.id)
    if label.id in ("SPAM", "TRASH"):
        raise errors.ProxyError(403, "label_immutable", label.id)
    # Eligibility-granting labels are immutable: adding one would smuggle a
    # message into scope, removing one would smuggle it out.
    if label.id in allowed_label_ids:
        raise errors.ProxyError(403, "label_immutable", f"eligibility label {label.id} is immutable")
    if label.type == "system":
        if label.id not in policy.mutable_labels:
            raise errors.ProxyError(403, "label_immutable", f"system label {label.id} not mutable")
    else:  # user label
        if not policy.allow_user_label_mutations:
            raise errors.ProxyError(403, "label_immutable", "user-label mutations disabled")


def _dedupe(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def validate_mutation(
    add_labels: list[str] | None,
    remove_labels: list[str] | None,
    policy: Policy,
    labels: list[Label],
    allowed_label_ids: frozenset[str] = frozenset(),
) -> ResolvedMutation:
    """Resolve + authorize a requested label mutation.  Raises ``ProxyError``."""
    if policy.mode == "read_only":
        raise errors.ProxyError(403, "mutation_not_allowed", "proxy is in read_only mode")

    add_ids: list[str] = []
    remove_ids: list[str] = []
    for names, out in ((add_labels or [], add_ids), (remove_labels or [], remove_ids)):
        for name in names:
            label = _resolve(name, labels)
            _check_mutable(label, policy, allowed_label_ids)
            out.append(label.id)

    add_set, remove_set = set(add_ids), set(remove_ids)
    if add_set & remove_set:
        raise errors.invalid_arguments("a label appears in both add and remove")
    if not add_ids and not remove_ids:
        raise errors.invalid_arguments("no labels to add or remove")

    return ResolvedMutation(add_ids=_dedupe(add_ids), remove_ids=_dedupe(remove_ids))
