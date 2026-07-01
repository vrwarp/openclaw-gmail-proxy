"""Tests for validate_mutation() -- the label-mutation / smuggling guard."""

import pytest

from gmail_proxy import errors
from gmail_proxy.config import Policy
from gmail_proxy.models import Label
from gmail_proxy.policy.mutation import validate_mutation

LABELS = [
    Label("INBOX", "INBOX", "system"),
    Label("UNREAD", "UNREAD", "system"),
    Label("STARRED", "STARRED", "system"),
    Label("SPAM", "SPAM", "system"),
    Label("TRASH", "TRASH", "system"),
    Label("IMPORTANT", "IMPORTANT", "system"),
    Label("CATEGORY_PROMOTIONS", "CATEGORY_PROMOTIONS", "system"),
    Label("Label_1", "Receipts", "user"),
]


def policy(**kw):
    kw.setdefault("mutable_labels", ["UNREAD", "STARRED", "INBOX"])
    return Policy(allowed_categories=["promotions", "social"], **kw)


def test_archive_via_remove_inbox_is_allowed():
    r = validate_mutation(None, ["INBOX"], policy(), LABELS)
    assert r.remove_ids == ["INBOX"] and r.add_ids == []


def test_mark_read_allowed():
    r = validate_mutation(None, ["UNREAD"], policy(), LABELS)
    assert r.remove_ids == ["UNREAD"]


def test_user_label_add_allowed():
    r = validate_mutation(["Receipts"], None, policy(), LABELS)
    assert r.add_ids == ["Label_1"]


def test_user_label_blocked_when_disabled():
    with pytest.raises(errors.ProxyError) as ei:
        validate_mutation(["Receipts"], None, policy(allow_user_label_mutations=False), LABELS)
    assert ei.value.reason == "label_immutable"


@pytest.mark.parametrize("label,reason", [
    ("CATEGORY_PROMOTIONS", "category_mutation_forbidden"),
    ("SPAM", "label_immutable"),
    ("TRASH", "label_immutable"),
])
def test_immutable_labels_rejected(label, reason):
    with pytest.raises(errors.ProxyError) as ei:
        validate_mutation([label], None, policy(), LABELS)
    assert ei.value.reason == reason
    with pytest.raises(errors.ProxyError) as ei2:
        validate_mutation(None, [label], policy(), LABELS)
    assert ei2.value.reason == reason


def test_system_label_not_in_mutable_allow_rejected():
    with pytest.raises(errors.ProxyError) as ei:
        validate_mutation(["IMPORTANT"], None, policy(), LABELS)
    assert ei.value.reason == "label_immutable"


def test_read_only_mode_forbids_mutation():
    with pytest.raises(errors.ProxyError) as ei:
        validate_mutation(None, ["UNREAD"], policy(mode="read_only"), LABELS)
    assert ei.value.reason == "mutation_not_allowed"


def test_same_label_add_and_remove_rejected():
    with pytest.raises(errors.ProxyError):
        validate_mutation(["STARRED"], ["STARRED"], policy(), LABELS)


def test_unknown_label_unresolvable():
    with pytest.raises(errors.ProxyError) as ei:
        validate_mutation(["Nonexistent"], None, policy(), LABELS)
    assert ei.value.reason == "label_unresolvable"


def test_policy_load_rejects_immutable_in_mutable_allow():
    with pytest.raises(Exception):
        Policy(allowed_categories=["promotions"], mutable_labels=["CATEGORY_PROMOTIONS"])
