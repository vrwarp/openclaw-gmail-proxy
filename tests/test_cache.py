"""Tests for CachingGmailBackend: real API-call reduction + correctness."""

from collections import Counter

import pytest

from gmail_proxy.cache import CachingGmailBackend
from gmail_proxy.config import CacheConfig, ContentCache
from gmail_proxy.gmail.client import GmailBackend
from gmail_proxy.gmail.mock_client import sample_backend


class Counting(GmailBackend):
    """Wraps a backend and counts inner calls (to prove cache hits)."""

    def __init__(self, inner):
        self.inner = inner
        self.calls: Counter = Counter()

    def list_message_ids(self, q, m, p):
        self.calls["list"] += 1
        return self.inner.list_message_ids(q, m, p)

    def get_message(self, mid):
        self.calls["get"] += 1
        return self.inner.get_message(mid)

    def get_message_metadata(self, mid):
        self.calls["meta"] += 1
        return self.inner.get_message_metadata(mid)

    def get_thread(self, tid):
        self.calls["thread"] += 1
        return self.inner.get_thread(tid)

    def modify_labels(self, mid, a, r):
        self.calls["modify"] += 1
        return self.inner.modify_labels(mid, a, r)

    def trash(self, mid):
        self.calls["trash"] += 1
        return self.inner.trash(mid)

    def list_labels(self):
        self.calls["labels"] += 1
        return self.inner.list_labels()

    def get_profile(self):
        self.calls["profile"] += 1
        return self.inner.get_profile()


def make(cfg=None):
    inner = Counting(sample_backend())
    return CachingGmailBackend(inner, cfg or CacheConfig()), inner


def test_content_cache_hit_avoids_refetch():
    cb, inner = make()
    a = cb.get_message("m001")
    b = cb.get_message("m001")
    assert a.body_text == b.body_text
    assert inner.calls["get"] == 1  # second served from cache
    assert cb.stats()["content"]["hits"] == 1


def test_content_cache_returns_independent_copies():
    cb, _ = make()
    a = cb.get_message("m001")
    a.label_ids.append("MUTATED")  # caller mutation must not poison the cache
    b = cb.get_message("m001")
    assert "MUTATED" not in b.label_ids


def test_content_cache_eviction():
    cb, inner = make(CacheConfig(content=ContentCache(enabled=True, max_messages=2)))
    for mid in ("m001", "m002", "m003"):
        cb.get_message(mid)
    s = cb.stats()["content"]
    assert s["size"] == 2 and s["evictions"] == 1


def test_content_cache_disabled_always_fetches():
    cb, inner = make(CacheConfig(content=ContentCache(enabled=False)))
    cb.get_message("m001")
    cb.get_message("m001")
    assert inner.calls["get"] == 2


def test_metadata_ttl_zero_is_always_fresh():
    cb, inner = make(CacheConfig(metadata_ttl_s=0))
    cb.get_message_metadata("m001")
    cb.get_message_metadata("m001")
    assert inner.calls["meta"] == 2  # eligibility labels never cached at ttl=0


def test_metadata_ttl_positive_caches():
    cb, inner = make(CacheConfig(metadata_ttl_s=60))
    cb.get_message_metadata("m001")
    cb.get_message_metadata("m001")
    assert inner.calls["meta"] == 1


def test_list_ttl_caches():
    cb, inner = make(CacheConfig(list_ttl_s=60))
    cb.list_message_ids("(category:promotions)", 25, None)
    cb.list_message_ids("(category:promotions)", 25, None)
    assert inner.calls["list"] == 1


def test_mutation_invalidates_metadata_content_and_list():
    cb, inner = make(CacheConfig(content=ContentCache(enabled=True, max_messages=100),
                                 metadata_ttl_s=60, list_ttl_s=60))
    cb.get_message("m001")                       # warm content
    cb.get_message_metadata("m001")              # warm metadata
    cb.list_message_ids("(category:promotions)", 25, None)  # warm list
    cb.modify_labels("m001", [], ["UNREAD"])     # mutation
    cb.get_message("m001")                        # content refetched
    cb.get_message_metadata("m001")               # metadata refetched
    cb.list_message_ids("(category:promotions)", 25, None)  # list refetched
    assert inner.calls["get"] == 2
    assert inner.calls["meta"] == 2
    assert inner.calls["list"] == 2


def test_labels_and_profile_ttl():
    cb, inner = make(CacheConfig(labels_ttl_s=60, profile_ttl_s=60))
    cb.list_labels(); cb.list_labels()
    cb.get_profile(); cb.get_profile()
    assert inner.calls["labels"] == 1 and inner.calls["profile"] == 1


def test_stats_shape():
    cb, _ = make(CacheConfig(metadata_ttl_s=30))
    cb.get_message("m001")
    st = cb.stats()
    assert set(st) >= {"content", "metadata", "list", "labels", "profile", "api_calls_saved"}
    assert st["metadata"]["ttl_s"] == 30


def test_reconfigure_shrinks_cache():
    cb, _ = make(CacheConfig(content=ContentCache(enabled=True, max_messages=100)))
    for mid in ("m001", "m002", "m003"):
        cb.get_message(mid)
    cb.reconfigure(CacheConfig(content=ContentCache(enabled=True, max_messages=1)))
    assert cb.stats()["content"]["size"] == 1
