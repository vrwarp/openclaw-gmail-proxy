"""Caching backend decorator to reduce real Gmail API calls.

Wraps any :class:`GmailBackend`.  Two kinds of cache, chosen for correctness:

* **Content cache** -- an LRU of full messages keyed by id.  Message content is
  *immutable* in Gmail, so this is durable (no TTL).  It stores content only; the
  eligibility decision is never cached here.
* **TTL caches** -- for labels/list/profile, which *can* change.  ``metadata``
  (labels) drives eligibility, so its default TTL is 0 (always fresh); a positive
  TTL is an explicit freshness-vs-calls tradeoff and is invalidated on mutation.

Caches never bypass the eligibility gate: the tool layer re-checks fresh labels
(``get_message_metadata``) before returning any cached content, and mutations
invalidate the affected entries + the list cache.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from collections import OrderedDict

from .config import CacheConfig
from .gmail.client import GmailBackend
from .models import Message, Thread


def _copy_message(m: Message) -> Message:
    return dataclasses.replace(
        m, label_ids=list(m.label_ids), headers=dict(m.headers), attachments=list(m.attachments)
    )


class _Stats:
    __slots__ = ("hits", "misses", "evictions")

    def __init__(self) -> None:
        self.hits = self.misses = self.evictions = 0


class CachingGmailBackend(GmailBackend):
    def __init__(self, inner: GmailBackend, cfg: CacheConfig) -> None:
        self.inner = inner
        self.cfg = cfg
        self._lock = threading.RLock()
        self._content: "OrderedDict[str, Message]" = OrderedDict()
        self._ttl: dict[str, dict[str, tuple[float, object]]] = {
            "metadata": {}, "list": {}, "labels": {}, "profile": {}
        }
        self._stats = {k: _Stats() for k in ("content", "metadata", "list", "labels", "profile")}

    # --- config / reconfigure --------------------------------------------
    def reconfigure(self, cfg: CacheConfig) -> None:
        with self._lock:
            self.cfg = cfg
            if not cfg.content.enabled:
                self._content.clear()
            else:
                self._trim_content()

    # --- content cache (immutable, LRU) ----------------------------------
    def _content_get(self, mid: str) -> Message | None:
        if not self.cfg.content.enabled or self.cfg.content.max_messages == 0:
            return None
        with self._lock:
            m = self._content.get(mid)
            if m is None:
                self._stats["content"].misses += 1
                return None
            self._content.move_to_end(mid)
            self._stats["content"].hits += 1
            return _copy_message(m)

    def _content_put(self, m: Message) -> None:
        if not self.cfg.content.enabled or self.cfg.content.max_messages == 0:
            return
        with self._lock:
            self._content[m.id] = _copy_message(m)
            self._content.move_to_end(m.id)
            self._trim_content()

    def _trim_content(self) -> None:
        cap = self.cfg.content.max_messages
        while len(self._content) > cap:
            self._content.popitem(last=False)
            self._stats["content"].evictions += 1

    # --- generic TTL cache ------------------------------------------------
    _MISS = object()

    def _ttl_get(self, bucket: str, key, ttl: int):
        if ttl <= 0:
            self._stats[bucket].misses += 1
            return self._MISS
        with self._lock:
            entry = self._ttl[bucket].get(key)
            if entry is not None and entry[0] > time.monotonic():
                self._stats[bucket].hits += 1
                return entry[1]
            if entry is not None:
                self._ttl[bucket].pop(key, None)
            self._stats[bucket].misses += 1
            return self._MISS

    def _ttl_put(self, bucket: str, key, value, ttl: int) -> None:
        if ttl <= 0:
            return
        with self._lock:
            self._ttl[bucket][key] = (time.monotonic() + ttl, value)

    def _invalidate_on_mutation(self, mid: str) -> None:
        with self._lock:
            self._ttl["metadata"].pop(mid, None)
            self._ttl["list"].clear()      # list/counts results changed
            self._content.pop(mid, None)   # labels-on-content now stale; refetch content too

    # --- GmailBackend interface ------------------------------------------
    def list_message_ids(self, q, max_results, page_token):
        key = (q, max_results, page_token)
        cached = self._ttl_get("list", key, self.cfg.list_ttl_s)
        if cached is not self._MISS:
            ids, nxt = cached
            return list(ids), nxt
        ids, nxt = self.inner.list_message_ids(q, max_results, page_token)
        self._ttl_put("list", key, (list(ids), nxt), self.cfg.list_ttl_s)
        return ids, nxt

    def get_message(self, message_id):
        hit = self._content_get(message_id)
        if hit is not None:
            return hit
        m = self.inner.get_message(message_id)
        self._content_put(m)
        return m

    def get_message_metadata(self, message_id):
        cached = self._ttl_get("metadata", message_id, self.cfg.metadata_ttl_s)
        if cached is not self._MISS:
            return _copy_message(cached)
        m = self.inner.get_message_metadata(message_id)
        self._ttl_put("metadata", message_id, m, self.cfg.metadata_ttl_s)
        return m

    def get_thread(self, thread_id) -> Thread:
        thread = self.inner.get_thread(thread_id)
        for m in thread.messages:  # warm the content cache with immutable members
            self._content_put(m)
        return thread

    def modify_labels(self, message_id, add_ids, remove_ids):
        result = self.inner.modify_labels(message_id, add_ids, remove_ids)
        self._invalidate_on_mutation(message_id)
        return result

    def trash(self, message_id):
        result = self.inner.trash(message_id)
        self._invalidate_on_mutation(message_id)
        return result

    def list_labels(self):
        cached = self._ttl_get("labels", "_", self.cfg.labels_ttl_s)
        if cached is not self._MISS:
            return list(cached)
        labels = self.inner.list_labels()
        self._ttl_put("labels", "_", list(labels), self.cfg.labels_ttl_s)
        return labels

    def get_profile(self):
        cached = self._ttl_get("profile", "_", self.cfg.profile_ttl_s)
        if cached is not self._MISS:
            return dict(cached)
        p = self.inner.get_profile()
        self._ttl_put("profile", "_", dict(p), self.cfg.profile_ttl_s)
        return p

    # --- stats for the admin UI ------------------------------------------
    def stats(self) -> dict:
        with self._lock:
            def rate(s: _Stats) -> float:
                total = s.hits + s.misses
                return round(100 * s.hits / total, 1) if total else 0.0

            out = {
                "content": {
                    "enabled": self.cfg.content.enabled,
                    "size": len(self._content),
                    "capacity": self.cfg.content.max_messages,
                    "hits": self._stats["content"].hits,
                    "misses": self._stats["content"].misses,
                    "evictions": self._stats["content"].evictions,
                    "hit_rate": rate(self._stats["content"]),
                },
            }
            for bucket, ttl in (("metadata", self.cfg.metadata_ttl_s), ("list", self.cfg.list_ttl_s),
                                ("labels", self.cfg.labels_ttl_s), ("profile", self.cfg.profile_ttl_s)):
                s = self._stats[bucket]
                out[bucket] = {"ttl_s": ttl, "entries": len(self._ttl[bucket]),
                               "hits": s.hits, "misses": s.misses, "hit_rate": rate(s)}
            out["api_calls_saved"] = sum(s.hits for s in self._stats.values())
            return out

    def reset_stats(self) -> None:
        with self._lock:
            for s in self._stats.values():
                s.hits = s.misses = s.evictions = 0

    def clear(self) -> None:
        with self._lock:
            self._content.clear()
            for b in self._ttl.values():
                b.clear()
