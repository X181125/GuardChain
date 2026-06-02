from __future__ import annotations

import time

import pytest

from aiolrucache._core import LRUCache


class TestSyncLRU:
    def test_basic_get_set(self) -> None:
        cache = LRUCache[str, int](max_size=3)
        cache.set("a", 1)
        assert cache.get("a") == 1
        assert cache.get("b") is None

    def test_max_size_eviction(self) -> None:
        cache = LRUCache[str, int](max_size=3)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        cache.set("d", 4)
        assert cache.get("a") is None
        assert cache.get("b") == 2
        assert cache.get("c") == 3
        assert cache.get("d") == 4

    def test_lru_ordering(self) -> None:
        cache = LRUCache[str, int](max_size=3)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        cache.get("a")
        cache.set("d", 4)
        assert cache.get("a") == 1
        assert cache.get("b") is None

    def test_ttl_expiry(self) -> None:
        cache = LRUCache[str, int](max_size=3, ttl=0.05)
        cache.set("a", 1)
        assert cache.get("a") == 1
        time.sleep(0.06)
        assert cache.get("a") is None

    def test_ttl_no_expiry(self) -> None:
        cache = LRUCache[str, int](max_size=3, ttl=10.0)
        cache.set("a", 1)
        time.sleep(0.01)
        assert cache.get("a") == 1

    def test_clear(self) -> None:
        cache = LRUCache[str, int](max_size=3)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.clear()
        assert cache.get("a") is None
        assert len(cache) == 0

    def test_contains(self) -> None:
        cache = LRUCache[str, int](max_size=3)
        cache.set("a", 1)
        assert "a" in cache
        assert "b" not in cache

    def test_len(self) -> None:
        cache = LRUCache[str, int](max_size=3)
        assert len(cache) == 0
        cache.set("a", 1)
        cache.set("b", 2)
        assert len(cache) == 2

    def test_info(self) -> None:
        cache = LRUCache[str, int](max_size=3, ttl=5.0)
        info = cache.info()
        assert info["max_size"] == 3
        assert info["ttl"] == 5.0
        assert info["size"] == 0

    def test_invalid_max_size(self) -> None:
        with pytest.raises(ValueError, match="max_size must be positive"):
            LRUCache[str, int](max_size=0)

    def test_invalid_ttl(self) -> None:
        with pytest.raises(ValueError, match="ttl must be positive"):
            LRUCache[str, int](max_size=3, ttl=-1)

    def test_update_existing_key(self) -> None:
        cache = LRUCache[str, int](max_size=3)
        cache.set("a", 1)
        cache.set("a", 2)
        assert cache.get("a") == 2
        assert len(cache) == 1

    def test_update_key_maintains_order(self) -> None:
        cache = LRUCache[str, int](max_size=3)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("a", 10)
        cache.set("c", 3)
        cache.set("d", 4)
        assert cache.get("a") == 10
        assert cache.get("b") is None
