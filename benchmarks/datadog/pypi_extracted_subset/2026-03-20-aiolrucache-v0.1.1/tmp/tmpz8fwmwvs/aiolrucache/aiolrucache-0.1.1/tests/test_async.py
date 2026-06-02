from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from aiolrucache.async_ import AsyncLRU


class TestAsyncLRU:
    @pytest_asyncio.fixture
    async def cache(self) -> AsyncLRU[str, int]:
        return AsyncLRU[str, int](max_size=3)

    @pytest_asyncio.fixture
    async def cache_with_ttl(self) -> AsyncLRU[str, int]:
        return AsyncLRU[str, int](max_size=3, ttl=0.05)

    @pytest.mark.asyncio
    async def test_basic_get_set(self, cache: AsyncLRU[str, int]) -> None:
        await cache.set("a", 1)
        assert await cache.get("a") == 1
        assert await cache.get("b") is None

    @pytest.mark.asyncio
    async def test_max_size_eviction(self, cache: AsyncLRU[str, int]) -> None:
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.set("c", 3)
        await cache.set("d", 4)
        assert await cache.get("a") is None
        assert await cache.get("b") == 2
        assert await cache.get("c") == 3
        assert await cache.get("d") == 4

    @pytest.mark.asyncio
    async def test_lru_ordering(self, cache: AsyncLRU[str, int]) -> None:
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.set("c", 3)
        await cache.get("a")
        await cache.set("d", 4)
        assert await cache.get("a") == 1
        assert await cache.get("b") is None

    @pytest.mark.asyncio
    async def test_ttl_expiry(self, cache_with_ttl: AsyncLRU[str, int]) -> None:
        await cache_with_ttl.set("a", 1)
        assert await cache_with_ttl.get("a") == 1
        await asyncio.sleep(0.06)
        assert await cache_with_ttl.get("a") is None

    @pytest.mark.asyncio
    async def test_ttl_no_expiry(self, cache_with_ttl: AsyncLRU[str, int]) -> None:
        await cache_with_ttl.set("a", 1)
        await asyncio.sleep(0.01)
        assert await cache_with_ttl.get("a") == 1

    @pytest.mark.asyncio
    async def test_clear(self, cache: AsyncLRU[str, int]) -> None:
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.clear()
        assert await cache.get("a") is None
        assert len(cache) == 0

    @pytest.mark.asyncio
    async def test_contains(self, cache: AsyncLRU[str, int]) -> None:
        await cache.set("a", 1)
        assert "a" in cache
        assert "b" not in cache

    @pytest.mark.asyncio
    async def test_len(self, cache: AsyncLRU[str, int]) -> None:
        assert len(cache) == 0
        await cache.set("a", 1)
        await cache.set("b", 2)
        assert len(cache) == 2

    @pytest.mark.asyncio
    async def test_info(self, cache: AsyncLRU[str, int]) -> None:
        info = cache.info()
        assert info["max_size"] == 3
        assert info["ttl"] is None
        assert info["size"] == 0

    @pytest.mark.asyncio
    async def test_invalid_max_size(self) -> None:
        with pytest.raises(ValueError, match="max_size must be positive"):
            AsyncLRU[str, int](max_size=0)

    @pytest.mark.asyncio
    async def test_invalid_ttl(self) -> None:
        with pytest.raises(ValueError, match="ttl must be positive"):
            AsyncLRU[str, int](max_size=3, ttl=-1)

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        async with AsyncLRU[str, int](max_size=3) as cache:
            await cache.set("a", 1)
            assert await cache.get("a") == 1

    @pytest.mark.asyncio
    async def test_aclose(self, cache: AsyncLRU[str, int]) -> None:
        await cache.set("a", 1)
        await cache.aclose()
        assert len(cache) == 0
