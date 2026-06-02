from __future__ import annotations

import asyncio

import pytest

from aiolrucache.decorators import alru_cache, lru_cache


class TestLruCacheDecorator:
    def test_basic_caching(self) -> None:
        call_count = 0

        @lru_cache(max_size=3)
        def expensive(a: int) -> int:
            nonlocal call_count
            call_count += 1
            return a * 2

        assert expensive(1) == 2
        assert expensive(1) == 2
        assert call_count == 1

    def test_max_size_eviction(self) -> None:
        call_count = 0

        @lru_cache(max_size=2)
        def expensive(a: int) -> int:
            nonlocal call_count
            call_count += 1
            return a

        expensive(1)
        expensive(2)
        expensive(1)
        expensive(3)
        expensive(1)
        assert call_count == 3

    def test_cache_clear(self) -> None:
        call_count = 0

        @lru_cache(max_size=3)
        def expensive(a: int) -> int:
            nonlocal call_count
            call_count += 1
            return a

        expensive(1)
        expensive(2)
        expensive.cache_clear()
        expensive(1)
        assert call_count == 3

    def test_cache_info(self) -> None:
        @lru_cache(max_size=3)
        def expensive(a: int) -> int:
            return a

        expensive(1)
        expensive(2)
        info = expensive.cache_info()
        assert info["max_size"] == 3
        assert info["ttl"] is None
        assert info["size"] == 2

    def test_with_kwargs(self) -> None:
        call_count = 0

        @lru_cache(max_size=3)
        def expensive(a: int, b: int = 0) -> int:
            nonlocal call_count
            call_count += 1
            return a + b

        expensive(1)
        expensive(1, b=0)
        assert call_count == 2


class TestAlruCacheDecorator:
    @pytest.mark.asyncio
    async def test_basic_caching(self) -> None:
        call_count = 0

        @alru_cache(max_size=3)
        async def expensive(a: int) -> int:
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.001)
            return a * 2

        assert await expensive(1) == 2
        assert await expensive(1) == 2
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_max_size_eviction(self) -> None:
        call_count = 0

        @alru_cache(max_size=2)
        async def expensive(a: int) -> int:
            nonlocal call_count
            call_count += 1
            return a

        await expensive(1)
        await expensive(2)
        await expensive(1)
        await expensive(3)
        await expensive(1)
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_cache_clear(self) -> None:
        call_count = 0

        @alru_cache(max_size=3)
        async def expensive(a: int) -> int:
            nonlocal call_count
            call_count += 1
            return a

        await expensive(1)
        await expensive(2)
        await expensive.cache_clear()
        await expensive(1)
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_cache_info(self) -> None:
        @alru_cache(max_size=3)
        async def expensive(a: int) -> int:
            return a

        await expensive(1)
        await expensive(2)
        info = expensive.cache_info()
        assert info["max_size"] == 3
        assert info["ttl"] is None
        assert info["size"] == 2

    @pytest.mark.asyncio
    async def test_with_kwargs(self) -> None:
        call_count = 0

        @alru_cache(max_size=3)
        async def expensive(a: int, b: int = 0) -> int:
            nonlocal call_count
            call_count += 1
            return a + b

        await expensive(1)
        await expensive(1, b=0)
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_ttl_expiry(self) -> None:
        call_count = 0

        @alru_cache(max_size=3, ttl=0.05)
        async def expensive(a: int) -> int:
            nonlocal call_count
            call_count += 1
            return a

        await expensive(1)
        assert await expensive(1) == 1
        assert call_count == 1
        await asyncio.sleep(0.06)
        assert await expensive(1) == 1
        assert call_count == 2
