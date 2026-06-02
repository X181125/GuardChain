from __future__ import annotations

from collections.abc import Awaitable, Callable, Hashable
from functools import wraps
from typing import Any, TypeVar

KT = TypeVar("KT", bound=Hashable)
VT = TypeVar("VT")


def lru_cache(
    max_size: int = 128,
    *,
    ttl: float | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        import threading
        import time

        cache: dict[tuple[Any, ...], tuple[Any, float | None]] = {}
        order: list[tuple[Any, ...]] = []
        lock = threading.Lock()

        def make_key(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[Any, ...]:
            key = (id(func), args)
            if kwargs:
                key = (*key, tuple(sorted(kwargs.items())))
            return key

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = make_key(args, kwargs)
            with lock:
                entry = cache.get(key)
                if entry is not None:
                    value, expires_at = entry
                    if expires_at is None or time.monotonic() <= expires_at:
                        if key in order:
                            order.remove(key)
                        order.append(key)
                        return value
                    del cache[key]
                    order.remove(key)

            result = func(*args, **kwargs)

            with lock:
                if len(cache) >= max_size and key not in cache:
                    oldest = order.pop(0)
                    del cache[oldest]

                expires_at = None if ttl is None else time.monotonic() + ttl
                cache[key] = (result, expires_at)
                order.append(key)

            return result

        def cache_clear() -> None:
            with lock:
                cache.clear()
                order.clear()

        def cache_info() -> dict[str, Any]:
            with lock:
                return {
                    "max_size": max_size,
                    "ttl": ttl,
                    "size": len(cache),
                }

        wrapper.cache_clear = cache_clear  # type: ignore[attr-defined]
        wrapper.cache_info = cache_info  # type: ignore[attr-defined]

        return wrapper

    return decorator


def alru_cache(
    max_size: int = 128,
    *,
    ttl: float | None = None,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        import asyncio
        import time
        from functools import wraps

        cache: dict[tuple[Any, ...], tuple[Any, float | None]] = {}
        order: list[tuple[Any, ...]] = []
        lock: asyncio.Lock = asyncio.Lock()

        def make_key(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[Any, ...]:
            key = (id(func), args)
            if kwargs:
                key = (*key, tuple(sorted(kwargs.items())))
            return key

        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = make_key(args, kwargs)
            async with lock:
                entry = cache.get(key)
                if entry is not None:
                    value, expires_at = entry
                    if expires_at is None or time.monotonic() <= expires_at:
                        if key in order:
                            order.remove(key)
                        order.append(key)
                        return value
                    del cache[key]
                    order.remove(key)

            result = await func(*args, **kwargs)

            async with lock:
                if len(cache) >= max_size and key not in cache:
                    oldest = order.pop(0)
                    del cache[oldest]

                expires_at = None if ttl is None else time.monotonic() + ttl
                cache[key] = (result, expires_at)
                order.append(key)

            return result

        async def cache_clear() -> None:
            async with lock:
                cache.clear()
                order.clear()

        def cache_info() -> dict[str, Any]:
            return {
                "max_size": max_size,
                "ttl": ttl,
                "size": len(cache),
            }

        wrapper.cache_clear = cache_clear  # type: ignore[attr-defined]
        wrapper.cache_info = cache_info  # type: ignore[attr-defined]

        return wrapper

    return decorator
