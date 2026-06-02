# aiolrucache

An asyncio LRU cache with TTL support for Python 3.14+.

## Installation

```bash
pip install aiolrucache
```

## Features

- **AsyncLRU**: Async-aware LRU cache with TTL support
- **@alru_cache**: Decorator for async functions (like stdlib `@lru_cache`)
- **LRU**: Sync LRU cache with TTL support
- **@lru_cache**: Decorator for sync functions
- **Lazy TTL eviction**: Expired entries are evicted on access
- **Thread-safe**: Sync LRU uses threading locks

## Quick Start

### Class-based usage

```python
import asyncio
from aiolrucache import AsyncLRU

async def main():
    cache = AsyncLRU(max_size=128, ttl=3600.0)  # 1 hour TTL
    
    await cache.set("key", {"data": "value"})
    result = await cache.get("key")
    
    async with AsyncLRU(max_size=64) as cache:
        await cache.set("foo", "bar")
        print(await cache.get("foo"))

asyncio.run(main())
```

### Decorator usage

```python
from aiolrucache import alru_cache, lru_cache

# Async
@alru_cache(max_size=64, ttl=1800.0)
async def fetch_data(url: str) -> dict:
    # Expensive async operation
    ...

# Sync
@lru_cache(max_size=128)
def expensive_computation(n: int) -> int:
    ...
```

## API Reference

### AsyncLRU

```python
class AsyncLRU[K, V]:
    def __init__(self, max_size: int, ttl: float | None = None) -> None:
        """
        Args:
            max_size: Maximum number of entries (required, must be positive)
            ttl: Time-to-live in seconds (optional, None = no expiry)
        """
    
    async def get(self, key: K) -> V | None: ...
    async def set(self, key: K, value: V) -> None: ...
    async def clear(self) -> None: ...
    async def aclose(self) -> None: ...
    
    def __len__(self) -> int: ...
    def __contains__(self, key: K) -> bool: ...
    def info(self) -> dict: ...
```

### @alru_cache Decorator

```python
@alru_cache(max_size: int = 128, *, ttl: float | None = None)
async def cached_func(arg: ArgType) -> ReturnType: ...

# Methods added to decorated function:
cached_func.cache_clear()  # Clear the cache
cached_func.cache_info()  # dict with max_size, ttl, size
```

### @lru_cache Decorator

Same API as `@alru_cache` but for sync functions.

## Development

```bash
# Install dev dependencies
uv sync --extra dev

# Run tests
pytest

# Run linter
ruff check src tests

# Run type checker
uvx ty check src
```

## License

MIT
