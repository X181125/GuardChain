from __future__ import annotations

from collections.abc import Hashable
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    import asyncio


KT = TypeVar("KT", bound=Hashable)
VT = TypeVar("VT")


class AsyncLRU(Generic[KT, VT]):
    __slots__ = ("_data", "_order", "_max_size", "_ttl", "_lock", "_async_lock")

    def __init__(
        self,
        max_size: int,
        ttl: float | None = None,
    ) -> None:
        import asyncio
        import threading
        from collections import OrderedDict

        if max_size <= 0:
            msg = "max_size must be positive"
            raise ValueError(msg)
        if ttl is not None and ttl <= 0:
            msg = "ttl must be positive"
            raise ValueError(msg)

        self._data: dict[KT, tuple[VT, float | None]] = {}
        self._order: OrderedDict[KT, None] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl
        self._lock: threading.Lock = threading.Lock()
        self._async_lock: asyncio.Lock = asyncio.Lock()

    async def get(self, key: KT) -> VT | None:
        import time

        async with self._async_lock:
            entry = self._data.get(key)
            if entry is None:
                return None

            value, expires_at = entry
            if expires_at is not None and time.monotonic() > expires_at:
                del self._data[key]
                del self._order[key]
                return None

            self._order.move_to_end(key)
            return value

    async def set(self, key: KT, value: VT) -> None:
        import time

        async with self._async_lock:
            if key in self._data:
                self._order.move_to_end(key)
                expires_at = None if self._ttl is None else time.monotonic() + self._ttl
                self._data[key] = (value, expires_at)
                return

            if len(self._data) >= self._max_size:
                oldest = next(iter(self._order))
                del self._order[oldest]
                del self._data[oldest]

            self._order[key] = None
            expires_at = None if self._ttl is None else time.monotonic() + self._ttl
            self._data[key] = (value, expires_at)

    async def clear(self) -> None:
        async with self._async_lock:
            self._data.clear()
            self._order.clear()

    async def aclose(self) -> None:
        await self.clear()

    async def __aenter__(self) -> AsyncLRU[KT, VT]:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, key: KT) -> bool:
        return key in self._data

    def info(self) -> dict[str, Any]:
        return {
            "max_size": self._max_size,
            "ttl": self._ttl,
            "size": len(self._data),
        }
