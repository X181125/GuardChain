from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    pass

KT = TypeVar("KT")
VT = TypeVar("VT")


@dataclass(slots=True)
class CacheEntry(Generic[VT]):
    value: VT
    expires_at: float | None


class LRUCache(Generic[KT, VT]):
    __slots__ = ("_data", "_order", "_max_size", "_ttl", "_lock")

    def __init__(
        self,
        max_size: int,
        ttl: float | None = None,
    ) -> None:
        if max_size <= 0:
            msg = "max_size must be positive"
            raise ValueError(msg)
        if ttl is not None and ttl <= 0:
            msg = "ttl must be positive"
            raise ValueError(msg)

        import threading
        from collections import OrderedDict

        self._data: dict[KT, CacheEntry[VT]] = {}
        self._order: OrderedDict[KT, None] = OrderedDict()
        self._max_size: int = max_size
        self._ttl: float | None = ttl
        self._lock = threading.Lock()

    def get(self, key: KT) -> VT | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None

            if entry.expires_at is not None:
                import time
                if time.monotonic() > entry.expires_at:
                    del self._data[key]
                    del self._order[key]
                    return None

            self._order.move_to_end(key)
            return entry.value

    def set(self, key: KT, value: VT) -> None:
        import time

        with self._lock:
            if key in self._data:
                self._order.move_to_end(key)
                self._data[key] = CacheEntry(value, self._get_expires_at(time.monotonic()))
                return

            if len(self._data) >= self._max_size:
                oldest = next(iter(self._order))
                del self._order[oldest]
                del self._data[oldest]

            self._order[key] = None
            self._data[key] = CacheEntry(value, self._get_expires_at(time.monotonic()))

    def _get_expires_at(self, now: float) -> float | None:
        if self._ttl is None:
            return None
        return now + self._ttl

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self._order.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def __contains__(self, key: KT) -> bool:
        with self._lock:
            return key in self._data

    def info(self) -> dict[str, Any]:
        with self._lock:
            return {
                "max_size": self._max_size,
                "ttl": self._ttl,
                "size": len(self._data),
            }
