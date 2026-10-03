"""Tumbling and sliding windows."""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Hashable, Iterator
from typing import Generic, TypeVar

K = TypeVar("K", bound=Hashable)


def window_index(ts: float, size: float) -> int:
    return int(math.floor(ts / size))


class TumblingSum(Generic[K]):
    """Per-key sums over fixed, non-overlapping windows.

    ``add`` and ``flush`` return closed windows as ``(key, window_start, total)``.
    """

    def __init__(self, size_s: float) -> None:
        self.size_s = size_s
        self._current: dict[K, tuple[int, float]] = {}

    def add(self, key: K, ts: float, value: float) -> list[tuple[K, float, float]]:
        idx = window_index(ts, self.size_s)
        closed: list[tuple[K, float, float]] = []
        current = self._current.get(key)
        if current is None or idx > current[0]:
            if current is not None:
                closed.append((key, current[0] * self.size_s, current[1]))
            self._current[key] = (idx, value)
        else:
            self._current[key] = (current[0], current[1] + value)
        return closed

    def flush(self, now: float) -> list[tuple[K, float, float]]:
        idx = window_index(now, self.size_s)
        closed = [(k, w * self.size_s, total) for k, (w, total) in self._current.items() if w < idx]
        for key, _, _ in closed:
            del self._current[key]
        return closed


class SlidingWindow:
    """Timestamped values kept for ``horizon_s`` seconds."""

    def __init__(self, horizon_s: float) -> None:
        self.horizon_s = horizon_s
        self._items: deque[tuple[float, object]] = deque()

    def add(self, ts: float, value: object = None) -> None:
        self._items.append((ts, value))
        self.prune(ts)

    def prune(self, now: float) -> None:
        cutoff = now - self.horizon_s
        while self._items and self._items[0][0] < cutoff:
            self._items.popleft()

    def __len__(self) -> int:
        return len(self._items)

    def values(self) -> Iterator[object]:
        return (v for _, v in self._items)

    def timestamps(self) -> Iterator[float]:
        return (t for t, _ in self._items)
