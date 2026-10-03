"""Detector interface shared by all detectors."""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections.abc import Hashable, Iterable
from typing import Any, ClassVar

from sentry_ai.core.signal import Alert, Event, EventKind, Tactic


def ratio_score(ratio: float, base: float = 0.6, cap: float = 0.95) -> float:
    """Map how far a statistic exceeds its threshold (ratio >= 1) to a score in [base, cap]."""
    if ratio <= 0:
        return 0.0
    return float(min(cap, max(0.0, base + 0.12 * math.log2(max(ratio, 1.0)))))


class Cooldown:
    """Suppresses repeated alerts for the same key within ``seconds``."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self._last: dict[Hashable, float] = {}

    def ready(self, key: Hashable, ts: float) -> bool:
        last = self._last.get(key)
        return last is None or ts - last >= self.seconds

    def mark(self, key: Hashable, ts: float) -> None:
        self._last[key] = ts


class Detector(ABC):
    """Base class for streaming detectors.

    ``fit`` learns baselines from historical events, ``process`` handles one
    live event, and ``flush`` runs time-driven checks such as closing windows.
    Both return alerts whose ``score`` is in [0, 1].
    """

    name: ClassVar[str] = "detector"
    tactic: ClassVar[Tactic] = Tactic.UNKNOWN
    technique: ClassVar[str] = ""
    kinds: ClassVar[frozenset[EventKind]] = frozenset()
    # False for safety nets: they add risk but never count toward the independent
    # detectors that CONTAIN and automatic actions require.
    corroborates: ClassVar[bool] = True

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._upgrade()

    def _upgrade(self) -> None:
        """Give attributes added since a state snapshot was written their defaults."""
        return

    def fit(self, history: Iterable[Event]) -> Detector:
        """Warm up on historical events; alerts raised during warm-up are discarded."""
        last_ts: float | None = None
        for event in history:
            if event.kind in self.kinds:
                self.process(event)
            last_ts = event.ts
        if last_ts is not None:
            self.flush(last_ts)
        return self

    @abstractmethod
    def process(self, event: Event) -> list[Alert]:
        """Update state with one event and return any alerts."""
        raise NotImplementedError

    def flush(self, now: float) -> list[Alert]:
        """Run time-driven checks up to ``now``."""
        return []

    def _alert(
        self,
        ts: float,
        entity: str,
        score: float,
        summary: str,
        *,
        related: Iterable[str] = (),
        evidence: dict[str, Any] | None = None,
        tactic: Tactic | None = None,
        technique: str | None = None,
    ) -> Alert:
        return Alert(
            ts=ts,
            detector=self.name,
            entity=entity,
            score=float(min(1.0, max(0.0, score))),
            tactic=tactic or self.tactic,
            technique=self.technique if technique is None else technique,
            summary=summary,
            related=tuple(related),
            evidence=evidence or {},
        )
