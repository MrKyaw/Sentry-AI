"""Per-entity historical baselines with hour-of-week seasonality."""

from __future__ import annotations

from sentry_ai.conditioning.filters import EWMA, Welford


class HourOfWeekBaseline:
    """Running mean/std per (entity, hour-of-week slot) with an entity-level fallback.

    Slots are UTC hours since the epoch modulo 168. A slot is used once it has
    ``min_slot_samples`` observations. Until then the entity-level statistics are
    used: all-time mean/std by default, or an EWMA with ``fallback_alpha`` so the
    fallback follows daily cycles that the slots have not yet learned (useful
    when less than a week of history is available).
    """

    SLOTS = 168

    def __init__(
        self,
        min_slot_samples: int = 6,
        sigma_floor: float = 1e-6,
        fallback_alpha: float | None = None,
    ) -> None:
        self.min_slot_samples = min_slot_samples
        self.sigma_floor = sigma_floor
        self.fallback_alpha = fallback_alpha
        self._slots: dict[tuple[str, int], Welford] = {}
        self._entity: dict[str, Welford] = {}
        self._ewma: dict[str, EWMA] = {}

    @classmethod
    def slot(cls, ts: float) -> int:
        return int(ts // 3600) % cls.SLOTS

    def update(self, entity: str, ts: float, value: float) -> None:
        self._slots.setdefault((entity, self.slot(ts)), Welford()).update(value)
        self._entity.setdefault(entity, Welford()).update(value)
        if self.fallback_alpha is not None:
            self._ewma.setdefault(entity, EWMA(self.fallback_alpha)).update(value)

    def count(self, entity: str) -> int:
        stats = self._entity.get(entity)
        return stats.n if stats else 0

    def expected(self, entity: str, ts: float) -> tuple[float, float, int]:
        """Return (mean, std, n) for the entity at time ``ts``."""
        slot = self._slots.get((entity, self.slot(ts)))
        if slot is not None and slot.n >= self.min_slot_samples:
            return slot.mean, max(slot.std, self.sigma_floor), slot.n
        overall = self._entity.get(entity)
        if overall is None:
            return 0.0, self.sigma_floor, 0
        ewma = self._ewma.get(entity)
        if ewma is not None:
            std = max(ewma.std, overall.std * 0.5, self.sigma_floor)
            return ewma.mean, std, overall.n
        return overall.mean, max(overall.std, self.sigma_floor), overall.n

    def zscore(
        self, entity: str, ts: float, value: float, sigma_floor: float | None = None
    ) -> float:
        mean, std, _ = self.expected(entity, ts)
        floor = self.sigma_floor if sigma_floor is None else sigma_floor
        return (value - mean) / max(std, floor)
