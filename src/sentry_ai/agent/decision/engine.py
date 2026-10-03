"""Risk-to-level decisions with hysteresis."""

from __future__ import annotations

from enum import IntEnum


class Level(IntEnum):
    OBSERVE = 0
    ALERT = 1
    RECOMMEND = 2
    CONTAIN = 3


class DecisionEngine:
    """Maps entity risk to response levels without flapping.

    Escalation is immediate once risk reaches a level's threshold. De-escalation
    happens only after risk falls ``hysteresis`` below the current level's
    threshold, so a score oscillating around a boundary does not toggle alerts.
    CONTAIN additionally requires ``contain_min_detectors`` independent detectors;
    a single signal, however strong, is capped at RECOMMEND.
    """

    def __init__(
        self,
        alert: float = 0.4,
        recommend: float = 0.7,
        contain: float = 0.9,
        hysteresis: float = 0.1,
        contain_min_detectors: int = 2,
    ) -> None:
        if not 0 < alert < recommend < contain <= 1:
            raise ValueError("thresholds must satisfy 0 < alert < recommend < contain <= 1")
        self.thresholds = {Level.ALERT: alert, Level.RECOMMEND: recommend, Level.CONTAIN: contain}
        self.hysteresis = hysteresis
        self.contain_min_detectors = contain_min_detectors
        self._levels: dict[str, Level] = {}

    def level_for(self, risk: float) -> Level:
        level = Level.OBSERVE
        for candidate, threshold in self.thresholds.items():
            if risk >= threshold:
                level = candidate
        return level

    def level(self, entity: str) -> Level:
        return self._levels.get(entity, Level.OBSERVE)

    def active(self) -> list[str]:
        return [e for e, lvl in self._levels.items() if lvl > Level.OBSERVE]

    def update(self, entity: str, risk: float, detectors: int | None = None) -> tuple[Level, Level]:
        """Apply a new risk value; returns (previous level, new level).

        ``detectors`` is the number of distinct detectors behind ``risk``; when
        omitted the CONTAIN corroboration requirement is considered met.
        """
        current = self.level(entity)
        target = self.level_for(risk)
        if (
            target == Level.CONTAIN
            and detectors is not None
            and detectors < self.contain_min_detectors
        ):
            target = Level.RECOMMEND
        new = current
        if target > current:
            new = target
        else:
            while new > Level.OBSERVE and risk < self.thresholds[new] - self.hysteresis:
                new = Level(new - 1)
        if new == Level.OBSERVE:
            self._levels.pop(entity, None)
        else:
            self._levels[entity] = new
        return current, new
