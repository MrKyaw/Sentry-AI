"""Evidence fusion: per-entity risk from time-decayed alerts and kill-chain progression."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from sentry_ai.core.signal import KILL_CHAIN, Alert, Tactic


@dataclass(frozen=True)
class RiskAssessment:
    """Fused risk for one entity at one point in time."""

    entity: str
    ts: float
    risk: float
    base_risk: float
    bonus: float
    contributions: dict[str, float]
    tactics: list[Tactic]
    stage: Tactic | None
    next_stages: list[Tactic]
    alerts: list[Alert] = field(default_factory=list)
    related: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "ts": self.ts,
            "risk": round(self.risk, 4),
            "base_risk": round(self.base_risk, 4),
            "kill_chain_bonus": round(self.bonus, 4),
            "contributions": {k: round(v, 4) for k, v in self.contributions.items()},
            "tactics": [t.value for t in self.tactics],
            "stage": self.stage.value if self.stage else None,
            "next_stages": [t.value for t in self.next_stages],
            "related": self.related,
        }


class RiskFusion:
    """Combines alerts per entity into a risk score in [0, 1).

    1. Each alert's score decays with half-life ``half_life_s``.
    2. Per detector, the strongest decayed score is kept (repeats of one signal
       do not inflate risk).
    3. Detectors are combined with noisy-OR: ``1 - prod(1 - c_d)``, treating them
       as independent pieces of evidence.
    4. If the entity shows ``k >= 2`` distinct kill-chain tactics with decayed
       score above ``tactic_floor``, a bonus ``min(max_bonus, bonus * (k - 1))``
       is applied, again via noisy-OR. Progression through the chain is stronger
       evidence than any single stage.
    """

    def __init__(
        self,
        half_life_s: float = 21600.0,
        horizon_s: float = 86400.0,
        kill_chain_bonus: float = 0.15,
        max_bonus: float = 0.5,
        tactic_floor: float = 0.2,
        max_alerts_per_entity: int = 500,
    ) -> None:
        self.half_life_s = half_life_s
        self.horizon_s = horizon_s
        self.kill_chain_bonus = kill_chain_bonus
        self.max_bonus = max_bonus
        self.tactic_floor = tactic_floor
        self.max_alerts_per_entity = max_alerts_per_entity
        self._alerts: dict[str, deque[Alert]] = {}

    def add(self, alert: Alert) -> None:
        self._alerts.setdefault(alert.entity, deque(maxlen=self.max_alerts_per_entity)).append(
            alert
        )

    def entities(self) -> list[str]:
        return list(self._alerts)

    def decay(self, score: float, age_s: float) -> float:
        return score if age_s <= 0 else score * 0.5 ** (age_s / self.half_life_s)

    def assess(self, entity: str, now: float) -> RiskAssessment:
        window = self._alerts.get(entity, deque())
        while window and window[0].ts < now - self.horizon_s:
            window.popleft()
        contributions: dict[str, float] = {}
        tactic_strength: dict[Tactic, float] = {}
        related: dict[str, None] = {}
        for alert in window:
            decayed = self.decay(alert.score, now - alert.ts)
            contributions[alert.detector] = max(contributions.get(alert.detector, 0.0), decayed)
            if alert.tactic.stage >= 0:
                tactic_strength[alert.tactic] = max(tactic_strength.get(alert.tactic, 0.0), decayed)
            for r in alert.related:
                related.setdefault(r, None)
        survival = 1.0
        for c in contributions.values():
            survival *= 1.0 - c
        base = 1.0 - survival
        tactics = sorted(
            (t for t, s in tactic_strength.items() if s >= self.tactic_floor), key=lambda t: t.stage
        )
        bonus = (
            min(self.max_bonus, self.kill_chain_bonus * (len(tactics) - 1))
            if len(tactics) > 1
            else 0.0
        )
        risk = 1.0 - (1.0 - base) * (1.0 - bonus)
        stage = tactics[-1] if tactics else None
        next_stages = list(KILL_CHAIN[stage.stage + 1 : stage.stage + 3]) if stage else []
        return RiskAssessment(
            entity=entity,
            ts=now,
            risk=risk,
            base_risk=base,
            bonus=bonus,
            contributions=contributions,
            tactics=tactics,
            stage=stage,
            next_stages=next_stages,
            alerts=list(window),
            related=list(related)[:20],
        )
