"""Minimal detect → fuse → decide loop (extracted from sigsentinel Agent orchestrator)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from sentry_ai.agent.decision.engine import DecisionEngine, Level
from sentry_ai.core.signal import Alert, Event
from sentry_ai.detectors.base import Detector
from sentry_ai.detectors.brute_force import BruteForceDetector
from sentry_ai.detectors.ddos import DDoSDetector
from sentry_ai.fusion.evidence import RiskAssessment, RiskFusion


@dataclass
class LevelChange:
    entity: str
    ts: float
    old: Level
    new: Level
    risk: float


@dataclass
class PipelineResult:
    alerts: list[Alert] = field(default_factory=list)
    assessments: dict[str, RiskAssessment] = field(default_factory=dict)
    level_changes: list[LevelChange] = field(default_factory=list)
    events_processed: int = 0

    def peak_levels(self) -> dict[str, Level]:
        peaks: dict[str, Level] = {}
        for change in self.level_changes:
            peaks[change.entity] = max(peaks.get(change.entity, Level.OBSERVE), change.new)
        return peaks


class Pipeline:
    """Sync replay pipeline: detectors, risk fusion, and decision levels."""

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        *,
        flush_interval_s: float = 60.0,
        fusion: RiskFusion | None = None,
        decision: DecisionEngine | None = None,
    ) -> None:
        self.detectors = list(detectors) if detectors is not None else [
            BruteForceDetector(),
            DDoSDetector(),
        ]
        self.flush_interval_s = flush_interval_s
        self.fusion = fusion or RiskFusion()
        self.decision = decision or DecisionEngine()
        self.now = 0.0
        self._next_flush: float | None = None
        self.result = PipelineResult()

    def _corroborating(self, assessment: RiskAssessment) -> int:
        safety_nets = {d.name for d in self.detectors if not d.corroborates}
        return sum(1 for name in assessment.contributions if name not in safety_nets)

    def _detect(self, event: Event) -> tuple[list[Alert], bool]:
        alerts: list[Alert] = []
        for detector in self.detectors:
            if event.kind in detector.kinds:
                alerts.extend(detector.process(event))
        periodic = False
        interval = self.flush_interval_s
        if self._next_flush is None:
            self._next_flush = event.ts + interval
        elif event.ts >= self._next_flush:
            for detector in self.detectors:
                alerts.extend(detector.flush(event.ts))
            self._next_flush = event.ts + interval
            periodic = True
        return alerts, periodic

    def _ingest(self, alerts: list[Alert], now: float, periodic: bool) -> list[Alert]:
        touched: set[str] = set()
        for alert in alerts:
            self.fusion.add(alert)
            self.result.alerts.append(alert)
            touched.add(alert.entity)
        if periodic:
            touched.update(self.decision.active())
        for entity in sorted(touched):
            self._assess(entity, now)
        return alerts

    def _assess(self, entity: str, now: float) -> None:
        assessment = self.fusion.assess(entity, now)
        self.result.assessments[entity] = assessment
        old, new = self.decision.update(
            entity, assessment.risk, detectors=self._corroborating(assessment)
        )
        if old != new:
            self.result.level_changes.append(
                LevelChange(entity=entity, ts=now, old=old, new=new, risk=assessment.risk)
            )

    def process(self, event: Event) -> list[Alert]:
        self.now = max(self.now, event.ts)
        self.result.events_processed += 1
        alerts, periodic = self._detect(event)
        return self._ingest(alerts, self.now, periodic)

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for detector in self.detectors:
            alerts.extend(detector.flush(self.now))
        return self._ingest(alerts, self.now, periodic=True)

    def run(self, events: Iterable[Event]) -> PipelineResult:
        for event in sorted(events, key=lambda e: e.ts):
            self.process(event)
        self.finalize()
        return self.result

    def summary(self) -> dict[str, Any]:
        return {
            "events_processed": self.result.events_processed,
            "alerts": len(self.result.alerts),
            "peak_levels": {e: lvl.name for e, lvl in self.result.peak_levels().items()},
            "level_changes": [
                {
                    "entity": c.entity,
                    "ts": c.ts,
                    "from": c.old.name,
                    "to": c.new.name,
                    "risk": round(c.risk, 4),
                }
                for c in self.result.level_changes
            ],
            "top_alerts": [a.to_dict() for a in self.result.alerts[-10:]],
        }
