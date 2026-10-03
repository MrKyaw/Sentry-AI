"""Denial-of-service detection via per-destination flow rates against a seasonal baseline."""

from __future__ import annotations

import math
from collections.abc import Iterable

from sentry_ai.conditioning.windowing import window_index
from sentry_ai.core.registry import register
from sentry_ai.core.signal import Alert, Event, EventKind, Tactic
from sentry_ai.detectors.base import Cooldown, Detector, ratio_score
from sentry_ai.detectors.failed_states import FAILED_STATES
from sentry_ai.features.baseline import HourOfWeekBaseline


class _Window:
    __slots__ = ("idx", "flows", "failed", "sources")

    def __init__(self, idx: int) -> None:
        self.idx = idx
        self.flows = 0
        self.failed = 0
        self.sources: dict[str, int] = {}


@register
class DDoSDetector(Detector):
    """Flags destinations whose connection rate jumps far above their own baseline.

    Connections per destination are counted in tumbling ``window_s`` windows and
    ``log1p(count)`` is compared with the destination's hour-of-week baseline.
    A window alarms when it has at least ``min_flows`` connections and either
    ``z >= z_threshold`` against a learned baseline, or, for destinations with
    fewer than ``min_windows`` baseline windows, at least ``unseen_min_flows``
    connections. A high half-open/refused share (SYN flood) raises the score.
    The check runs as the count grows, so a flood is reported within its first
    window. Sources with at least ``source_share`` of the window's connections
    are blamed; if none dominates (a widely distributed flood) the alert is
    raised on the destination itself. Alarming windows never enter a learned
    baseline, but until a destination has ``min_windows`` windows every window
    is learned, so a busy server first seen live (a DNS resolver, a proxy) stops
    alarming once its baseline exists instead of re-alarming after every
    cooldown. Only destinations with ``track_min_flows`` connections in a window
    are baselined, which bounds memory and biases the baseline upwards.
    """

    name = "ddos"
    tactic = Tactic.IMPACT
    technique = "T1498"
    kinds = frozenset({EventKind.CONN})

    def __init__(
        self,
        window_s: float = 60.0,
        min_flows: int = 200,
        unseen_min_flows: int = 1000,
        z_threshold: float = 6.0,
        min_windows: int = 12,
        track_min_flows: int = 10,
        sigma_floor: float = 0.5,
        learn_max_z: float = 3.0,
        source_share: float = 0.05,
        min_source_flows: int = 20,
        max_sources: int = 20,
        max_tracked_sources: int = 512,
        half_open_share: float = 0.5,
        cooldown_s: float = 1800.0,
        failed_states: Iterable[str] = FAILED_STATES,
    ) -> None:
        self.window_s = window_s
        self.min_flows = min_flows
        self.unseen_min_flows = unseen_min_flows
        self.z_threshold = z_threshold
        self.min_windows = min_windows
        self.track_min_flows = track_min_flows
        self.sigma_floor = sigma_floor
        self.learn_max_z = learn_max_z
        self.source_share = source_share
        self.min_source_flows = min_source_flows
        self.max_sources = max_sources
        self.max_tracked_sources = max_tracked_sources
        self.half_open_share = half_open_share
        self.failed_states = frozenset(failed_states)
        self.baseline = HourOfWeekBaseline(min_slot_samples=6)
        self._windows: dict[str, _Window] = {}
        self._alarmed: set[str] = set()
        self._next_check: dict[str, int] = {}
        self._cooldown = Cooldown(cooldown_s)

    def process(self, event: Event) -> list[Alert]:
        if not event.dst:
            return []
        idx = window_index(event.ts, self.window_s)
        win = self._windows.get(event.dst)
        if win is None or win.idx != idx:
            if win is not None:
                self._close(event.dst, win)
            win = self._windows[event.dst] = _Window(idx)
        win.flows += 1
        if event.state in self.failed_states:
            win.failed += 1
        sources = win.sources
        if event.src in sources or len(sources) < self.max_tracked_sources:
            sources[event.src] = sources.get(event.src, 0) + 1
        if win.flows < self._next_check.get(event.dst, self.min_flows):
            return []
        self._next_check[event.dst] = win.flows + max(1, win.flows // 4)
        return self._check(event.dst, win, event.ts)

    def flush(self, now: float) -> list[Alert]:
        idx = window_index(now, self.window_s)
        for dst in [d for d, w in self._windows.items() if w.idx < idx]:
            self._close(dst, self._windows.pop(dst))
        return []

    def _close(self, dst: str, win: _Window) -> None:
        self._next_check.pop(dst, None)
        alarmed = dst in self._alarmed
        self._alarmed.discard(dst)
        if win.flows < self.track_min_flows:
            return
        ts = (win.idx + 1) * self.window_s
        y = math.log1p(win.flows)
        if self.baseline.count(dst) >= self.min_windows:
            if alarmed:
                return
            if self.baseline.zscore(dst, ts, y, sigma_floor=self.sigma_floor) > self.learn_max_z:
                return
        self.baseline.update(dst, ts, y)

    def _check(self, dst: str, win: _Window, ts: float) -> list[Alert]:
        y = math.log1p(win.flows)
        known = self.baseline.count(dst) >= self.min_windows
        if known:
            z = self.baseline.zscore(dst, ts, y, sigma_floor=self.sigma_floor)
            ratio = z / self.z_threshold
        else:
            z = float("nan")
            ratio = win.flows / self.unseen_min_flows
        if ratio < 1:
            return []
        self._alarmed.add(dst)
        if not self._cooldown.ready(dst, ts):
            return []
        self._cooldown.mark(dst, ts)
        half_open = win.failed / win.flows
        score = ratio_score(ratio, base=0.6)
        if half_open >= self.half_open_share:
            score = min(0.95, score + 0.1)
        technique = "T1498.001" if half_open >= self.half_open_share else "T1498"
        ranked = sorted(win.sources.items(), key=lambda kv: kv[1], reverse=True)
        blamed = [
            src
            for src, n in ranked[: self.max_sources]
            if n >= self.min_source_flows and n >= self.source_share * win.flows
        ]
        mean, _, _ = self.baseline.expected(dst, ts)
        evidence = {
            "target": dst,
            "flows": win.flows,
            "window_s": self.window_s,
            "baseline_flows": round(math.expm1(mean), 1) if known else None,
            "z": None if math.isnan(z) else round(z, 2),
            "half_open_share": round(half_open, 3),
            "sources": len(win.sources),
            "top_sources": dict(ranked[:5]),
        }
        rate = f"{win.flows} connections to {dst} in {self.window_s / 60:.0f} min"
        base = f" (baseline ~{math.expm1(mean):.0f})" if known else " (no baseline)"
        if not blamed:
            return [
                self._alert(
                    ts,
                    dst,
                    score,
                    f"Distributed flood: {rate}{base} from {len(win.sources)} sources",
                    related=tuple(src for src, _ in ranked[:10]),
                    evidence=evidence,
                    technique=technique,
                )
            ]
        return [
            self._alert(
                ts,
                src,
                score,
                f"Flood source: {win.sources[src]} of {rate}{base}",
                related=(dst,),
                evidence=evidence,
                technique=technique,
            )
            for src in blamed
        ]
