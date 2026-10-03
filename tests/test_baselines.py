import numpy as np
import pytest

from sentry_ai.conditioning.filters import EWMA, Welford, mad, robust_threshold, robust_zscore
from sentry_ai.conditioning.windowing import SlidingWindow, TumblingSum
from sentry_ai.features.baseline import HourOfWeekBaseline


def test_welford_matches_numpy() -> None:
    data = np.random.default_rng(0).normal(5, 2, 1000)
    w = Welford()
    for x in data:
        w.update(float(x))
    assert w.mean == pytest.approx(data.mean())
    assert w.std == pytest.approx(data.std(ddof=1))


def test_ewma_tracks_level_shift() -> None:
    e = EWMA(alpha=0.2)
    for _ in range(50):
        e.update(1.0)
    assert e.mean == pytest.approx(1.0) and e.std == pytest.approx(0.0)
    for _ in range(50):
        e.update(10.0)
    assert e.mean == pytest.approx(10.0, rel=1e-3)


def test_robust_statistics_ignore_outliers() -> None:
    values = [10.0] * 20 + [11.0] * 20 + [1000.0]
    assert mad(values) == pytest.approx(1.0)
    assert robust_zscore(1000.0, values) > 100
    assert robust_threshold([0.0, 0.0], k=5, floor=10) == 10


def test_windows() -> None:
    tw: TumblingSum[str] = TumblingSum(60)
    assert tw.add("h", 0, 5) == []
    assert tw.add("h", 30, 5) == []
    assert tw.add("h", 61, 1) == [("h", 0.0, 10.0)]
    assert tw.flush(200) == [("h", 60.0, 1.0)]
    sw = SlidingWindow(10)
    for t in range(20):
        sw.add(float(t))
    assert len(sw) == 11


def test_hour_of_week_baseline_uses_slot_then_fallback() -> None:
    b = HourOfWeekBaseline(min_slot_samples=3)
    for day in range(4):
        b.update("h", day * 7 * 86400 + 10, 100.0)  # same slot every week
        b.update("h", day * 7 * 86400 + 7200, 10.0)
    mean, _, n = b.expected("h", 10)
    assert mean == 100.0 and n == 4
    mean, _, n = b.expected("h", 3 * 3600)  # empty slot -> entity-wide fallback
    assert mean == pytest.approx(55.0) and n == 8





