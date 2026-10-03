"""Online smoothing and robust statistics (EWMA, Welford, MAD, robust z-score)."""

from __future__ import annotations

import math

import numpy as np
from numpy.typing import ArrayLike

MAD_TO_SIGMA = 1.4826  # Scales MAD to the standard deviation for Gaussian data.


class EWMA:
    """Exponentially weighted moving mean and variance with O(1) updates."""

    def __init__(self, alpha: float = 0.1) -> None:
        if not 0 < alpha <= 1:
            raise ValueError("alpha must be in (0, 1]")
        self.alpha = alpha
        self.mean = 0.0
        self.var = 0.0
        self.n = 0

    def update(self, x: float) -> float:
        if self.n == 0:
            self.mean = x
        else:
            diff = x - self.mean
            incr = self.alpha * diff
            self.mean += incr
            self.var = (1 - self.alpha) * (self.var + diff * incr)
        self.n += 1
        return self.mean

    @property
    def std(self) -> float:
        return math.sqrt(self.var)


class Welford:
    """Numerically stable running mean and variance."""

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self._m2 = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self._m2 += delta * (x - self.mean)

    @property
    def variance(self) -> float:
        return self._m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


def mad(values: ArrayLike) -> float:
    """Median absolute deviation (unscaled)."""
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        return 0.0
    return float(np.median(np.abs(arr - np.median(arr))))


def robust_zscore(x: float, values: ArrayLike, sigma_floor: float = 1e-9) -> float:
    """z-score of ``x`` against ``values`` using the median and scaled MAD."""
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        return 0.0
    sigma = max(MAD_TO_SIGMA * mad(arr), sigma_floor)
    return float((x - np.median(arr)) / sigma)


def robust_threshold(values: ArrayLike, k: float, floor: float) -> float:
    """``median + k * sigma`` (sigma from MAD), never below ``floor``."""
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        return floor
    return float(max(floor, np.median(arr) + k * MAD_TO_SIGMA * mad(arr)))
