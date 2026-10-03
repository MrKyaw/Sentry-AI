"""Plugin registry for detectors (subset from sigsentinel)."""

from __future__ import annotations

from typing import TypeVar

if False:  # TYPE_CHECKING
    from sentry_ai.detectors.base import Detector

D = TypeVar("D", bound="type[Detector]")

_REGISTRY: dict[str, type[Detector]] = {}


def register(cls: D) -> D:
    existing = _REGISTRY.get(cls.name)
    if existing is not None and existing is not cls:
        raise ValueError(f"Detector name {cls.name!r} is already registered")
    _REGISTRY[cls.name] = cls
    return cls
