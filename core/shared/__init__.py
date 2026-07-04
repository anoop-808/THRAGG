"""Shared package public API."""

from importlib import import_module
from typing import Any

_EXPORTS = {
    "Confidence": ".constants",
    "EntityType": ".constants",
    "PriorityRanker": ".priority_ranker",
    "Severity": ".constants",
    "TraceabilityMap": ".traceability_map",
    "stable_sha_id": ".stable_id",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Load shared symbols lazily to avoid package import cycles."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(_EXPORTS[name], __name__), name)
    globals()[name] = value
    return value
