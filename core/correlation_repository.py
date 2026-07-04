"""
core.correlation_repository
===========================

In-memory repository for generated correlations.
"""

from __future__ import annotations

import hashlib

from .correlation import Correlation

__all__ = ["CorrelationRepository", "correlation_duplicate_key"]


def correlation_duplicate_key(correlation: Correlation) -> str:
    """Return duplicate key: rule id + sorted matched entity ids."""
    entity_ids = sorted(
        str(entity["id"])
        for entity in correlation.matched_entities
        if "id" in entity
    )
    raw = f"{correlation.rule_id}|{'|'.join(entity_ids)}"
    return hashlib.sha256(raw.encode()).hexdigest()


class CorrelationRepository:
    """Store generated correlations and skip duplicates."""

    def __init__(self) -> None:
        self._correlations: dict[str, Correlation] = {}
        self._duplicate_keys: set[str] = set()

    def add(self, correlation: Correlation) -> bool:
        """Store a correlation, returning False when duplicate."""
        key = correlation_duplicate_key(correlation)
        if key in self._duplicate_keys:
            return False
        self._duplicate_keys.add(key)
        self._correlations[correlation.id] = correlation
        return True

    def list(self) -> tuple[Correlation, ...]:
        """Return correlations in deterministic id order."""
        return tuple(self._correlations[item_id] for item_id in sorted(self._correlations))

    def __len__(self) -> int:
        return len(self._correlations)
