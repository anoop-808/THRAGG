"""
core.chain_edge
===============

First-class edge explaining why two correlations belong together.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["AFFINITY_WEIGHTS", "ChainEdge", "affinity_score"]


AFFINITY_WEIGHTS = {
    "USER": 2,
    "HOST": 2,
    "IDENTITY": 3,
    "DATABASE": 3,
    "SERVICE": 1,
    "IP_ADDRESS": 1,
    "PORT": 1,
    "NETWORK": 1,
    "APPLICATION": 1,
    "CONTAINER": 1,
    "CLOUD_RESOURCE": 1,
    "STORAGE": 2,
    "PROCESS": 1,
    "FILE": 1,
    "REGISTRY_KEY": 1,
    "DOMAIN": 1,
    "CERTIFICATE": 1,
    "UNKNOWN": 1,
}


@dataclass(frozen=True)
class ChainEdge:
    """Connection between two correlations through one shared entity."""

    from_correlation_id: str
    to_correlation_id: str
    shared_entity_id: str
    shared_entity_type: str
    affinity_score: int
    reason: str

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary."""
        return {
            "from_correlation_id": self.from_correlation_id,
            "to_correlation_id": self.to_correlation_id,
            "shared_entity_id": self.shared_entity_id,
            "shared_entity_type": self.shared_entity_type,
            "affinity_score": self.affinity_score,
            "reason": self.reason,
        }


def affinity_score(entity_type: str) -> int:
    """Return deterministic affinity score for a shared entity type."""
    return AFFINITY_WEIGHTS[entity_type]
