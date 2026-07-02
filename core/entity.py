"""
core.entity

Shared Entity model for THRAGG.
Mirrors core.finding architecture. Single source of truth.

A Finding is an event. An Entity is a thing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .finding import Confidence, EntityType

__all__ = ["Entity", "stable_entity_id"]


def stable_entity_id(entity_type: EntityType, primary_identifier: str) -> str:
    """
    Deterministic id from entity type + primary identifier.

    Uses the same algorithm as Finding ID generation for consistency:
    SHA-256("<entity_type>|<primary_identifier>")[:16] prefixed with
    the entity type value (lowercased), e.g. "host-3f1a9c2d84b67e01".

    Same (type, identifier) across runs -> same id, independent of
    execution order.
    """
    raw = f"{entity_type.value}|{primary_identifier}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"{entity_type.value.lower()}-{digest}"


@dataclass
class Entity:
    """One extracted security entity."""

    id: str
    type: EntityType
    primary_identifier: str
    source_module: str
    source_finding: str
    confidence: Confidence
    aliases: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "primary_identifier": self.primary_identifier,
            "aliases": list(self.aliases),
            "attributes": dict(self.attributes),
            "source_module": self.source_module,
            "source_finding": self.source_finding,
            "confidence": self.confidence.value,
        }
