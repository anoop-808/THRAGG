"""
core.resolved_entity

Shared ResolvedEntity model for THRAGG identity resolution.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .finding import EntityType

__all__ = [
    "ResolutionConfidence",
    "ResolutionMethod",
    "ResolutionRecord",
    "ResolvedEntity",
    "stable_resolved_entity_id",
]


class ResolutionMethod(str, Enum):
    """Deterministic method used to resolve entity identity."""

    EXACT_IDENTIFIER = "EXACT_IDENTIFIER"
    EXACT_ALIAS = "EXACT_ALIAS"
    EXACT_IP = "EXACT_IP"
    EXACT_HOSTNAME = "EXACT_HOSTNAME"
    UNKNOWN = "UNKNOWN"


class ResolutionConfidence(str, Enum):
    """Confidence that multiple Entities represent the same identity."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


def stable_resolved_entity_id(
    entity_type: EntityType, primary_identifier: str
) -> str:
    """Return a deterministic resolved identity id."""
    raw = f"{entity_type.value}|{primary_identifier}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"resolved-{entity_type.value.lower()}-{digest}"


@dataclass
class ResolutionRecord:
    """Audit record explaining one deterministic merge decision."""

    resolution_method: ResolutionMethod
    resolution_reason: str
    resolution_confidence: ResolutionConfidence
    timestamp: str
    resolver_version: str
    supporting_entities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolution_method": self.resolution_method.value,
            "resolution_reason": self.resolution_reason,
            "resolution_confidence": self.resolution_confidence.value,
            "timestamp": self.timestamp,
            "resolver_version": self.resolver_version,
            "supporting_entities": list(self.supporting_entities),
        }


@dataclass
class ResolvedEntity:
    """Canonical identity created from one or more immutable Entity objects."""

    id: str
    entity_type: EntityType
    primary_identifier: str
    aliases: list[str] = field(default_factory=list)
    source_entities: list[str] = field(default_factory=list)
    source_findings: list[str] = field(default_factory=list)
    source_modules: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    resolution_records: list[ResolutionRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity_type": self.entity_type.value,
            "primary_identifier": self.primary_identifier,
            "aliases": list(self.aliases),
            "source_entities": list(self.source_entities),
            "source_findings": list(self.source_findings),
            "source_modules": list(self.source_modules),
            "attributes": dict(self.attributes),
            "resolution_records": [
                record.to_dict() for record in self.resolution_records
            ],
        }
