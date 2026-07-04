"""
core.observation
================

Milestone 8 executive observation contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .finding import Confidence, Severity

__all__ = ["Observation", "ObservationCategory"]


class ObservationCategory(str, Enum):
    """M8 executive observation categories."""

    EXPOSURE = "EXPOSURE"
    IDENTITY = "IDENTITY"
    NETWORK = "NETWORK"
    PRIVILEGE = "PRIVILEGE"
    EXECUTION = "EXECUTION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_ACCESS = "DATA_ACCESS"
    CONFIGURATION = "CONFIGURATION"
    CLOUD = "CLOUD"


@dataclass(frozen=True)
class Observation:
    """One traceable executive-level observation."""

    id: str
    category: ObservationCategory
    severity: Severity
    confidence: Confidence
    text: str
    supporting_object_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        """Defensively copy caller-owned iterables."""
        object.__setattr__(
            self,
            "supporting_object_ids",
            tuple(self.supporting_object_ids),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize deterministically to plain data."""
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "text": self.text,
            "supporting_object_ids": list(self.supporting_object_ids),
        }
