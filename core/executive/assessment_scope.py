"""
core.executive.assessment_scope
===============================

Assessment scope metadata for ExecutiveAssessment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["AssessmentScope"]


@dataclass(frozen=True)
class AssessmentScope:
    """States what was and was not assessed for executive consumers."""

    modules_run: tuple[str, ...]
    modules_skipped: tuple[str, ...]
    evidence_files: tuple[str, ...]
    assessment_limitations: tuple[str, ...]
    assessment_time: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "modules_run", tuple(self.modules_run))
        object.__setattr__(self, "modules_skipped", tuple(self.modules_skipped))
        object.__setattr__(self, "evidence_files", tuple(self.evidence_files))
        object.__setattr__(
            self,
            "assessment_limitations",
            tuple(self.assessment_limitations),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain data."""
        return {
            "modules_run": list(self.modules_run),
            "modules_skipped": list(self.modules_skipped),
            "evidence_files": list(self.evidence_files),
            "assessment_limitations": list(self.assessment_limitations),
            "assessment_time": self.assessment_time,
        }
