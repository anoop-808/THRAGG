"""
core.reporting.report
=====================
Core Report object and ReportType enum.

Design constraints
------------------
- Report is a plain data container. No rendering or file I/O here.
- All construction lives in report_builder.py.
- All validation lives in report_validator.py.
- Renderers consume ReportModel, never Report directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .report_artifact import ReportArtifact
from .report_metadata import ReportMetadata
from .section import Section


class ReportType(str, Enum):
    EXECUTIVE  = "EXECUTIVE"
    TECHNICAL  = "TECHNICAL"
    MARKDOWN   = "MARKDOWN"
    HTML       = "HTML"
    JSON       = "JSON"
    EVIDENCE   = "EVIDENCE"
    COMPLIANCE = "COMPLIANCE"


@dataclass
class TraceabilityEntry:
    """
    One traceable recommendation → evidence chain.

    recommendation_id : str
        ID of the recommendation being traced.
    risk_assessment_id : str
        RiskAssessment that triggered this recommendation.
    attack_chain_id : str
        AttackChain behind the risk assessment.
    correlation_id : str
        Correlation object behind the attack chain.
    finding_ids : list[str]
        Findings that fed the correlation.
    evidence_files : list[str]
        Original evidence files.
    """
    recommendation_id:  str
    risk_assessment_id: str
    attack_chain_id:    str
    correlation_id:     str
    finding_ids:        list[str] = field(default_factory=list)
    evidence_files:     list[str] = field(default_factory=list)
    chain_depth:        int | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "recommendation_id":  self.recommendation_id,
            "risk_assessment_id": self.risk_assessment_id,
            "attack_chain_id":    self.attack_chain_id,
            "correlation_id":     self.correlation_id,
            "finding_ids":        list(self.finding_ids),
            "evidence_files":     list(self.evidence_files),
        }
        if self.chain_depth is not None:
            data["chain_depth"] = self.chain_depth
        return data


@dataclass
class ReportModel:
    """
    Central reporting contract.

    Every renderer consumes a Report. No renderer accesses
    ExecutiveAssessment directly.

    Fields
    ------
    id              : Stable run-scoped identifier.
    title           : Human-readable report title.
    report_type     : ReportType enum value.
    generated_at    : ISO 8601 timestamp.
    framework_version : THRAGG framework version string.
    sections        : Ordered list of Section objects.
    metadata        : Typed ReportMetadata object.
    traceability_appendix : Full recommendation traceability map.
    artifacts       : List of ReportArtifact objects.
    """
    id:                    str
    title:                 str
    report_type:           ReportType
    generated_at:          str
    framework_version:     str
    sections:              list[Section]       = field(default_factory=list)
    metadata:              ReportMetadata      | None = None
    traceability_appendix: list[TraceabilityEntry] = field(default_factory=list)
    artifacts:             list[ReportArtifact]    = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":                    self.id,
            "title":                 self.title,
            "report_type":           self.report_type.value,
            "generated_at":          self.generated_at,
            "framework_version":     self.framework_version,
            "sections":              [s.to_dict() for s in self.sections],
            "metadata":              self.metadata.to_dict() if self.metadata else {},
            "traceability_appendix": [t.to_dict() for t in self.traceability_appendix],
            "artifacts":             [a.to_dict() for a in self.artifacts],
        }


Report = ReportModel
