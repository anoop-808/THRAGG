"""
core.reporting.report_builder
==============================
ReportBuilder assembles a Report from an ExecutiveAssessment dict.

Design constraints
------------------
- Consumes ExecutiveAssessment as a plain dict (no upstream class import).
- Delegates structure to TemplateRegistry.
- Delegates content to SectionBuilder.
- Never calculates risk, severity, confidence, or recommendations.
- Single construction path for all Report objects.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from ..shared.version import (
    BUILD_VERSION,
    FRAMEWORK_VERSION,
    PIPELINE_VERSION,
    REPORT_VERSION,
)
from .report import ReportModel, ReportType, TraceabilityEntry
from .report_artifact import ReportArtifact, ArtifactType
from .report_metadata import ReportMetadata
from .section_builder import SectionBuilder
from .template_registry import TemplateRegistry


def _stable_report_id(execution_id: str, report_type: ReportType) -> str:
    raw = f"{execution_id}|{report_type.value}"
    return "rpt-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


class ReportBuilder:
    """
    Assembles a Report for a given ReportType.

    Usage
    -----
    builder = ReportBuilder(assessment_dict, execution_id="run-001")
    report  = builder.build(ReportType.EXECUTIVE)
    """

    def __init__(
        self,
        assessment: dict[str, Any] | Any,
        execution_id: str = "unknown",
        generated_at: str | None = None,
    ) -> None:
        self._assessment  = assessment.to_dict() if hasattr(assessment, "to_dict") else dict(assessment)
        self._execution_id = execution_id
        self._registry    = TemplateRegistry()
        self._now         = generated_at or datetime.now(timezone.utc).isoformat()

    def build(self, report_type: ReportType) -> ReportModel:
        """Build and return a fully populated Report."""
        templates    = self._registry.get(report_type)
        sec_builder  = SectionBuilder(self._assessment)
        sections     = [sec_builder.build(t) for t in templates]

        metadata = ReportMetadata(
            framework_version = FRAMEWORK_VERSION,
            report_version    = REPORT_VERSION,
            assessment_time   = self._assessment.get("generated_at", self._assessment.get("metadata", {}).get("assessment_time", self._now)),
            generated_time    = self._now,
            modules_used      = self._assessment.get("metadata", {}).get("modules_used", []),
            execution_id      = self._execution_id,
            pipeline_version  = PIPELINE_VERSION,
            framework_commit  = self._assessment.get("metadata", {}).get("framework_commit", ""),
            build_version     = self._assessment.get("metadata", {}).get("build_version", BUILD_VERSION),
            generator         = "ReportBuilder",
            assessment_scope  = self._assessment.get("scope", {}).get("description", ""),
            limitations       = self._assessment.get("scope", {}).get("assessment_limitations", []),
        )

        traceability = self._build_traceability()
        artifacts    = self._build_artifacts()

        posture = self._posture_label()
        title   = f"THRAGG {report_type.value.title()} Report - Posture: {posture}"

        return ReportModel(
            id                    = _stable_report_id(self._execution_id, report_type),
            title                 = title,
            report_type           = report_type,
            generated_at          = self._now,
            framework_version     = FRAMEWORK_VERSION,
            sections              = sections,
            metadata              = metadata,
            traceability_appendix = traceability,
            artifacts             = artifacts,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_traceability(self) -> list[TraceabilityEntry]:
        entries = []
        raw_traceability = self._assessment.get("traceability", [])
        if isinstance(raw_traceability, dict):
            raw_traceability = [
                {"recommendation_id": key, "finding_ids": list(items)}
                for key, items in raw_traceability.get("recommendation_to_observations", [])
            ]
        for item in raw_traceability:
            entries.append(TraceabilityEntry(
                recommendation_id  = item.get("recommendation_id", "—"),
                risk_assessment_id = item.get("risk_assessment_id", "—"),
                attack_chain_id    = item.get("attack_chain_id", "—"),
                correlation_id     = item.get("correlation_id", "—"),
                finding_ids        = item.get("finding_ids", []),
                evidence_files     = item.get("evidence_files", []),
                chain_depth        = item.get("chain_depth"),
            ))
        existing = {entry.recommendation_id for entry in entries}
        for item in self._assessment.get("executive_recommendations", []):
            rec_id = item.get("id") if isinstance(item, dict) else str(item)
            if rec_id and rec_id not in existing:
                entries.append(TraceabilityEntry(rec_id, "—", "—", "—"))
        return entries

    def _build_artifacts(self) -> list[ReportArtifact]:
        artifacts = []
        for i, ev in enumerate(
            self._assessment.get("scope", {}).get("evidence_files", [])
        ):
            artifacts.append(ReportArtifact(
                artifact_id   = f"art-{i+1:03d}",
                artifact_type = ArtifactType.EVIDENCE_FILE,
                display_name  = ev,
                path          = ev,
                mime_type     = "application/octet-stream",
            ))
        return artifacts

    def _posture_label(self) -> str:
        posture = self._assessment.get("security_posture", "UNKNOWN")
        if isinstance(posture, dict):
            return str(posture.get("posture", "UNKNOWN"))
        return str(posture)
