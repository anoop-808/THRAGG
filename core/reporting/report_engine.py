"""
core.reporting.report_engine
=============================
Orchestrates ReportBuilder → ReportValidator → ReportRepository.

Design constraints
------------------
- One public method: generate().
- Never renders or exports. Delegates to renderers/exporters.
- Returns validated Report or raises on validation failure.
"""

from __future__ import annotations

import logging
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence_package import (
    EvidencePackage,
    EvidencePackageManifest,
    stable_evidence_package_id,
)
from .evidence_package_schema import EvidencePackageSchema
from .report import ReportModel, ReportType
from .report_builder import ReportBuilder
from .report_validator import ReportValidator, ReportValidationError
from .report_repository import ReportRepository
from .renderers.html_renderer import HTMLRenderer
from .renderers.json_renderer import JSONRenderer
from .renderers.markdown_renderer import MarkdownRenderer

logger = logging.getLogger(__name__)


class ReportEngine:
    """
    Orchestrates the full Report generation pipeline.

    Usage
    -----
    engine = ReportEngine()
    report = engine.generate(assessment_dict, ReportType.EXECUTIVE, "run-001")
    """

    def __init__(
        self,
        renderers: tuple[Any, ...] | None = None,
        engine_version: str = "report-engine",
        thragg_version: str | None = None,
    ) -> None:
        self._validator  = ReportValidator()
        self._repository = ReportRepository()
        self.renderers = renderers or (MarkdownRenderer(), JSONRenderer(), HTMLRenderer())
        self.engine_version = engine_version
        self.thragg_version = thragg_version

    def generate(
        self,
        assessment: dict[str, Any] | Any,
        report_type: ReportType = ReportType.EXECUTIVE,
        execution_id: str = "unknown",
        strict: bool = True,
        generated_at: str | None = None,
    ) -> ReportModel:
        """
        Build, validate, and store a Report.

        Parameters
        ----------
        assessment   : ExecutiveAssessment serialized as dict.
        report_type  : Target ReportType.
        execution_id : Run identifier from the orchestrator.
        strict       : If True, raise on validation errors. If False, log and continue.

        Returns
        -------
        Report
        """
        logger.info("Generating %s report (execution_id=%s)", report_type.value, execution_id)

        builder = ReportBuilder(
            assessment,
            execution_id=execution_id,
            generated_at=generated_at,
        )
        report  = builder.build(report_type)

        result = self._validator.validate(report)
        if not result.valid:
            for err in result.errors:
                logger.error("Validation failure: %s", err)
            if strict:
                raise ReportValidationError(
                    result.errors[0].rule,
                    f"{len(result.errors)} validation error(s). First: {result.errors[0].message}",
                )

        self._repository.add(report)
        logger.info("Report %s stored successfully.", report.id)
        return report

    def repository(self) -> ReportRepository:
        return self._repository

    def publish(
        self,
        executive_assessment: Any,
        framework_snapshot: Any,
        output_directory: str,
        generated_at: str | None = None,
    ) -> EvidencePackage:
        """Compatibility publisher: build ReportModel, render, export package."""
        generated_at = generated_at or datetime.now(timezone.utc).isoformat()
        output_path = Path(output_directory)
        output_path.mkdir(parents=True, exist_ok=True)

        report = self.generate(
            executive_assessment,
            ReportType.EXECUTIVE,
            getattr(executive_assessment, "id", "unknown"),
            generated_at=generated_at,
        )
        rendered = tuple(
            (renderer.format, _render(renderer, report, executive_assessment, framework_snapshot))
            for renderer in self.renderers
        )
        files_written = tuple(
            f"report.{_extension(format_name)}" for format_name, _ in rendered
        ) + ("manifest.json",)
        thragg_version = self.thragg_version or report.framework_version

        manifest = EvidencePackageManifest(
            package_id=f"evidence-{getattr(executive_assessment, 'id', report.id)}",
            generated_at=generated_at,
            engine_version=self.engine_version,
            thragg_version=thragg_version,
            files=files_written,
            snapshot_summary=(
                ("findings", str(framework_snapshot.finding_count)),
                ("entities", str(framework_snapshot.entity_count)),
                ("resolved_entities", str(framework_snapshot.resolved_entity_count)),
                ("relationships", str(framework_snapshot.relationship_count)),
            ),
        )
        EvidencePackageSchema.validate_manifest(manifest)

        for format_name, text in rendered:
            (output_path / f"report.{_extension(format_name)}").write_text(
                text,
                encoding="utf-8",
            )
        (output_path / "manifest.json").write_text(
            json.dumps(manifest.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

        package = EvidencePackage(
            id=stable_evidence_package_id(
                manifest.package_id,
                str(output_path),
                files_written,
                generated_at,
            ),
            manifest=manifest,
            output_directory=str(output_path),
            files_written=files_written,
            generated_at=generated_at,
            framework_version=thragg_version,
        )
        EvidencePackageSchema.validate_package(package)
        return package


def _extension(format_name: str) -> str:
    return "md" if format_name == "markdown" else format_name.lower()


def _render(
    renderer: Any,
    report: ReportModel,
    executive_assessment: Any,
    framework_snapshot: Any,
) -> str:
    try:
        return renderer.render(report)
    except TypeError:
        return renderer.render(executive_assessment, framework_snapshot)
