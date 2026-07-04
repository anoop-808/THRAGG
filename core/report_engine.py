"""
core.report_engine
==================

Milestone 9 report publishing engine.
"""

from __future__ import annotations

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
from .report_renderer import ReportRenderer

__all__ = ["ReportEngine"]


class ReportEngine:
    """Publish existing THRAGG intelligence through registered renderers."""

    def __init__(
        self,
        renderers: tuple[ReportRenderer, ...],
        engine_version: str = "m9-report-engine",
        thragg_version: str = "1.0",
    ) -> None:
        self.renderers = tuple(renderers)
        self.engine_version = engine_version
        self.thragg_version = thragg_version

    def publish(
        self,
        executive_assessment: Any,
        framework_snapshot: Any,
        output_directory: str,
        generated_at: str | None = None,
    ) -> EvidencePackage:
        """Render reports, write a manifest, and return an EvidencePackage."""
        generated_at = generated_at or datetime.now(timezone.utc).isoformat()
        output_path = Path(output_directory)
        output_path.mkdir(parents=True, exist_ok=True)

        rendered = tuple(
            (renderer.format, renderer.render(executive_assessment, framework_snapshot))
            for renderer in self.renderers
        )
        files_written = tuple(
            f"report.{_extension(format_name)}" for format_name, _ in rendered
        ) + ("manifest.json",)

        manifest = EvidencePackageManifest(
            package_id=f"evidence-{executive_assessment.id}",
            generated_at=generated_at,
            engine_version=self.engine_version,
            thragg_version=self.thragg_version,
            files=files_written,
            snapshot_summary=(
                ("findings", str(framework_snapshot.finding_count)),
                ("entities", str(framework_snapshot.entity_count)),
                (
                    "resolved_entities",
                    str(framework_snapshot.resolved_entity_count),
                ),
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
            framework_version=self.thragg_version,
        )
        EvidencePackageSchema.validate_package(package)
        return package


def _extension(format_name: str) -> str:
    return "md" if format_name == "markdown" else format_name
