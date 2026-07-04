"""
core.dashboard_generator
========================

Milestone 10 offline dashboard generator.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .dashboard_bundle import DashboardBundle, stable_dashboard_bundle_id
from .dashboard_schema import DashboardSchema
from .dashboard_view import DashboardView

__all__ = ["DashboardGenerator"]


class DashboardGenerator:
    """Generate one self-contained, read-only HTML dashboard."""

    def __init__(self, engine_version: str = "m10-dashboard-generator") -> None:
        self.engine_version = engine_version
        self.template_path = Path(__file__).with_name("dashboard_template.html")

    def generate(
        self,
        executive_assessment: Any,
        framework_snapshot: Any,
        output_file: str,
        *,
        relationships: tuple[Any, ...] = (),
        resolved_entities: tuple[Any, ...] = (),
        entities: tuple[Any, ...] = (),
        findings: tuple[Any, ...] = (),
        generated_at: str | None = None,
    ) -> DashboardBundle:
        """Write a self-contained dashboard HTML file and return its bundle."""
        generated_at = generated_at or datetime.now(timezone.utc).isoformat()
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "views": [view.value for view in DashboardView],
            "generated_at": generated_at,
            "executive_assessment": executive_assessment.to_dict(),
            "framework_snapshot": framework_snapshot.to_dict(),
            "risk_assessments": [
                item.to_dict() for item in framework_snapshot.risk_assessments
            ],
            "attack_chains": [item.to_dict() for item in framework_snapshot.attack_chains],
            "correlations": [item.to_dict() for item in framework_snapshot.correlations],
            "relationships": [_to_dict(item) for item in relationships],
            "resolved_entities": [_to_dict(item) for item in resolved_entities],
            "entities": [_to_dict(item) for item in entities],
            "findings": [_to_dict(item) for item in findings],
            "explain_order": (
                "ExecutiveAssessment",
                "RiskAssessment",
                "AttackChain",
                "Correlation",
                "Relationship",
                "ResolvedEntity",
                "Entity",
                "Finding",
            ),
        }
        embedded_json = json.dumps(data, sort_keys=True).replace("</", "<\\/")
        output_path.write_text(
            self.template_path.read_text(encoding="utf-8").replace(
                "__THRAGG_DASHBOARD_DATA__",
                embedded_json,
            ),
            encoding="utf-8",
        )

        bundle = DashboardBundle(
            id=stable_dashboard_bundle_id(
                str(output_path),
                _data_snapshot(framework_snapshot),
                generated_at,
                self.engine_version,
            ),
            html_file=str(output_path),
            data_snapshot=_data_snapshot(framework_snapshot),
            generated_at=generated_at,
            engine_version=self.engine_version,
        )
        DashboardSchema.validate_bundle(bundle)
        return bundle


def _to_dict(value: Any) -> dict[str, Any]:
    return value.to_dict() if hasattr(value, "to_dict") else dict(value)


def _data_snapshot(framework_snapshot: Any) -> tuple[tuple[str, str], ...]:
    return (
        ("findings", str(framework_snapshot.finding_count)),
        ("entities", str(framework_snapshot.entity_count)),
        ("resolved_entities", str(framework_snapshot.resolved_entity_count)),
        ("relationships", str(framework_snapshot.relationship_count)),
    )
