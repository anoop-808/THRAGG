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
from .dashboard_section import DashboardSection, DashboardWidget
from .dashboard_view import DashboardView

__all__ = ["DashboardGenerator"]


class DashboardGenerator:
    """Generate one self-contained, read-only HTML dashboard."""

    def __init__(self, engine_version: str = "m10-dashboard-generator") -> None:
        self.engine_version = engine_version
        self.template_path = Path(__file__).with_name("dashboard_template.html")

    def generate(
        self,
        report_model: Any = None,
        framework_snapshot_or_output: Any = None,
        output_file: str | None = None,
        *,
        relationships: tuple[Any, ...] = (),
        resolved_entities: tuple[Any, ...] = (),
        entities: tuple[Any, ...] = (),
        findings: tuple[Any, ...] = (),
        generated_at: str | None = None,
        executive_assessment: Any = None,
        framework_snapshot: Any = None,
    ) -> DashboardBundle:
        """Write a self-contained dashboard HTML file and return its bundle."""
        generated_at = generated_at or datetime.now(timezone.utc).isoformat()
        if executive_assessment is not None:
            report_model = executive_assessment
            framework_snapshot_or_output = framework_snapshot
        if output_file is None:
            data = self._data_from_report_model(report_model, generated_at)
            output_file = str(framework_snapshot_or_output)
            snapshot = (("report_sections", str(len(report_model.sections))),)
        else:
            framework_snapshot = framework_snapshot_or_output
            data = {
                "views": [view.value for view in DashboardView],
                "generated_at": generated_at,
                "executive_assessment": report_model.to_dict(),
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
            snapshot = _data_snapshot(framework_snapshot)
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        embedded_json = json.dumps(data, sort_keys=True).replace("</", "<\\/")
        output_path.write_text(
            self.template_path.read_text(encoding="utf-8").replace(
                "__THRAGG_DASHBOARD_DATA__",
                embedded_json,
                1,
            ),
            encoding="utf-8",
        )

        bundle = DashboardBundle(
            id=stable_dashboard_bundle_id(
                str(output_path),
                snapshot,
                generated_at,
                self.engine_version,
            ),
            html_file=str(output_path),
            data_snapshot=snapshot,
            generated_at=generated_at,
            engine_version=self.engine_version,
        )
        DashboardSchema.validate_bundle(bundle)
        return bundle

    def _data_from_report_model(
        self,
        report_model: Any,
        generated_at: str,
    ) -> dict[str, Any]:
        return {
            "views": [view.value for view in DashboardView],
            "generated_at": generated_at,
            "report_model": report_model.to_dict(),
            "report_sections": [section.to_dict() for section in report_model.sections],
            "traceability_appendix": [
                item.to_dict() for item in report_model.traceability_appendix
            ],
            "artifacts": [item.to_dict() for item in report_model.artifacts],
            "explain_order": ("ReportModel", "Section", "TraceabilityEntry", "ReportArtifact"),
        }

    def build_sections(
        self,
        executive_assessment: Any,
        framework_snapshot: Any,
    ) -> tuple[DashboardSection, ...]:
        """Return dashboard-ready data with no visualization logic."""
        risks = tuple(framework_snapshot.risk_assessments)
        chains = tuple(framework_snapshot.attack_chains)
        correlations = tuple(framework_snapshot.correlations)
        return (
            DashboardSection(
                "risk-overview",
                "Risk Overview",
                (
                    DashboardWidget(
                        "risk-distribution",
                        "Risk Distribution",
                        "bar",
                        executive_assessment.to_dict()["risk_distribution"],
                    ),
                    DashboardWidget(
                        "severity-distribution",
                        "Severity Distribution",
                        "bar",
                        _count_by(correlations, lambda item: item.severity.value),
                    ),
                    DashboardWidget(
                        "confidence-distribution",
                        "Confidence Distribution",
                        "bar",
                        _count_by(correlations, lambda item: item.confidence.value),
                    ),
                ),
            ),
            DashboardSection(
                "attack-chains",
                "Top Attack Chains",
                (
                    DashboardWidget(
                        "top-attack-chains",
                        "Top Attack Chains",
                        "table",
                        [
                            item.to_dict()
                            for item in sorted(
                                chains,
                                key=lambda chain: chain.severity.value,
                            )
                        ],
                    ),
                    DashboardWidget(
                        "mitre-technique-distribution",
                        "MITRE Technique Distribution",
                        "bar",
                        _mitre_distribution(correlations),
                    ),
                ),
            ),
            DashboardSection(
                "assets-identities",
                "Assets And Identities",
                (
                    DashboardWidget(
                        "most-targeted-hosts",
                        "Most Targeted Hosts",
                        "table",
                        _entity_distribution(chains, "host"),
                    ),
                    DashboardWidget(
                        "most-targeted-identities",
                        "Most Targeted Identities",
                        "table",
                        _entity_distribution(chains, "user"),
                    ),
                    DashboardWidget(
                        "asset-distribution",
                        "Asset Distribution",
                        "bar",
                        executive_assessment.to_dict()["most_critical_assets"],
                    ),
                ),
            ),
            DashboardSection(
                "relationships",
                "Relationship Statistics",
                (
                    DashboardWidget(
                        "relationship-statistics",
                        "Relationship Statistics",
                        "number",
                        {"count": framework_snapshot.relationship_count},
                    ),
                    DashboardWidget(
                        "timeline-placeholder",
                        "Timeline",
                        "timeline",
                        [],
                    ),
                ),
            ),
        )


def _to_dict(value: Any) -> dict[str, Any]:
    return value.to_dict() if hasattr(value, "to_dict") else dict(value)


def _data_snapshot(framework_snapshot: Any) -> tuple[tuple[str, str], ...]:
    return (
        ("findings", str(framework_snapshot.finding_count)),
        ("entities", str(framework_snapshot.entity_count)),
        ("resolved_entities", str(framework_snapshot.resolved_entity_count)),
        ("relationships", str(framework_snapshot.relationship_count)),
    )


def _count_by(values: tuple[Any, ...], key) -> list[dict[str, int | str]]:
    counts: dict[str, int] = {}
    for value in values:
        name = str(key(value))
        counts[name] = counts.get(name, 0) + 1
    return [
        {"name": name, "count": count}
        for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _mitre_distribution(correlations: tuple[Any, ...]) -> list[dict[str, int | str]]:
    techniques = [
        technique
        for correlation in correlations
        for technique in correlation.mitre
    ]
    return _count_by(tuple(techniques), lambda item: item)


def _entity_distribution(
    chains: tuple[Any, ...],
    marker: str,
) -> list[dict[str, int | str]]:
    entities = [
        entity
        for chain in chains
        for entity in chain.entities
        if marker in entity.lower()
    ]
    return _count_by(tuple(entities), lambda item: item)
