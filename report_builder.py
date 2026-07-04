"""
Application-layer report builder for THRAGG framework output.

This module renders already-produced framework objects. It does not parse raw
evidence, calculate scores, correlate findings, or build attack chains.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from html import escape
from typing import Any

from core.evidence_package import EvidencePackage
from core.report_engine import ReportEngine
from core.report_renderer import ReportRenderer

__all__ = [
    "ReportBuilder",
    "HumanMarkdownRenderer",
    "HumanHtmlRenderer",
    "JsonIndexRenderer",
]


@dataclass(frozen=True)
class ReportBuilder:
    """Publish human-readable reports from immutable framework objects."""

    framework_version: str = "1.0"
    engine_version: str = "application-report-builder"

    def build(
        self,
        executive_assessment: Any,
        framework_snapshot: Any,
        output_directory: str,
        *,
        evidence_package: EvidencePackage | None = None,
        dashboard_bundle: Any | None = None,
        generated_at: str | None = None,
    ) -> EvidencePackage:
        """Write Markdown, HTML, and JSON index files via ReportEngine."""
        generated_at = generated_at or executive_assessment.generated_at
        renderers: tuple[ReportRenderer, ...] = (
            HumanMarkdownRenderer(
                self.framework_version,
                self.engine_version,
                generated_at,
                evidence_package,
                dashboard_bundle,
            ),
            HumanHtmlRenderer(
                self.framework_version,
                self.engine_version,
                generated_at,
                evidence_package,
                dashboard_bundle,
            ),
            JsonIndexRenderer(
                self.framework_version,
                self.engine_version,
                generated_at,
                evidence_package,
                dashboard_bundle,
            ),
        )
        return ReportEngine(
            renderers,
            engine_version=self.engine_version,
            thragg_version=self.framework_version,
        ).publish(
            executive_assessment,
            framework_snapshot,
            output_directory,
            generated_at=generated_at,
        )


@dataclass(frozen=True)
class _RenderContext:
    framework_version: str
    engine_version: str
    generated_at: str
    evidence_package: EvidencePackage | None = None
    dashboard_bundle: Any | None = None


@dataclass(frozen=True)
class HumanMarkdownRenderer:
    """Render framework output as a professional Markdown report."""

    framework_version: str
    engine_version: str
    generated_at: str
    evidence_package: EvidencePackage | None = None
    dashboard_bundle: Any | None = None

    format = "markdown"
    content_type = "text/markdown"

    def render(self, executive_assessment: Any, framework_snapshot: Any) -> str:
        context = _RenderContext(
            self.framework_version,
            self.engine_version,
            self.generated_at,
            self.evidence_package,
            self.dashboard_bundle,
        )
        lines = [
            "# THRAGG Security Report",
            "",
            "## Executive Summary",
            "",
            executive_assessment.summary,
            "",
            "## Security Posture",
            "",
            str(executive_assessment.security_posture.value),
            "",
            "## Risk Overview",
            "",
            *_metric_lines(executive_assessment.statistics.risk_counts),
            "",
            "## Top Risks",
            "",
            *_risk_lines(framework_snapshot.risk_assessments),
            "",
            "## Attack Chains",
            "",
            *_attack_chain_lines(framework_snapshot.attack_chains),
            "",
            "## Correlation Summary",
            "",
            *_correlation_lines(framework_snapshot.correlations),
            "",
            "## Framework Statistics",
            "",
            *_statistics_lines(executive_assessment.statistics),
            "",
            "## Recommendations",
            "",
            *_recommendation_lines(executive_assessment.recommendations),
            "",
            "## Evidence Package Summary",
            "",
            *_evidence_lines(context.evidence_package),
            "",
            "## Dashboard Information",
            "",
            *_dashboard_lines(context.dashboard_bundle),
            "",
            "## Version Information",
            "",
            *_version_lines(executive_assessment, framework_snapshot, context),
            "",
        ]
        return "\n".join(lines)


@dataclass(frozen=True)
class HumanHtmlRenderer:
    """Render framework output as a standalone HTML report."""

    framework_version: str
    engine_version: str
    generated_at: str
    evidence_package: EvidencePackage | None = None
    dashboard_bundle: Any | None = None

    format = "html"
    content_type = "text/html"

    def render(self, executive_assessment: Any, framework_snapshot: Any) -> str:
        markdown = HumanMarkdownRenderer(
            self.framework_version,
            self.engine_version,
            self.generated_at,
            self.evidence_package,
            self.dashboard_bundle,
        ).render(executive_assessment, framework_snapshot)
        return _markdown_subset_to_html(markdown)


@dataclass(frozen=True)
class JsonIndexRenderer:
    """Render a deterministic JSON index for framework output."""

    framework_version: str
    engine_version: str
    generated_at: str
    evidence_package: EvidencePackage | None = None
    dashboard_bundle: Any | None = None

    format = "json"
    content_type = "application/json"

    def render(self, executive_assessment: Any, framework_snapshot: Any) -> str:
        return json.dumps(
            {
                "executive_summary": executive_assessment.summary,
                "security_posture": executive_assessment.security_posture.value,
                "top_risks": [risk.to_dict() for risk in _ordered_risks(
                    framework_snapshot.risk_assessments
                )],
                "attack_chains": [
                    chain.to_dict() for chain in framework_snapshot.attack_chains
                ],
                "correlations": [
                    correlation.to_dict()
                    for correlation in framework_snapshot.correlations
                ],
                "statistics": executive_assessment.statistics.to_dict(),
                "recommendations": list(executive_assessment.recommendations),
                "evidence_package": (
                    self.evidence_package.to_dict()
                    if self.evidence_package is not None
                    else None
                ),
                "dashboard": (
                    self.dashboard_bundle.to_dict()
                    if self.dashboard_bundle is not None
                    else None
                ),
                "version_information": {
                    "framework_version": self.framework_version,
                    "engine_version": self.engine_version,
                    "intelligence_engine_version": executive_assessment.engine_version,
                    "snapshot_version": framework_snapshot.snapshot_version,
                    "generated_at": self.generated_at,
                },
            },
            indent=2,
            sort_keys=True,
        )


def _ordered_risks(risks: tuple[Any, ...]) -> tuple[Any, ...]:
    return tuple(
        sorted(
            risks,
            key=lambda risk: (
                risk.priority_rank is None,
                risk.priority_rank if risk.priority_rank is not None else 0,
                -risk.score,
                risk.id,
            ),
        )
    )


def _metric_lines(metrics: tuple[Any, ...]) -> list[str]:
    return [f"- {metric.name}: {metric.count}" for metric in metrics] or ["- None"]


def _risk_lines(risks: tuple[Any, ...]) -> list[str]:
    return [
        (
            f"- {risk.id}: {risk.risk_level.value} ({risk.score}) - "
            f"{risk.summary} Recommendation: {risk.recommendation}"
        )
        for risk in _ordered_risks(risks)
    ] or ["- No risks provided."]


def _attack_chain_lines(chains: tuple[Any, ...]) -> list[str]:
    return [
        (
            f"- {chain.id}: {chain.title} [{chain.severity.value}/"
            f"{chain.confidence.value}] Entry: {chain.entry_point}; "
            f"Target: {chain.target}; Correlations: {len(chain.correlations)}"
        )
        for chain in chains
    ] or ["- No attack chains provided."]


def _correlation_lines(correlations: tuple[Any, ...]) -> list[str]:
    return [
        (
            f"- {correlation.id}: {correlation.title} "
            f"[{correlation.severity.value}/{correlation.confidence.value}] "
            f"{correlation.recommendation}"
        )
        for correlation in correlations
    ] or ["- No correlations provided."]


def _statistics_lines(statistics: Any) -> list[str]:
    lines = [
        f"- Findings: {statistics.total_findings}",
        f"- Entities: {statistics.total_entities}",
        f"- Relationships: {statistics.total_relationships}",
        f"- Correlations: {statistics.total_correlations}",
        f"- Attack chains: {statistics.total_attack_chains}",
        "- Top entity types: "
        + _inline_metrics(statistics.top_entity_types),
        "- Top attack stages: "
        + _inline_metrics(statistics.top_attack_stages),
        "- Top attack categories: "
        + _inline_metrics(statistics.top_attack_categories),
    ]
    return lines


def _recommendation_lines(recommendations: tuple[str, ...]) -> list[str]:
    return [f"- {item}" for item in recommendations] or ["- No recommendations."]


def _evidence_lines(package: EvidencePackage | None) -> list[str]:
    if package is None:
        return ["- No evidence package provided."]
    return [
        f"- Package ID: {package.id}",
        f"- Output directory: {package.output_directory}",
        f"- Files: {', '.join(package.files_written)}",
        f"- Generated at: {package.generated_at}",
    ]


def _dashboard_lines(bundle: Any | None) -> list[str]:
    if bundle is None:
        return ["- No dashboard bundle provided."]
    return [
        f"- Dashboard ID: {bundle.id}",
        f"- HTML file: {bundle.html_file}",
        f"- Engine version: {bundle.engine_version}",
        f"- Generated at: {bundle.generated_at}",
    ]


def _version_lines(
    executive_assessment: Any,
    framework_snapshot: Any,
    context: _RenderContext,
) -> list[str]:
    return [
        f"- framework_version: {context.framework_version}",
        f"- engine_version: {context.engine_version}",
        f"- intelligence_engine_version: {executive_assessment.engine_version}",
        f"- snapshot_version: {framework_snapshot.snapshot_version}",
        f"- generated_at: {context.generated_at}",
    ]


def _inline_metrics(metrics: tuple[Any, ...]) -> str:
    return ", ".join(f"{metric.name}={metric.count}" for metric in metrics) or "None"


def _markdown_subset_to_html(markdown: str) -> str:
    body = []
    in_list = False
    for line in markdown.splitlines():
        if line.startswith("# "):
            if in_list:
                body.append("</ul>")
                in_list = False
            body.append(f"<h1>{escape(line[2:])}</h1>")
        elif line.startswith("## "):
            if in_list:
                body.append("</ul>")
                in_list = False
            body.append(f"<h2>{escape(line[3:])}</h2>")
        elif line.startswith("- "):
            if not in_list:
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{escape(line[2:])}</li>")
        elif line:
            if in_list:
                body.append("</ul>")
                in_list = False
            body.append(f"<p>{escape(line)}</p>")
    if in_list:
        body.append("</ul>")

    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>THRAGG Security Report</title>
  <style>
    body { font-family: Georgia, serif; max-width: 920px; margin: 48px auto; line-height: 1.6; color: #1f2933; }
    h1, h2 { line-height: 1.2; }
    h2 { border-top: 1px solid #c9d1d9; padding-top: 20px; margin-top: 28px; }
  </style>
</head>
<body>
""" + "\n".join(body) + """
</body>
</html>"""
