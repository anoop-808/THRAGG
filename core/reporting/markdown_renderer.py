"""Backward-compatible Markdown renderer import path."""

from __future__ import annotations

from typing import Any

from .renderers.markdown_renderer import MarkdownRenderer as _MarkdownRenderer

__all__ = ["MarkdownRenderer"]


class MarkdownRenderer(_MarkdownRenderer):
    """Render ReportModel, with legacy ExecutiveAssessment support."""

    def render(self, report_model: Any, framework_snapshot: Any = None) -> str:
        if framework_snapshot is None:
            return super().render(report_model)
        lines = [
            "# THRAGG Executive Assessment",
            "",
            report_model.summary,
            "",
            "## Security Posture",
            "",
            report_model.security_posture.value,
            "",
            "## Observations",
            "",
        ]
        lines.extend(
            f"- **{item.severity.value}** {item.text}"
            for item in report_model.observations
        )
        lines.extend(["", "## Recommendations", ""])
        lines.extend(f"- {item}" for item in report_model.recommendations)
        lines.extend(
            [
                "",
                "## Snapshot",
                "",
                f"- Findings: {framework_snapshot.finding_count}",
                f"- Entities: {framework_snapshot.entity_count}",
                f"- Resolved entities: {framework_snapshot.resolved_entity_count}",
                f"- Relationships: {framework_snapshot.relationship_count}",
                "",
            ]
        )
        return "\n".join(lines)
