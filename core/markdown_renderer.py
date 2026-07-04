"""
core.markdown_renderer
======================

Milestone 9 Markdown report renderer.
"""

from __future__ import annotations

from typing import Any

from .report_renderer import ReportRenderer

__all__ = ["MarkdownRenderer"]


class MarkdownRenderer(ReportRenderer):
    """Render M8 executive assessment data as Markdown."""

    format = "markdown"
    content_type = "text/markdown"

    def render(self, executive_assessment: Any, framework_snapshot: Any) -> str:
        """Return Markdown mirroring the ExecutiveAssessment contract."""
        lines = [
            "# THRAGG Executive Assessment",
            "",
            executive_assessment.summary,
            "",
            "## Security Posture",
            "",
            executive_assessment.security_posture.value,
            "",
            "## Observations",
            "",
        ]
        lines.extend(
            f"- **{item.severity.value}** {item.text}"
            for item in executive_assessment.observations
        )
        lines.extend(["", "## Recommendations", ""])
        lines.extend(f"- {item}" for item in executive_assessment.recommendations)
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
