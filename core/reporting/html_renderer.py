"""
core.html_renderer
==================

Milestone 9 HTML report renderer.
"""

from __future__ import annotations

from html import escape
from typing import Any

from .report_renderer import ReportRenderer

__all__ = ["HtmlRenderer"]


class HtmlRenderer(ReportRenderer):
    """Render M8 executive assessment data as a standalone HTML report."""

    format = "html"
    content_type = "text/html"

    def render(self, executive_assessment: Any, framework_snapshot: Any) -> str:
        """Return HTML for already-produced intelligence."""
        observations = "\n".join(
            "<li>"
            f"<strong>{escape(item.severity.value)}</strong> "
            f"{escape(item.text)}"
            "</li>"
            for item in executive_assessment.observations
        )
        recommendations = "\n".join(
            f"<li>{escape(item)}</li>" for item in executive_assessment.recommendations
        )
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>THRAGG Executive Assessment</title>
  <style>
    body {{ font-family: Georgia, serif; max-width: 880px; margin: 48px auto; line-height: 1.6; color: #1f2933; }}
    h1, h2 {{ line-height: 1.2; }}
    .posture {{ font-size: 1.2rem; font-weight: 700; }}
    .snapshot {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
    .metric {{ border-top: 1px solid #9aa5b1; padding-top: 8px; }}
  </style>
</head>
<body>
  <h1>THRAGG Executive Assessment</h1>
  <p>{escape(executive_assessment.summary)}</p>
  <h2>Security Posture</h2>
  <p class="posture">{escape(executive_assessment.security_posture.value)}</p>
  <h2>Observations</h2>
  <ul>{observations}</ul>
  <h2>Recommendations</h2>
  <ul>{recommendations}</ul>
  <h2>Snapshot</h2>
  <section class="snapshot">
    <div class="metric"><strong>{framework_snapshot.finding_count}</strong><br>Findings</div>
    <div class="metric"><strong>{framework_snapshot.entity_count}</strong><br>Entities</div>
    <div class="metric"><strong>{framework_snapshot.resolved_entity_count}</strong><br>Resolved entities</div>
    <div class="metric"><strong>{framework_snapshot.relationship_count}</strong><br>Relationships</div>
  </section>
</body>
</html>"""
