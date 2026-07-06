"""Backward-compatible HTML renderer import path."""

from __future__ import annotations

from html import escape
from typing import Any

from .renderers.html_renderer import HTMLRenderer as _HTMLRenderer

__all__ = ["HtmlRenderer"]


class HtmlRenderer(_HTMLRenderer):
    """Render ReportModel, with legacy ExecutiveAssessment support."""

    def render(self, report_model: Any, framework_snapshot: Any = None) -> str:
        if framework_snapshot is None:
            return super().render(report_model)
        observations = "\n".join(
            "<li>"
            f"<strong>{escape(item.severity.value)}</strong> "
            f"{escape(item.text)}"
            "</li>"
            for item in report_model.observations
        )
        recommendations = "\n".join(
            f"<li>{escape(item)}</li>" for item in report_model.recommendations
        )
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>THRAGG Executive Assessment</title>
</head>
<body>
  <h1>THRAGG Executive Assessment</h1>
  <p>{escape(report_model.summary)}</p>
  <h2>Security Posture</h2>
  <p>{escape(report_model.security_posture.value)}</p>
  <h2>Observations</h2>
  <ul>{observations}</ul>
  <h2>Recommendations</h2>
  <ul>{recommendations}</ul>
  <h2>Snapshot</h2>
  <p>Findings: {framework_snapshot.finding_count}</p>
  <p>Entities: {framework_snapshot.entity_count}</p>
  <p>Resolved entities: {framework_snapshot.resolved_entity_count}</p>
  <p>Relationships: {framework_snapshot.relationship_count}</p>
</body>
</html>"""
