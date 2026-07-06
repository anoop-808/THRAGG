"""
core.reporting.renderers.console_renderer
==========================================
ConsoleRenderer has exactly one responsibility:
Generate a concise five-line execution summary string.

No tables. No verbose output. No formatting beyond the 5 lines.
"""

from __future__ import annotations

from ..report import Report
from ..section import ContentType


class ConsoleRenderer:
    format = "console"
    content_type = "text/plain"

    def render(self, report: Report) -> str:
        posture = "UNKNOWN"
        critical = 0
        top_priority = "—"

        for section in report.sections:
            c = section.content
            if section.content_type == ContentType.KPI:
                posture  = c.get("posture_label", "UNKNOWN")
                critical = c.get("critical_count", 0)
            if section.content_type == ContentType.LIST:
                items = c.get("items", [])
                if items:
                    top_priority = items[0]

        path_label = f"reports/{report.report_type.value.lower()}.md"

        return (
            f"THRAGG Assessment Complete\n"
            f"Security Posture  : {posture}\n"
            f"Critical Risks    : {critical}\n"
            f"Highest Priority  : {top_priority}\n"
            f"Executive Report  : {path_label}"
        )
