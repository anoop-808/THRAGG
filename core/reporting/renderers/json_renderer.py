"""
core.reporting.renderers.json_renderer
=======================================
Renders a Report to a JSON string.
Returns str. Never writes files.
"""

from __future__ import annotations

import json

from ..report import Report


class JSONRenderer:
    format = "json"
    content_type = "application/json"

    def render(self, report: Report) -> str:
        indent = 2
        return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)
