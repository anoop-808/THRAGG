"""
core.reporting.renderers.json_renderer
=======================================
Renders a Report to a JSON string.
Returns str. Never writes files.
"""

from __future__ import annotations

import json
from typing import Any

from ..report import Report


class JSONRenderer:
    format = "json"
    content_type = "application/json"

    def render(self, report: Any, framework_snapshot: Any = None) -> str:
        if framework_snapshot is not None:
            return json.dumps(
                {
                    "executive_assessment": report.to_dict(),
                    "framework_snapshot": framework_snapshot.to_dict(),
                },
                indent=2,
                sort_keys=True,
            )
        indent = 2
        return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)
