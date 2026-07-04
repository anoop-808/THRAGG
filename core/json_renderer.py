"""
core.json_renderer
==================

Milestone 9 JSON report renderer.
"""

from __future__ import annotations

import json
from typing import Any

from .report_renderer import ReportRenderer

__all__ = ["JsonRenderer"]


class JsonRenderer(ReportRenderer):
    """Render M8 intelligence and snapshot data as deterministic JSON."""

    format = "json"
    content_type = "application/json"

    def render(self, executive_assessment: Any, framework_snapshot: Any) -> str:
        """Return deterministic JSON for already-produced intelligence."""
        return json.dumps(
            {
                "executive_assessment": executive_assessment.to_dict(),
                "framework_snapshot": framework_snapshot.to_dict(),
            },
            indent=2,
            sort_keys=True,
        )
