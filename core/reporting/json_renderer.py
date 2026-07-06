"""Backward-compatible JSON renderer import path."""

from __future__ import annotations

import json
from typing import Any

from .renderers.json_renderer import JSONRenderer as _JSONRenderer

__all__ = ["JsonRenderer"]


class JsonRenderer(_JSONRenderer):
    """Render ReportModel, with legacy ExecutiveAssessment support."""

    def render(self, report_model: Any, framework_snapshot: Any = None) -> str:
        if framework_snapshot is None:
            return super().render(report_model)
        return json.dumps(
            {
                "executive_assessment": report_model.to_dict(),
                "framework_snapshot": framework_snapshot.to_dict(),
            },
            indent=2,
            sort_keys=True,
        )
