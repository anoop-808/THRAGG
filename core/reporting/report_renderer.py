"""
core.report_renderer
====================

Milestone 9 report renderer protocol.
"""

from __future__ import annotations

from typing import Protocol

from .report import ReportModel

__all__ = ["ReportRenderer"]


class ReportRenderer(Protocol):
    """Contract for future report renderers."""

    format: str
    content_type: str

    def render(self, report_model: ReportModel) -> str:
        """Render a ReportModel into a report string."""
        ...
