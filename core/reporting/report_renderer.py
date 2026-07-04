"""
core.report_renderer
====================

Milestone 9 report renderer protocol.
"""

from __future__ import annotations

from typing import Any, Protocol

__all__ = ["ReportRenderer"]


class ReportRenderer(Protocol):
    """Contract for future report renderers."""

    format: str
    content_type: str

    def render(
        self,
        executive_assessment: Any,
        framework_snapshot: Any,
    ) -> str:
        """Render already-produced intelligence into a report string."""
        ...
