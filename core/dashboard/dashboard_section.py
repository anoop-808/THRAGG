"""
core.dashboard_section
======================

Dashboard-ready data objects with no rendering behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["DashboardSection", "DashboardWidget"]


@dataclass(frozen=True)
class DashboardWidget:
    """One dashboard visualization payload."""

    widget_id: str
    title: str
    widget_type: str
    data: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "widget_id": self.widget_id,
            "title": self.title,
            "widget_type": self.widget_type,
            "data": self.data,
        }


@dataclass(frozen=True)
class DashboardSection:
    """A reusable group of dashboard widgets."""

    section_id: str
    title: str
    widgets: tuple[DashboardWidget, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "widgets", tuple(self.widgets))

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "title": self.title,
            "widgets": [widget.to_dict() for widget in self.widgets],
        }
