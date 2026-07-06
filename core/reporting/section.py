"""
core.reporting.section
======================
Section is the building block of every Report.

Design constraints
------------------
- SectionBuilder generates content. Section only stores it.
- ContentType enum drives renderer formatting — renderers never guess.
- Section is immutable after construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ContentType(str, Enum):
    TEXT           = "TEXT"
    TABLE          = "TABLE"
    LIST           = "LIST"
    SUMMARY        = "SUMMARY"
    KPI            = "KPI"
    CHAIN          = "CHAIN"
    RECOMMENDATION = "RECOMMENDATION"
    TRACEABILITY   = "TRACEABILITY"
    STATISTICS     = "STATISTICS"


@dataclass
class Section:
    """
    One logical block in a Report.

    Fields
    ------
    section_id   : Unique identifier within the report.
    title        : Human-readable section heading.
    order        : Integer sort key (ascending = earlier in report).
    content_type : ContentType enum — tells renderers how to format content.
    content      : Structured dict whose schema is defined by content_type.
    references   : List of IDs this section references (finding IDs, risk IDs, etc.).
    metadata     : Arbitrary additional data (report_type hints, flags, etc.).
    """
    section_id:   str
    title:        str
    order:        int
    content_type: ContentType
    content:      dict[str, Any]    = field(default_factory=dict)
    references:   list[str]         = field(default_factory=list)
    metadata:     dict[str, Any]    = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id":   self.section_id,
            "title":        self.title,
            "order":        self.order,
            "content_type": self.content_type.value,
            "content":      dict(self.content),
            "references":   list(self.references),
            "metadata":     dict(self.metadata),
        }
