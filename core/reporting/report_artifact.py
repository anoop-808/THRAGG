"""
core.reporting.report_artifact
===============================
Typed artifact attached to a Report.
Replaces generic list[str] artifact lists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ArtifactType(str, Enum):
    EVIDENCE_FILE = "EVIDENCE_FILE"
    SCREENSHOT    = "SCREENSHOT"
    JSON_EXPORT   = "JSON_EXPORT"
    LOG_FILE      = "LOG_FILE"
    SCAN_RESULT   = "SCAN_RESULT"


@dataclass
class ReportArtifact:
    """
    One artifact referenced by a Report.

    Fields
    ------
    artifact_id   : Unique identifier within the report.
    artifact_type : ArtifactType enum.
    display_name  : Human-readable label.
    path          : File path or URL.
    mime_type     : MIME type string (e.g. "application/json").
    referenced_by : List of section_ids that reference this artifact.
    metadata      : Arbitrary additional data.
    """
    artifact_id:   str
    artifact_type: ArtifactType
    display_name:  str
    path:          str
    mime_type:     str                  = "application/octet-stream"
    referenced_by: list[str]            = field(default_factory=list)
    metadata:      dict[str, Any]       = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id":   self.artifact_id,
            "artifact_type": self.artifact_type.value,
            "display_name":  self.display_name,
            "path":          self.path,
            "mime_type":     self.mime_type,
            "referenced_by": list(self.referenced_by),
            "metadata":      dict(self.metadata),
        }
