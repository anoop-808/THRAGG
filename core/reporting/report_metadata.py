"""
core.reporting.report_metadata
===============================
Typed metadata attached to every Report.
No generic dicts — all fields are explicit and typed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReportMetadata:
    """
    Provenance and context for a generated Report.

    Fields
    ------
    framework_version : THRAGG version string (e.g. "1.0.0").
    report_version    : Report schema version string.
    assessment_time   : ISO 8601 timestamp of the assessment run.
    generated_time    : ISO 8601 timestamp of report generation.
    modules_used      : Names of modules that contributed evidence.
    execution_id      : Unique ID of the thragg.py run.
    pipeline_version  : Version of the pipeline/orchestrator.
    framework_commit  : Source commit used for this build.
    build_version     : Build/release identifier.
    generator         : Reporting component that produced the model.
    """
    framework_version: str
    report_version:    str
    assessment_time:   str
    generated_time:    str
    modules_used:      list[str]      = field(default_factory=list)
    execution_id:      str            = "unknown"
    pipeline_version:  str            = ""
    framework_commit:  str            = ""
    build_version:     str            = ""
    generator:         str            = "ReportBuilder"
    assessment_scope:  str            = ""
    limitations:       list[str]      = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework_version": self.framework_version,
            "report_version":    self.report_version,
            "assessment_time":   self.assessment_time,
            "generated_time":    self.generated_time,
            "modules_used":      list(self.modules_used),
            "execution_id":      self.execution_id,
            "pipeline_version":  self.pipeline_version,
            "framework_commit":  self.framework_commit,
            "build_version":     self.build_version,
            "generator":         self.generator,
            "assessment_scope":  self.assessment_scope,
            "limitations":       list(self.limitations),
        }
