"""
core.reporting.report_repository
==================================
In-memory store for all Reports produced in one THRAGG run.

Responsibilities
----------------
- Accept validated Reports.
- Deduplicate by report ID.
- Provide query interface to the report engine and exporters.
- Never write files (that is the Exporter's job).
- Never validate (that is the Validator's job).
"""

from __future__ import annotations

from .report import ReportModel, ReportType


class ReportRepository:
    """Holds all Reports produced in a single run."""

    def __init__(self) -> None:
        self._store: dict[str, ReportModel] = {}

    def add(self, report: ReportModel) -> None:
        """Store report. Silently replaces duplicate IDs."""
        self._store[report.id] = report

    def get(self, report_id: str) -> ReportModel | None:
        return self._store.get(report_id)

    def latest(self, report_type: ReportType | None = None) -> ReportModel | None:
        reports = self.by_type(report_type) if report_type is not None else self.all()
        return max(reports, key=lambda report: report.generated_at, default=None)

    def all(self) -> list[ReportModel]:
        return list(self._store.values())

    def by_type(self, report_type: ReportType) -> list[ReportModel]:
        return [r for r in self._store.values() if r.report_type == report_type]

    def get_by_type(self, report_type: ReportType) -> list[ReportModel]:
        return self.by_type(report_type)

    def count(self) -> int:
        return len(self._store)
