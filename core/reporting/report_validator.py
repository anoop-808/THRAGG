"""
core.reporting.report_validator
================================
Exactly four validation rules — frozen per architecture spec.

Rules
-----
1. Every report must contain at least one section.
2. Every section must contain non-empty content.
3. Every recommendation must have a matching traceability entry.
4. Report type must match a registered template.

Any rule failure raises ReportValidationError with the specific rule that failed.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..shared.errors import ReportValidationError
from .report import ReportModel
from .template_registry import TemplateRegistry


@dataclass
class ValidationResult:
    valid:  bool
    errors: list[ReportValidationError]


class ReportValidator:
    """
    Validates a Report against the four frozen rules.

    Usage
    -----
    result = ReportValidator().validate(report)
    if not result.valid:
        for err in result.errors:
            print(err)
    """

    def __init__(self) -> None:
        self._registry = TemplateRegistry()

    def validate(self, report: ReportModel) -> ValidationResult:
        errors: list[ReportValidationError] = []

        # Rule 1 — at least one section
        if not report.sections:
            errors.append(ReportValidationError(
                1, "Report contains no sections."
            ))

        # Rule 2 — every section must have non-empty content
        for section in report.sections:
            if not section.content:
                errors.append(ReportValidationError(
                    2,
                    f"Section '{section.section_id}' has empty content."
                ))

        # Rule 3 — every recommendation must have a traceability entry
        rec_ids   = self._collect_recommendation_ids(report)
        trace_ids = {t.recommendation_id for t in report.traceability_appendix}
        for rid in rec_ids:
            if rid not in trace_ids:
                errors.append(ReportValidationError(
                    3,
                    f"Recommendation '{rid}' has no matching traceability entry."
                ))

        # Rule 4 — report type must be registered
        if not self._registry.is_registered(report.report_type):
            errors.append(ReportValidationError(
                4,
                f"ReportType '{report.report_type.value}' is not registered in TemplateRegistry."
            ))

        return ValidationResult(valid=len(errors) == 0, errors=errors)

    # ------------------------------------------------------------------

    def _collect_recommendation_ids(self, report: ReportModel) -> list[str]:
        from .section import ContentType
        ids = []
        for section in report.sections:
            if section.content_type == ContentType.RECOMMENDATION:
                for rec in section.content.get("recommendations", []):
                    if rec_id := rec.get("id"):
                        ids.append(rec_id)
        return ids
