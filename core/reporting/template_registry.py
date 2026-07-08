"""
core.reporting.template_registry
=================================
Single registry defining which sections appear in each report type
and in what order.

Design constraints
------------------
- TemplateRegistry defines STRUCTURE only. Never content.
- SectionBuilder generates content. TemplateRegistry defines order.
- New report types = new entry in TEMPLATES. No other file changes.
"""

from __future__ import annotations

from dataclasses import dataclass


from .section import ContentType
from .report import ReportType
from ..shared.errors import TemplateError


@dataclass(frozen=True)
class SectionTemplate:
    """Blueprint for one section slot in a report."""
    section_id:   str
    title:        str
    order:        int
    content_type: ContentType
    required:     bool = True
    visible:      bool = True


# ---------------------------------------------------------------------------
# Template definitions — one per ReportType
# ---------------------------------------------------------------------------

TEMPLATES: dict[ReportType, list[SectionTemplate]] = {

    ReportType.EXECUTIVE: [
        SectionTemplate("exec-scope",       "Assessment Scope",        1,  ContentType.SUMMARY),
        SectionTemplate("exec-posture",     "Security Posture",        2,  ContentType.KPI),
        SectionTemplate("exec-priorities",  "Executive Priorities",    3,  ContentType.LIST),
        SectionTemplate("exec-risks",       "Top Business Risks",      4,  ContentType.TABLE),
        SectionTemplate("exec-impact",      "Business Impact",         5,  ContentType.TEXT),
        SectionTemplate("exec-recs",        "Recommendations",         6,  ContentType.RECOMMENDATION),
        SectionTemplate("exec-stats",       "Risk Statistics",         7,  ContentType.STATISTICS),
        SectionTemplate("exec-trace",       "Traceability Appendix",   8,  ContentType.TRACEABILITY),
    ],

    ReportType.TECHNICAL: [
        SectionTemplate("tech-scope",       "Assessment Scope",        1,  ContentType.SUMMARY),
        SectionTemplate("tech-chains",      "Attack Chains",           2,  ContentType.CHAIN),
        SectionTemplate("tech-risks",       "Risk Assessments",        3,  ContentType.TABLE),
        SectionTemplate("tech-mitre",       "MITRE ATT&CK Coverage",   4,  ContentType.TABLE),
        SectionTemplate("tech-findings",    "Finding Statistics",      5,  ContentType.STATISTICS),
        SectionTemplate("tech-recs",        "Technical Recommendations", 6, ContentType.RECOMMENDATION),
        SectionTemplate("tech-trace",       "Traceability Appendix",   7,  ContentType.TRACEABILITY),
    ],

    ReportType.MARKDOWN: [
        SectionTemplate("md-posture",       "Security Posture",        1,  ContentType.KPI),
        SectionTemplate("md-risks",         "Top Risks",               2,  ContentType.TABLE),
        SectionTemplate("md-recs",          "Recommendations",         3,  ContentType.RECOMMENDATION),
        SectionTemplate("md-trace",         "Traceability",            4,  ContentType.TRACEABILITY),
    ],

    ReportType.HTML: [
        SectionTemplate("html-posture",     "Security Posture",        1,  ContentType.KPI),
        SectionTemplate("html-risks",       "Risk Summary",            2,  ContentType.TABLE),
        SectionTemplate("html-chains",      "Attack Chains",           3,  ContentType.CHAIN),
        SectionTemplate("html-recs",        "Recommendations",         4,  ContentType.RECOMMENDATION),
        SectionTemplate("html-stats",       "Statistics",              5,  ContentType.STATISTICS),
        SectionTemplate("html-trace",       "Traceability Appendix",   6,  ContentType.TRACEABILITY),
    ],

    ReportType.JSON: [
        SectionTemplate("json-posture",     "Security Posture",        1,  ContentType.KPI),
        SectionTemplate("json-risks",       "Risk Assessments",        2,  ContentType.TABLE),
        SectionTemplate("json-chains",      "Attack Chains",           3,  ContentType.CHAIN),
        SectionTemplate("json-recs",        "Recommendations",         4,  ContentType.RECOMMENDATION),
        SectionTemplate("json-trace",       "Traceability Appendix",   5,  ContentType.TRACEABILITY),
    ],

    ReportType.EVIDENCE: [
        SectionTemplate("ev-scope",         "Assessment Scope",        1,  ContentType.SUMMARY),
        SectionTemplate("ev-findings",      "All Findings",            2,  ContentType.TABLE),
        SectionTemplate("ev-artifacts",     "Evidence Artifacts",      3,  ContentType.LIST),
        SectionTemplate("ev-trace",         "Full Traceability",       4,  ContentType.TRACEABILITY),
    ],

    ReportType.COMPLIANCE: [
        SectionTemplate("comp-scope",       "Assessment Scope",        1,  ContentType.SUMMARY),
        SectionTemplate("comp-mitre",       "MITRE ATT&CK Coverage",   2,  ContentType.TABLE),
        SectionTemplate("comp-risks",       "Risk Summary",            3,  ContentType.TABLE),
        SectionTemplate("comp-recs",        "Governance Recommendations", 4, ContentType.RECOMMENDATION),
        SectionTemplate("comp-trace",       "Traceability Appendix",   5,  ContentType.TRACEABILITY),
    ],
}


class TemplateRegistry:
    """
    Single registry for report structure templates.

    Responsibilities
    ----------------
    - Return the ordered list of SectionTemplates for a given ReportType.
    - Validate that a given report type is registered.
    - Never generate section content (that is SectionBuilder's job).
    """

    def get(self, report_type: ReportType) -> list[SectionTemplate]:
        """Return section templates for this report type, sorted by order."""
        if report_type not in TEMPLATES:
            raise TemplateError(
                4,
                f"ReportType '{report_type.value}' is not registered in TemplateRegistry. "
                f"Registered types: {[rt.value for rt in TEMPLATES]}"
            )
        return sorted((t for t in TEMPLATES[report_type] if t.visible), key=lambda t: t.order)

    def is_registered(self, report_type: ReportType) -> bool:
        return report_type in TEMPLATES

    def registered_types(self) -> list[ReportType]:
        return list(TEMPLATES.keys())
