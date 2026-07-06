"""
core.reporting.section_builder
===============================
SectionBuilder generates Section content from ExecutiveAssessment data.

Design constraints
------------------
- SectionBuilder generates CONTENT only. Never changes report structure.
- TemplateRegistry defines which sections exist and their order.
- SectionBuilder populates what those sections contain.
- Never calculates risk, severity, or confidence — reads from input only.
- Every build_* method returns a populated Section object.
"""

from __future__ import annotations

from typing import Any

from .section import Section, ContentType
from .template_registry import SectionTemplate


class SectionBuilder:
    """
    Builds Section objects from ExecutiveAssessment data.

    Parameters
    ----------
    assessment : dict
        ExecutiveAssessment serialized as a plain dict.
        SectionBuilder never imports the ExecutiveAssessment class directly
        to avoid coupling the reporting layer to upstream object schemas.
    """

    def __init__(self, assessment: dict[str, Any] | Any) -> None:
        self._a = assessment.to_dict() if hasattr(assessment, "to_dict") else dict(assessment)

    def build(self, template: SectionTemplate) -> Section:
        """Dispatch to the correct builder based on section_id prefix."""
        builders = {
            ContentType.KPI:            self._build_kpi,
            ContentType.TABLE:          self._build_table,
            ContentType.LIST:           self._build_list,
            ContentType.SUMMARY:        self._build_summary,
            ContentType.RECOMMENDATION: self._build_recommendations,
            ContentType.TRACEABILITY:   self._build_traceability,
            ContentType.STATISTICS:     self._build_statistics,
            ContentType.CHAIN:          self._build_chains,
            ContentType.TEXT:           self._build_text,
        }
        builder_fn = builders.get(template.content_type, self._build_text)
        return builder_fn(template)

    # ------------------------------------------------------------------
    # Section builders — one per ContentType
    # ------------------------------------------------------------------

    def _build_kpi(self, t: SectionTemplate) -> Section:
        posture = self._a.get("security_posture", {})
        posture_label = posture.get("posture", "UNKNOWN") if isinstance(posture, dict) else posture
        return Section(
            section_id=t.section_id,
            title=t.title,
            order=t.order,
            content_type=ContentType.KPI,
            content={
                "posture_label":  posture_label or "UNKNOWN",
                "overall_score":  self._a.get("overall_risk", {}).get("score", 0),
                "risk_level":     self._a.get("overall_risk", {}).get("level", posture_label or "UNKNOWN"),
                "critical_count": self._risk_count("CRITICAL"),
                "high_count":     self._risk_count("HIGH"),
                "medium_count":   self._risk_count("MEDIUM"),
                "modules_run":    self._a.get("metadata", {}).get("modules_used", []),
            },
        )

    def _build_table(self, t: SectionTemplate) -> Section:
        risks = self._a.get("top_risks") or self._a.get("top_priorities", [])
        rows = []
        for r in risks:
            if not isinstance(r, dict):
                r = {"label": str(r)}
            rows.append({
                "id":       r.get("risk_id", "—"),
                "label":    r.get("label", r.get("summary", "—")),
                "domain":   r.get("domain", "—"),
                "score":    r.get("score", 0),
                "level":    r.get("level", r.get("risk_level", "—")),
                "priority": r.get("priority", "—"),
            })
        return Section(
            section_id=t.section_id,
            title=t.title,
            order=t.order,
            content_type=ContentType.TABLE,
            content={"columns": ["ID", "Label", "Domain", "Score", "Level", "Priority"], "rows": rows},
            references=[r.get("risk_id", "") for r in risks],
        )

    def _build_list(self, t: SectionTemplate) -> Section:
        priorities = self._a.get("top_priorities", [])
        items = [
            str(p) if not isinstance(p, dict)
            else f"[{p.get('domain', '?')}] {p.get('label', '?')} - {p.get('level', '?')}"
            for p in priorities
        ]
        return Section(
            section_id=t.section_id,
            title=t.title,
            order=t.order,
            content_type=ContentType.LIST,
            content={"items": items},
        )

    def _build_summary(self, t: SectionTemplate) -> Section:
        scope = self._a.get("scope", self._a.get("assessment_scope", {}))
        return Section(
            section_id=t.section_id,
            title=t.title,
            order=t.order,
            content_type=ContentType.SUMMARY,
            content={
                "modules_run":      scope.get("modules_run", []),
                "modules_skipped":  scope.get("modules_skipped", []),
                "evidence_files":   scope.get("evidence_files", []),
                "limitations":      scope.get("assessment_limitations", []),
                "assessed_at":      scope.get("assessed_at", scope.get("assessment_time", "—")),
            },
        )

    def _build_recommendations(self, t: SectionTemplate) -> Section:
        recs = self._a.get("executive_recommendations") or self._a.get("recommendations", [])
        formatted = []
        for r in recs:
            if not isinstance(r, dict):
                r = {"id": str(r), "title": str(r), "description": str(r)}
            formatted.append({
                "id":               r.get("id", "—"),
                "title":            r.get("title", "—"),
                "description":      r.get("description", "—"),
                "priority":         r.get("priority", "—"),
                "domain":           r.get("domain", "—"),
                "expected_benefit": r.get("expected_benefit", "—"),
                "category":         r.get("category", "—"),
            })
        return Section(
            section_id=t.section_id,
            title=t.title,
            order=t.order,
            content_type=ContentType.RECOMMENDATION,
            content={"recommendations": formatted},
            references=[r.get("id", "") for r in recs],
        )

    def _build_traceability(self, t: SectionTemplate) -> Section:
        trace = self._a.get("traceability", [])
        if isinstance(trace, dict):
            trace = [
                {"recommendation_id": key, "observation_ids": list(items)}
                for key, items in trace.get("recommendation_to_observations", [])
            ]
        return Section(
            section_id=t.section_id,
            title=t.title,
            order=t.order,
            content_type=ContentType.TRACEABILITY,
            content={"entries": trace},
        )

    def _build_statistics(self, t: SectionTemplate) -> Section:
        stats = self._a.get("risk_statistics", {})
        risk_distribution = self._a.get("risk_distribution", [])
        if not stats and risk_distribution:
            stats = {
                str(item.get("risk_level", item.get("name", ""))).lower(): item.get("count", 0)
                for item in risk_distribution
                if isinstance(item, dict)
            }
            stats["total"] = sum(value for value in stats.values() if isinstance(value, int))
        return Section(
            section_id=t.section_id,
            title=t.title,
            order=t.order,
            content_type=ContentType.STATISTICS,
            content={
                "total_risks":      stats.get("total", 0),
                "critical":         stats.get("critical", 0),
                "high":             stats.get("high", 0),
                "medium":           stats.get("medium", 0),
                "low":              stats.get("low", 0),
                "domain_breakdown": stats.get("by_domain", {}),
                "average_score":    stats.get("average_score", 0),
            },
        )

    def _build_chains(self, t: SectionTemplate) -> Section:
        chains = self._a.get("attack_chains", self._a.get("primary_attack_paths", []))
        return Section(
            section_id=t.section_id,
            title=t.title,
            order=t.order,
            content_type=ContentType.CHAIN,
            content={"chains": chains},
            references=[c.get("chain_id", "") for c in chains],
        )

    def _build_text(self, t: SectionTemplate) -> Section:
        impact = self._a.get("business_impact", {})
        if isinstance(impact, list):
            text = "\n".join(str(item.get("summary", item)) for item in impact)
        else:
            text = impact.get("summary", self._a.get("overall_summary", "No business impact summary available."))
        return Section(
            section_id=t.section_id,
            title=t.title,
            order=t.order,
            content_type=ContentType.TEXT,
            content={"text": text},
        )

    def _risk_count(self, level: str) -> int:
        for item in self._a.get("risk_distribution", []):
            if str(item.get("risk_level", item.get("name", ""))).upper() == level:
                return int(item.get("count", 0))
        return int(self._a.get("risk_statistics", {}).get(level.lower(), 0))
