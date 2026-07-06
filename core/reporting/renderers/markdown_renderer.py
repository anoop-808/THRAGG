"""
core.reporting.renderers.markdown_renderer
==========================================
Renders a Report to a Markdown string.

Design constraints
------------------
- Returns str. Never writes files (Exporter writes files).
- Never modifies Report.
- Uses section.content_type to format — never guesses content shape.
"""

from __future__ import annotations

from ..report import Report
from ..section import Section, ContentType


class MarkdownRenderer:
    format = "markdown"
    content_type = "text/markdown"

    def render(self, report: Report) -> str:
        lines: list[str] = []
        lines.append(f"# {report.title}")
        lines.append(f"\n_Generated: {report.generated_at} · THRAGG v{report.framework_version}_\n")
        lines.append("---\n")

        for section in sorted(report.sections, key=lambda s: s.order):
            lines.append(f"## {section.title}\n")
            lines.extend(self._render_section(section))
            lines.append("")

        # Traceability appendix
        if report.traceability_appendix:
            lines.append("## Traceability Appendix\n")
            for entry in report.traceability_appendix:
                lines.append(f"**{entry.recommendation_id}**")
                lines.append(f"- Risk: `{entry.risk_assessment_id}`")
                lines.append(f"- Chain: `{entry.attack_chain_id}`")
                lines.append(f"- Correlation: `{entry.correlation_id}`")
                lines.append(f"- Findings: {', '.join(entry.finding_ids) or '—'}")
                lines.append(f"- Evidence: {', '.join(entry.evidence_files) or '—'}")
                lines.append("")

        return "\n".join(lines)

    def _render_section(self, section: Section) -> list[str]:
        ct = section.content_type
        c  = section.content

        if ct == ContentType.KPI:
            return [
                f"| Metric | Value |",
                f"|--------|-------|",
                f"| Security Posture | **{c.get('posture_label','—')}** |",
                f"| Overall Score    | {c.get('overall_score', 0)} |",
                f"| Risk Level       | {c.get('risk_level','—')} |",
                f"| Critical         | {c.get('critical_count', 0)} |",
                f"| High             | {c.get('high_count', 0)} |",
                f"| Medium           | {c.get('medium_count', 0)} |",
                f"| Modules Run      | {', '.join(c.get('modules_run', []))} |",
            ]

        if ct == ContentType.TABLE:
            cols = c.get("columns", [])
            rows = c.get("rows", [])
            if not cols or not rows:
                return ["_No data._"]
            header = "| " + " | ".join(cols) + " |"
            sep    = "| " + " | ".join(["---"] * len(cols)) + " |"
            body   = [
                "| " + " | ".join(str(r.get(k.lower(), "—")) for k in cols) + " |"
                for r in rows
            ]
            return [header, sep] + body

        if ct == ContentType.LIST:
            items = c.get("items", [])
            return [f"- {item}" for item in items] or ["_No items._"]

        if ct == ContentType.SUMMARY:
            lines = []
            lines.append(f"**Modules run:** {', '.join(c.get('modules_run', [])) or '—'}")
            lines.append(f"**Modules skipped:** {', '.join(c.get('modules_skipped', [])) or 'None'}")
            lines.append(f"**Evidence files:** {', '.join(c.get('evidence_files', [])) or '—'}")
            lines.append(f"**Assessed at:** {c.get('assessed_at', '—')}")
            lims = c.get("limitations", [])
            if lims:
                lines.append(f"\n**Limitations:**")
                lines.extend([f"- {l}" for l in lims])
            return lines

        if ct == ContentType.RECOMMENDATION:
            lines = []
            for r in c.get("recommendations", []):
                lines.append(f"### [{r.get('priority','?')}] {r.get('title','—')}")
                lines.append(f"_{r.get('domain','—')} · {r.get('category','—')}_")
                lines.append(f"\n{r.get('description','—')}")
                lines.append(f"\n**Expected benefit:** {r.get('expected_benefit','—')}\n")
            return lines or ["_No recommendations._"]

        if ct == ContentType.STATISTICS:
            return [
                f"| Severity | Count |",
                f"|----------|-------|",
                f"| Critical | {c.get('critical', 0)} |",
                f"| High     | {c.get('high', 0)} |",
                f"| Medium   | {c.get('medium', 0)} |",
                f"| Low      | {c.get('low', 0)} |",
                f"| **Total**| **{c.get('total_risks', 0)}** |",
            ]

        if ct == ContentType.CHAIN:
            lines = []
            for chain in c.get("chains", []):
                lines.append(f"### Chain `{chain.get('chain_id','—')}`")
                lines.append(f"**Severity:** {chain.get('severity','—')} · **Confidence:** {chain.get('confidence', 0)}")
                for i, step in enumerate(chain.get("steps", []), 1):
                    lines.append(f"{i}. {step.get('description','—')} `{step.get('mitre','—')}`")
                lines.append("")
            return lines or ["_No chains._"]

        if ct == ContentType.TRACEABILITY:
            lines = []
            for entry in c.get("entries", []):
                lines.append(f"- **{entry.get('recommendation_id','—')}** ← `{entry.get('risk_assessment_id','—')}` ← `{entry.get('attack_chain_id','—')}`")
            return lines or ["_No traceability data._"]

        # TEXT fallback
        return [c.get("text", "_No content._")]
