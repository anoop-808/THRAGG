"""
core.reporting.renderers.html_renderer
=======================================
Renders a Report to an HTML string.
Returns str. Never writes files.
"""

from __future__ import annotations

from html import escape

from ..report import Report
from ..section import Section, ContentType

_CSS = """
<style>
  body{font-family:'Segoe UI',sans-serif;background:#0a0c0f;color:#c9d8e8;margin:0;padding:24px}
  h1{color:#00ff88;font-size:22px;border-bottom:1px solid #1e2a35;padding-bottom:12px}
  h2{color:#00cc6a;font-size:16px;margin-top:32px;border-left:3px solid #00ff88;padding-left:10px}
  h3{color:#44aaff;font-size:14px}
  table{border-collapse:collapse;width:100%;margin:12px 0}
  th{background:#0f1318;color:#5a7080;font-size:11px;letter-spacing:1px;padding:8px 12px;text-align:left;border-bottom:1px solid #1e2a35}
  td{padding:8px 12px;border-bottom:1px solid #151b22;font-size:13px}
  tr:hover td{background:#151b22}
  .kpi{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin:12px 0}
  .kpi-card{background:#0f1318;border:1px solid #1e2a35;border-radius:4px;padding:14px}
  .kpi-label{font-size:10px;color:#5a7080;letter-spacing:2px;text-transform:uppercase}
  .kpi-value{font-size:24px;color:#00ff88;font-weight:700;margin-top:4px}
  ul{padding-left:20px;line-height:2}
  .badge{font-size:10px;padding:2px 8px;border-radius:2px}
  .CRITICAL{background:#ff446620;color:#ff4466;border:1px solid #ff4466}
  .HIGH{background:#ff994420;color:#ff9944;border:1px solid #ff9944}
  .MEDIUM{background:#ffcc4420;color:#ffcc44;border:1px solid #ffcc44}
  .LOW{background:#44aaff20;color:#44aaff;border:1px solid #44aaff}
  .trace{font-family:monospace;font-size:11px;background:#0f1318;padding:8px;border-radius:3px;margin:4px 0}
  footer{margin-top:40px;padding-top:12px;border-top:1px solid #1e2a35;font-size:11px;color:#5a7080}
</style>
"""


class HTMLRenderer:
    format = "html"
    content_type = "text/html"

    def render(self, report: Report) -> str:
        body_parts = [
            f"<h1>{escape(report.title)}</h1>",
            f"<p style='color:#5a7080;font-size:12px'>Generated: {report.generated_at} · THRAGG v{report.framework_version}</p>",
        ]

        for section in sorted(report.sections, key=lambda s: s.order):
            body_parts.append(f"<h2>{escape(section.title)}</h2>")
            body_parts.append(self._render_section(section))

        if report.traceability_appendix:
            body_parts.append("<h2>Traceability Appendix</h2>")
            for entry in report.traceability_appendix:
                body_parts.append(
                    f"<div class='trace'>"
                    f"<b>{entry.recommendation_id}</b> ← "
                    f"{entry.risk_assessment_id} ← "
                    f"{entry.attack_chain_id} ← "
                    f"{', '.join(entry.finding_ids) or '—'} ← "
                    f"{', '.join(entry.evidence_files) or '—'}"
                    f"</div>"
                )

        body_parts.append(
            f"<footer>THRAGG v{report.framework_version} · "
            f"Report ID: {report.id} · {report.generated_at}</footer>"
        )

        return (
            "<!DOCTYPE html><html lang='en'><head>"
            "<meta charset='UTF-8'>"
            f"<title>{escape(report.title)}</title>"
            f"{_CSS}"
            "</head><body>"
            + "\n".join(body_parts)
            + "</body></html>"
        )

    def _render_section(self, section: Section) -> str:
        ct = section.content_type
        c  = section.content

        if ct == ContentType.KPI:
            cards = ""
            for label, key in [
                ("Posture",  "posture_label"),
                ("Score",    "overall_score"),
                ("Level",    "risk_level"),
                ("Critical", "critical_count"),
                ("High",     "high_count"),
                ("Medium",   "medium_count"),
            ]:
                cards += f"<div class='kpi-card'><div class='kpi-label'>{label}</div><div class='kpi-value'>{c.get(key,'—')}</div></div>"
            return f"<div class='kpi'>{cards}</div>"

        if ct == ContentType.TABLE:
            cols = c.get("columns", [])
            rows = c.get("rows", [])
            if not cols:
                return "<p><em>No data.</em></p>"
            header = "<tr>" + "".join(f"<th>{col}</th>" for col in cols) + "</tr>"
            body_rows = ""
            for row in rows:
                level = str(row.get("level", "")).upper()
                cells = []
                for k in cols:
                    val = row.get(k.lower(), row.get(k, "—"))
                    if k.lower() == "level":
                        cells.append(f"<td><span class='badge {level}'>{escape(str(val))}</span></td>")
                    else:
                        cells.append(f"<td>{escape(str(val))}</td>")
                body_rows += "<tr>" + "".join(cells) + "</tr>"
            return f"<table><thead>{header}</thead><tbody>{body_rows}</tbody></table>"

        if ct == ContentType.LIST:
            items = c.get("items", [])
            lis = "".join(f"<li>{escape(str(item))}</li>" for item in items)
            return f"<ul>{lis}</ul>" if lis else "<p><em>No items.</em></p>"

        if ct == ContentType.SUMMARY:
            return (
                f"<p><b>Modules run:</b> {', '.join(c.get('modules_run', [])) or '—'}</p>"
                f"<p><b>Modules skipped:</b> {', '.join(c.get('modules_skipped', [])) or 'None'}</p>"
                f"<p><b>Evidence files:</b> {', '.join(c.get('evidence_files', [])) or '—'}</p>"
                f"<p><b>Assessed at:</b> {c.get('assessed_at','—')}</p>"
            )

        if ct == ContentType.RECOMMENDATION:
            parts = []
            for r in c.get("recommendations", []):
                lvl = str(r.get("priority", "")).upper()
                parts.append(
                    f"<h3><span class='badge {lvl}'>{r.get('priority','—')}</span> {r.get('title','—')}</h3>"
                    f"<p><em>{r.get('domain','—')} · {r.get('category','—')}</em></p>"
                    f"<p>{r.get('description','—')}</p>"
                    f"<p><b>Expected benefit:</b> {r.get('expected_benefit','—')}</p>"
                )
            return "".join(parts) or "<p><em>No recommendations.</em></p>"

        if ct == ContentType.STATISTICS:
            rows = "".join(
                f"<tr><td>{sev}</td><td>{c.get(sev.lower(),0)}</td></tr>"
                for sev in ["Critical", "High", "Medium", "Low"]
            )
            total = f"<tr><td><b>Total</b></td><td><b>{c.get('total_risks',0)}</b></td></tr>"
            return f"<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{rows}{total}</tbody></table>"

        if ct == ContentType.CHAIN:
            parts = []
            for chain in c.get("chains", []):
                steps = "".join(
                    f"<li>{s.get('description','—')} <code>{s.get('mitre','—')}</code></li>"
                    for s in chain.get("steps", [])
                )
                parts.append(
                    f"<h3>Chain <code>{chain.get('chain_id','—')}</code></h3>"
                    f"<p>Severity: <b>{chain.get('severity','—')}</b> · Confidence: {chain.get('confidence',0)}</p>"
                    f"<ol>{steps}</ol>"
                )
            return "".join(parts) or "<p><em>No chains.</em></p>"

        if ct == ContentType.TRACEABILITY:
            items = "".join(
                f"<div class='trace'><b>{e.get('recommendation_id','—')}</b> ← "
                f"<code>{e.get('risk_assessment_id','—')}</code> ← "
                f"<code>{e.get('attack_chain_id','—')}</code></div>"
                for e in c.get("entries", [])
            )
            return items or "<p><em>No traceability data.</em></p>"

        return f"<p>{escape(str(c.get('text', 'No content.')))}</p>"
