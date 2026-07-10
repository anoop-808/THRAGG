/* ==========================================================================
   THRAGG — Report Template
   Handles presentation generation from the Canonical Report Model.
   ========================================================================== */

const THRAGG_ReportTemplate = {
  /* ── HTML Generator ──────────────────────────────────────────────────── */
  generateHTML(model, config) {
    const sections = config.sections || [];
    let html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${config.title || 'Incident Report'} - ${model.metadata.report_id}</title>
  <style>
    :root {
      --bg: #070b14; --text: #e2e8f0; --muted: #94a3b8; 
      --brand: #6c5ce7; --card-bg: #121827; --border: #1e293b;
      --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #3b82f6;
    }
    body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; padding: 2rem; }
    h1, h2, h3 { color: #fff; margin-top: 1.5em; }
    .report-container { max-width: 900px; margin: 0 auto; background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 3rem; }
    .cover-page { text-align: center; margin-bottom: 4rem; padding-bottom: 2rem; border-bottom: 2px solid var(--border); }
    .cover-title { font-size: 2.5rem; margin-bottom: 0.5rem; color: var(--brand); }
    .metadata-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 2rem; text-align: left; background: #0c101a; padding: 1.5rem; border-radius: 8px; }
    .meta-item { display: flex; flex-direction: column; }
    .meta-label { font-size: 0.75rem; text-transform: uppercase; color: var(--muted); letter-spacing: 0.05em; }
    .meta-value { font-weight: 600; }
    .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 99px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .badge.critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge.high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    .badge.medium { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    
    .section-block { margin-bottom: 3rem; page-break-inside: avoid; }
    .section-title { border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 1.5rem; font-size: 1.5rem; color: #fff; }
    
    .card { background: #0c101a; border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
    .card-title { font-weight: 600; color: #fff; margin-bottom: 0.5rem; display: flex; justify-content: space-between; }
    .mitre-tag { display: inline-block; background: rgba(108, 92, 231, 0.2); color: var(--brand); padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.8rem; margin-right: 0.4rem; font-family: monospace; }
    
    ul, ol { padding-left: 1.5rem; }
    li { margin-bottom: 0.5rem; }
    
    @media print {
      body { background: #fff; color: #000; }
      .report-container { border: none; padding: 0; box-shadow: none; background: #fff; }
      h1, h2, h3, .card-title, .section-title, .cover-title { color: #000; }
      .card, .metadata-grid { background: #f8fafc; border-color: #e2e8f0; }
      :root { --border: #cbd5e1; --muted: #64748b; }
      .badge { border-width: 2px; }
    }
  </style>
</head>
<body>
  <div class="report-container">
    <div class="cover-page">
      <div class="cover-title">${config.title || 'Incident Report'}</div>
      <div style="color: var(--muted); font-size: 1.2rem;">${config.organization || 'Organization Confidential'}</div>
      
      <div class="metadata-grid">
        <div class="meta-item"><span class="meta-label">Report ID</span><span class="meta-value" style="font-family: monospace;">${model.metadata.report_id}</span></div>
        <div class="meta-item"><span class="meta-label">Generated At</span><span class="meta-value">${new Date(model.metadata.generated_at).toLocaleString()}</span></div>
        <div class="meta-item"><span class="meta-label">Analyst</span><span class="meta-value">${config.analyst || model.metadata.analyst}</span></div>
        <div class="meta-item"><span class="meta-label">Classification</span><span class="meta-value">${config.classification || 'TLP:AMBER'}</span></div>
        <div class="meta-item"><span class="meta-label">Severity</span><span class="meta-value"><span class="badge ${model.metadata.severity.toLowerCase()}">${model.metadata.severity}</span></span></div>
        <div class="meta-item"><span class="meta-label">Case Status</span><span class="meta-value">${model.metadata.case_status}</span></div>
      </div>
    </div>
    
    <div class="report-body">
    `;

    // Process each section based on user configuration
    sections.forEach(secId => {
      if (secId === 'executive_summary') html += this._renderHTMLExecutiveSummary(model);
      if (secId === 'findings') html += this._renderHTMLFindings(model);
      if (secId === 'replay') html += this._renderHTMLReplay(model);
      if (secId === 'mitre') html += this._renderHTMLMitre(model);
      if (secId === 'recommendations') html += this._renderHTMLRecommendations(model);
      if (secId === 'investigation_notes') html += this._renderHTMLNotes(model);
      if (secId === 'investigation_timeline') html += this._renderHTMLTimeline(model);
    });

    html += `
    </div>
  </div>
</body>
</html>
    `;
    return html;
  },

  _renderHTMLExecutiveSummary(model) {
    if (!model.executive_summary) return '';
    return `
      <div class="section-block">
        <h2 class="section-title">Executive Summary</h2>
        <div class="card">
          <p>${model.executive_summary.summary}</p>
          <div style="margin-top: 1rem;">
            <strong>Security Posture Score:</strong> ${model.executive_summary.posture_score} / 100
          </div>
        </div>
      </div>
    `;
  },

  _renderHTMLFindings(model) {
    if (!model.findings || model.findings.length === 0) return '';
    const sorted = [...model.findings].sort((a,b) => {
      const v = {CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1};
      return (v[b.severity] || 0) - (v[a.severity] || 0);
    });
    
    let html = `<div class="section-block"><h2 class="section-title">Key Findings</h2>`;
    sorted.forEach(f => {
      html += `
        <div class="card">
          <div class="card-title">
            <span>${f.category}</span>
            <span class="badge ${f.severity.toLowerCase()}">${f.severity}</span>
          </div>
          <p style="margin-top:0.5rem;">${f.summary}</p>
          ${f.mitre && f.mitre.length ? `<div style="margin-top:1rem;">${f.mitre.map(m => `<span class="mitre-tag">${m}</span>`).join('')}</div>` : ''}
        </div>
      `;
    });
    html += `</div>`;
    return html;
  },

  _renderHTMLReplay(model) {
    if (!model.replay || model.replay.steps.length === 0) return '';
    let html = `
      <div class="section-block">
        <h2 class="section-title">Attack Progression (Replay Summary)</h2>
        <p style="color:var(--muted); margin-bottom: 1rem;">Chronological reconstruction based on ${model.replay.total_steps} extracted stages.</p>
        <div style="border-left: 2px solid var(--border); padding-left: 1.5rem; margin-left: 0.5rem;">
    `;
    model.replay.steps.forEach((s, idx) => {
      html += `
        <div style="position: relative; margin-bottom: 1.5rem;">
          <div style="position: absolute; left: -1.9rem; top: 0.2rem; width: 0.6rem; height: 0.6rem; border-radius: 50%; background: var(--brand); border: 4px solid var(--card-bg);"></div>
          <div style="font-size: 0.8rem; color: var(--muted); font-family: monospace;">Stage ${idx+1} · ${new Date(s.timestamp).toLocaleTimeString()}</div>
          <div style="font-weight: 600; color: #fff; margin: 0.2rem 0;">${s.stage}</div>
          ${s.mitre && s.mitre.length ? `<div style="margin-bottom:0.5rem;">${s.mitre.map(m => `<span class="mitre-tag">${m}</span>`).join('')}</div>` : ''}
          <div style="font-size: 0.9rem; color: var(--muted);">${s.description || `${s.source} ➔ ${s.target}`}</div>
        </div>
      `;
    });
    html += `</div></div>`;
    return html;
  },

  _renderHTMLMitre(model) {
    if (!model.mitre || model.mitre.length === 0) return '';
    return `
      <div class="section-block">
        <h2 class="section-title">MITRE ATT&CK® Coverage</h2>
        <div class="card">
          <div style="display:flex; flex-wrap:wrap; gap:0.5rem;">
            ${model.mitre.map(m => `<span class="mitre-tag">${m.technique} <span style="opacity:0.6">(${m.count})</span></span>`).join('')}
          </div>
        </div>
      </div>
    `;
  },

  _renderHTMLRecommendations(model) {
    if (!model.recommendations || model.recommendations.length === 0) return '';
    let html = `<div class="section-block"><h2 class="section-title">Recommendations</h2>`;
    model.recommendations.forEach(r => {
      html += `
        <div class="card">
          <div class="card-title">
            <span>${r.title}</span>
            <span class="badge ${r.priority.toLowerCase()}">Priority: ${r.priority}</span>
          </div>
          <p style="margin-top:0.5rem;">${r.description}</p>
          <div style="margin-top:0.5rem; font-size: 0.8rem; color: var(--muted);">Estimated Effort: ${r.effort}</div>
        </div>
      `;
    });
    html += `</div>`;
    return html;
  },

  _renderHTMLNotes(model) {
    if (!model.investigation.notes || model.investigation.notes.length === 0) return '';
    let html = `<div class="section-block"><h2 class="section-title">Analyst Notes</h2>`;
    model.investigation.notes.forEach(n => {
      html += `
        <div class="card" style="border-left: 4px solid var(--brand);">
          <div style="font-size:0.8rem; color:var(--muted); margin-bottom:0.5rem;">
            ${new Date(n.timestamp).toLocaleString()} · ${n.author}
            ${n.related_object_id ? `· Ref: <span style="font-family:monospace">${n.related_object_id}</span>` : ''}
          </div>
          <div>${n.content.replace(/\n/g, '<br>')}</div>
        </div>
      `;
    });
    html += `</div>`;
    return html;
  },

  _renderHTMLTimeline(model) {
    if (!model.timeline || model.timeline.length === 0) return '';
    let html = `
      <div class="section-block">
        <h2 class="section-title">Investigation Action Timeline</h2>
        <div class="card">
          <table style="width:100%; border-collapse:collapse; text-align:left; font-size:0.9rem;">
            <thead>
              <tr style="border-bottom:1px solid var(--border);">
                <th style="padding:0.5rem; color:var(--muted);">Timestamp</th>
                <th style="padding:0.5rem; color:var(--muted);">Action</th>
                <th style="padding:0.5rem; color:var(--muted);">Details</th>
              </tr>
            </thead>
            <tbody>
    `;
    model.timeline.forEach(t => {
      html += `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
          <td style="padding:0.5rem; white-space:nowrap; font-family:monospace; color:var(--muted);">${new Date(t.timestamp).toLocaleTimeString()}</td>
          <td style="padding:0.5rem; font-weight:600;">${t.action}</td>
          <td style="padding:0.5rem; color:var(--text);">${t.details}</td>
        </tr>
      `;
    });
    html += `</tbody></table></div></div>`;
    return html;
  },

  /* ── Markdown Generator ──────────────────────────────────────────────── */
  generateMarkdown(model, config) {
    const sections = config.sections || [];
    let md = `# ${config.title || 'Incident Report'} - ${model.metadata.report_id}\n`;
    md += `**Organization:** ${config.organization || 'Organization Confidential'}\n`;
    md += `**Classification:** ${config.classification || 'TLP:AMBER'}\n`;
    md += `**Generated At:** ${new Date(model.metadata.generated_at).toLocaleString()}\n`;
    md += `**Analyst:** ${config.analyst || model.metadata.analyst}\n`;
    md += `**Severity:** ${model.metadata.severity}\n`;
    md += `**Case Status:** ${model.metadata.case_status}\n\n---\n\n`;

    sections.forEach(secId => {
      if (secId === 'executive_summary') {
        md += `## Executive Summary\n${model.executive_summary?.summary}\n\n`;
        md += `**Security Posture Score:** ${model.executive_summary?.posture_score} / 100\n\n`;
      }
      if (secId === 'findings') {
        md += `## Key Findings\n`;
        model.findings.forEach(f => {
          md += `### ${f.category} [${f.severity}]\n${f.summary}\n`;
          if (f.mitre && f.mitre.length) md += `*MITRE:* ${f.mitre.join(', ')}\n`;
          md += `\n`;
        });
      }
      if (secId === 'replay' && model.replay?.steps.length) {
        md += `## Attack Progression (Replay Summary)\n`;
        model.replay.steps.forEach((s, i) => {
          md += `**Stage ${i+1}: ${s.stage}** (${new Date(s.timestamp).toLocaleTimeString()})\n`;
          if (s.mitre && s.mitre.length) md += `*MITRE:* ${s.mitre.join(', ')}\n`;
          md += `> ${s.description || s.source + ' -> ' + s.target}\n\n`;
        });
      }
      if (secId === 'recommendations') {
        md += `## Recommendations\n`;
        model.recommendations.forEach(r => {
          md += `### ${r.title} [Priority: ${r.priority}]\n${r.description}\n*Effort:* ${r.effort}\n\n`;
        });
      }
      if (secId === 'investigation_notes' && model.investigation?.notes.length) {
        md += `## Analyst Notes\n`;
        model.investigation.notes.forEach(n => {
          md += `> **${new Date(n.timestamp).toLocaleString()} - ${n.author}**\n> ${n.content.replace(/\n/g, '\n> ')}\n\n`;
        });
      }
    });

    return md;
  },

  /* ── Plain Text Generator ────────────────────────────────────────────── */
  generateTXT(model, config) {
    const md = this.generateMarkdown(model, config);
    // Extremely rudimentary strip:
    return md.replace(/#/g, '').replace(/\*/g, '').replace(/> /g, '    ');
  }
};
