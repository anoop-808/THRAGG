/* ==========================================================================
   THRAGG — Report Composer
   Interactive UI for configuring the Executive Report.
   ========================================================================== */

const THRAGG_ReportComposer = {
  config: {
    title: 'Executive Incident Report',
    organization: 'Organization Confidential',
    classification: 'TLP:AMBER',
    analyst: 'Local Analyst',
    sections: [
      'executive_summary',
      'findings',
      'replay',
      'mitre',
      'recommendations',
      'investigation_notes',
      'investigation_timeline'
    ]
  },

  availableSections: [
    { id: 'executive_summary', label: 'Executive Summary', icon: '📝' },
    { id: 'findings', label: 'Key Findings', icon: '🎯' },
    { id: 'replay', label: 'Attack Replay Summary', icon: '🎬' },
    { id: 'mitre', label: 'MITRE ATT&CK Coverage', icon: '🛡️' },
    { id: 'recommendations', label: 'Recommendations', icon: '💡' },
    { id: 'investigation_notes', label: 'Analyst Notes', icon: '✍️' },
    { id: 'investigation_timeline', label: 'Investigation Timeline', icon: '⏱️' }
  ],

  render(container) {
    if (!container) return;

    // Prefill analyst from active case if possible
    if (typeof THRAGG_CaseManager !== 'undefined') {
      const active = THRAGG_CaseManager.getActiveCase();
      if (active && active.analyst) this.config.analyst = active.analyst;
    }

    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header" style="margin-bottom: var(--space-6);">
          <div class="page-title">Executive Report Builder</div>
          <div class="page-subtitle">Configure and export professional incident packages</div>
        </div>

        <div class="grid grid-2" style="gap: var(--space-6); align-items: start;">
          <!-- Configuration Column -->
          <div>
            <div class="card" style="margin-bottom: var(--space-6);">
              <div class="card-header"><h3 style="margin:0;">Report Configuration</h3></div>
              <div class="card-body" style="display:flex; flex-direction:column; gap:var(--space-4);">
                
                <div>
                  <label style="display:block; font-size:var(--font-size-sm); color:var(--text-muted); margin-bottom:4px;">Report Title</label>
                  <input type="text" id="rc-title" class="form-control" value="${this.config.title}" style="width:100%; padding:8px; border-radius:4px; background:rgba(255,255,255,0.05); border:1px solid var(--border); color:#fff;" onchange="THRAGG_ReportComposer.updateConfig('title', this.value)">
                </div>

                <div>
                  <label style="display:block; font-size:var(--font-size-sm); color:var(--text-muted); margin-bottom:4px;">Organization Name</label>
                  <input type="text" id="rc-org" class="form-control" value="${this.config.organization}" style="width:100%; padding:8px; border-radius:4px; background:rgba(255,255,255,0.05); border:1px solid var(--border); color:#fff;" onchange="THRAGG_ReportComposer.updateConfig('organization', this.value)">
                </div>

                <div style="display:grid; grid-template-columns:1fr 1fr; gap:var(--space-4);">
                  <div>
                    <label style="display:block; font-size:var(--font-size-sm); color:var(--text-muted); margin-bottom:4px;">Classification</label>
                    <select id="rc-class" class="form-control" style="width:100%; padding:8px; border-radius:4px; background:rgba(255,255,255,0.05); border:1px solid var(--border); color:#fff;" onchange="THRAGG_ReportComposer.updateConfig('classification', this.value)">
                      <option value="TLP:RED" ${this.config.classification==='TLP:RED'?'selected':''}>TLP:RED</option>
                      <option value="TLP:AMBER" ${this.config.classification==='TLP:AMBER'?'selected':''}>TLP:AMBER</option>
                      <option value="TLP:GREEN" ${this.config.classification==='TLP:GREEN'?'selected':''}>TLP:GREEN</option>
                      <option value="TLP:CLEAR" ${this.config.classification==='TLP:CLEAR'?'selected':''}>TLP:CLEAR</option>
                    </select>
                  </div>
                  <div>
                    <label style="display:block; font-size:var(--font-size-sm); color:var(--text-muted); margin-bottom:4px;">Analyst</label>
                    <input type="text" id="rc-analyst" class="form-control" value="${this.config.analyst}" style="width:100%; padding:8px; border-radius:4px; background:rgba(255,255,255,0.05); border:1px solid var(--border); color:#fff;" onchange="THRAGG_ReportComposer.updateConfig('analyst', this.value)">
                  </div>
                </div>

              </div>
            </div>

            <div class="card">
              <div class="card-header"><h3 style="margin:0;">Included Sections</h3></div>
              <div class="card-body">
                <p style="font-size:var(--font-size-sm); color:var(--text-muted); margin-bottom:var(--space-4);">Toggle sections. (Drag and drop reordering supported in subsequent update).</p>
                <div id="rc-sections" style="display:flex; flex-direction:column; gap:8px;">
                  ${this.availableSections.map(sec => `
                    <div style="display:flex; align-items:center; padding:8px 12px; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:4px; cursor:pointer;" onclick="THRAGG_ReportComposer.toggleSection('${sec.id}')">
                      <input type="checkbox" ${this.config.sections.includes(sec.id) ? 'checked' : ''} style="margin-right:12px; cursor:pointer;">
                      <span style="margin-right:8px;">${sec.icon}</span>
                      <span>${sec.label}</span>
                    </div>
                  `).join('')}
                </div>
              </div>
            </div>
          </div>

          <!-- Actions Column -->
          <div>
            <div class="card" style="margin-bottom: var(--space-6); background: linear-gradient(145deg, #121827, #0c101a); border-color: var(--brand-primary);">
              <div class="card-body" style="text-align:center; padding:var(--space-8) var(--space-4);">
                <div style="font-size:3rem; margin-bottom:var(--space-4);">📑</div>
                <h3 style="margin-bottom:var(--space-2);">Generate Incident Package</h3>
                <p style="color:var(--text-muted); font-size:var(--font-size-sm); margin-bottom:var(--space-6);">Export the finalized report to your preferred format based on the canonical active investigation data.</p>
                
                <div style="display:flex; flex-wrap:wrap; gap:var(--space-3); justify-content:center; margin-bottom:var(--space-6);">
                  <button class="btn btn-primary" onclick="THRAGG_ReportComposer.exportReport('HTML')" style="flex:1; min-width:120px;">Export HTML</button>
                  <button class="btn btn-secondary" onclick="THRAGG_ReportComposer.exportReport('MD')" style="flex:1; min-width:120px;">Export Markdown</button>
                  <button class="btn btn-secondary" onclick="THRAGG_ReportComposer.exportReport('JSON')" style="flex:1; min-width:120px;">Export JSON</button>
                </div>
                
                <button class="btn btn-secondary" style="width:100%; border-style:dashed;" onclick="THRAGG_App.navigate('report_preview')">
                  👁️ Preview HTML Layout
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  },

  updateConfig(key, value) {
    this.config[key] = value;
    if (typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('REPORT_UPDATED', this.config);
  },

  toggleSection(id) {
    if (this.config.sections.includes(id)) {
      this.config.sections = this.config.sections.filter(s => s !== id);
    } else {
      // maintain original order
      const newSections = [];
      this.availableSections.forEach(s => {
        if (s.id === id || this.config.sections.includes(s.id)) {
          newSections.push(s.id);
        }
      });
      this.config.sections = newSections;
    }
    
    // Re-render section list (cheap update)
    const list = document.getElementById('rc-sections');
    if (list) {
      list.innerHTML = this.availableSections.map(sec => `
        <div style="display:flex; align-items:center; padding:8px 12px; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:4px; cursor:pointer;" onclick="THRAGG_ReportComposer.toggleSection('${sec.id}')">
          <input type="checkbox" ${this.config.sections.includes(sec.id) ? 'checked' : ''} style="margin-right:12px; cursor:pointer;">
          <span style="margin-right:8px;">${sec.icon}</span>
          <span>${sec.label}</span>
        </div>
      `).join('');
    }
    if (typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('REPORT_UPDATED', this.config);
  },

  exportReport(format) {
    if (typeof THRAGG_ReportBuilder === 'undefined' || typeof THRAGG_ReportExporter === 'undefined') {
      alert("Reporting utilities not initialized.");
      return;
    }
    const model = THRAGG_ReportBuilder.buildCanonicalModel();
    THRAGG_ReportExporter.export(format, model, this.config);
  }
};
