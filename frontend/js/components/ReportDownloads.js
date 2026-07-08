/* ==========================================================================
   THRAGG — Report Downloads Component
   ========================================================================== */

const THRAGG_ReportDownloads = {
  reports: [
    { format: 'PDF', icon: '📄', desc: 'Executive Report', size: '2.4 MB', color: '#ef4444', file: 'executive_report.pdf' },
    { format: 'HTML', icon: '🌐', desc: 'Full Dashboard Export', size: '4.8 MB', color: '#f97316', file: 'dashboard_export.html' },
    { format: 'MD', icon: '📝', desc: 'Markdown Summary', size: '180 KB', color: '#3b82f6', file: 'summary.md' },
    { format: 'JSON', icon: '📊', desc: 'Raw Intelligence Data', size: '1.2 MB', color: '#22c55e', file: 'session_data.json' },
    { format: 'CSV', icon: '📋', desc: 'Findings & Risks', size: '340 KB', color: '#6c5ce7', file: 'findings.csv' },
    { format: 'ZIP', icon: '📦', desc: 'Complete Evidence Package', size: '12.6 MB', color: '#eab308', file: 'evidence_package.zip' }
  ],

  render(container) {
    if (!container) return;

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0">Report Downloads</span>
          <span class="badge badge-info">${this.reports.length} formats</span>
        </div>
        <div class="card-body">
          <div class="download-grid">
            ${this.reports.map((r, i) => `
              <div class="download-card stagger-item" style="animation-delay: ${i * 50}ms" onclick="window.location.href = '/api/download/' + window.THRAGG_SESSION_ID + '/' + '${r.file}'">
                <div class="download-card-icon">${r.icon}</div>
                <div class="download-card-title" style="color: ${r.color}">${r.format}</div>
                <div style="font-size: var(--font-size-xs); color: var(--text-secondary); margin-top: var(--space-1);">${r.desc}</div>
                <div class="download-card-size">${r.size}</div>
                <div style="margin-top: var(--space-3);">
                  <button class="btn btn-secondary btn-sm" style="width:100%">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    Download
                  </button>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }
};
