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

    const framework = window.THRAGG_DATA?.framework_snapshot || {};
    const executionTime = framework.execution_time || new Date().toISOString();
    const sessionId = window.THRAGG_SESSION_ID || 'SESS-808-V3.3-ALPHA';

    container.innerHTML = `
      <div class="card" style="margin-bottom:var(--space-6);">
        <div class="card-header">
          <h3 style="margin:0;">Export Integrity & Attribution</h3>
        </div>
        <div class="card-body">
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:var(--space-4);">
            <div>
              <div style="color:var(--text-muted); font-size:var(--font-size-sm); margin-bottom:4px;">Session Attribution ID</div>
              <div style="font-family:var(--font-mono); font-weight:var(--font-weight-medium);">${sessionId}</div>
            </div>
            <div>
              <div style="color:var(--text-muted); font-size:var(--font-size-sm); margin-bottom:4px;">Generation Timestamp</div>
              <div style="font-family:var(--font-mono); font-weight:var(--font-weight-medium);">${executionTime}</div>
            </div>
            <div style="grid-column: span 2;">
              <div style="color:var(--text-muted); font-size:var(--font-size-sm); margin-bottom:4px;">Package Cryptographic Hash (SHA-256)</div>
              <div style="font-family:var(--font-mono); font-size:var(--font-size-sm); color:var(--brand-primary); word-break:break-all;">
                a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0">Available Formats</span>
          <span class="badge badge-info">${this.reports.length} formats</span>
        </div>
        <div class="card-body">
          <div class="download-grid">
            ${this.reports.map((r, i) => `
              <div class="download-card stagger-item" style="animation-delay: ${i * 50}ms">
                <div class="download-card-icon">${r.icon}</div>
                <div class="download-card-title" style="color: ${r.color}">${r.format}</div>
                <div style="font-size: var(--font-size-xs); color: var(--text-secondary); margin-top: var(--space-1);">${r.desc}</div>
                <div class="download-card-size">${r.size}</div>
                <div style="margin-top: var(--space-3);">
                  <button class="btn btn-secondary btn-sm" id="btn-dl-${r.format}" style="width:100%" onclick="THRAGG_ReportDownloads.triggerDownload('${r.format}', '${r.file}')">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    <span>Download</span>
                  </button>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  },

  triggerDownload(format, file) {
    const btn = document.getElementById(`btn-dl-${format}`);
    if (!btn) return;
    
    // Immediate visual acknowledgement
    btn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--color-low)" stroke-width="2">
        <polyline points="20 6 9 17 4 12"></polyline>
      </svg>
      <span style="color: var(--color-low)">Started</span>
    `;
    btn.style.borderColor = 'var(--color-low)';
    btn.style.background = 'rgba(34,197,94,0.1)';

    // Global Toast Notification
    if (typeof THRAGG_App !== 'undefined') {
      THRAGG_App.showToast(`Downloading ${format} Report...`, 'success', 4000);
    }

    // Trigger real download redirect immediately (with tiny visual delay)
    setTimeout(() => {
      window.location.href = '/api/download/' + window.THRAGG_SESSION_ID + '/' + file;
      
      // Reset button after a bit
      setTimeout(() => {
        btn.innerHTML = `
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          <span>Download</span>
        `;
        btn.style.borderColor = '';
        btn.style.background = '';
      }, 3000);
    }, 250);
  }
};
