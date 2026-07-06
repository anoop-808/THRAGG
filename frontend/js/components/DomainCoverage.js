/* ==========================================================================
   THRAGG — Domain Coverage Component
   ========================================================================== */

const THRAGG_DomainCoverage = {
  domains: [
    { id: 'network', label: 'Network', icon: '🌐', color: '#00d2ff', bgColor: 'rgba(0, 210, 255, 0.1)', findings: 12, issues: 5, status: 'warning' },
    { id: 'cloud', label: 'Cloud', icon: '☁️', color: '#6c5ce7', bgColor: 'rgba(108, 92, 231, 0.1)', findings: 8, issues: 3, status: 'warning' },
    { id: 'identity', label: 'Identity', icon: '🔑', color: '#f97316', bgColor: 'rgba(249, 115, 22, 0.1)', findings: 10, issues: 4, status: 'warning' },
    { id: 'web', label: 'Web', icon: '🌍', color: '#22c55e', bgColor: 'rgba(34, 197, 94, 0.1)', findings: 7, issues: 2, status: 'active' },
    { id: 'logs', label: 'Logs', icon: '📋', color: '#eab308', bgColor: 'rgba(234, 179, 8, 0.1)', findings: 10, issues: 1, status: 'active' }
  ],

  render(container) {
    if (!container) return;

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0">Domain Coverage</span>
          <span class="badge badge-info">${this.domains.length} domains</span>
        </div>
        <div class="card-body">
          <div class="domain-grid">
            ${this.domains.map((d, i) => `
              <div class="domain-card stagger-item" style="animation-delay: ${i * 60}ms">
                <div class="domain-card-icon" style="background: ${d.bgColor}">
                  <span style="font-size: 20px;">${d.icon}</span>
                </div>
                <div class="domain-card-name" style="color: ${d.color}">${d.label}</div>
                <div class="domain-card-count" style="color: ${d.color}">${d.issues}</div>
                <div class="domain-card-status">
                  Issues Found
                  <span class="status-dot ${d.status}" style="vertical-align: middle; margin-left: 4px;"></span>
                </div>
                <div style="margin-top: var(--space-2); font-size: 10px; color: var(--text-muted);">
                  ${d.findings} total findings
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }
};
