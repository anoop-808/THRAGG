/* ==========================================================================
   THRAGG — Risk Distribution Component
   ========================================================================== */

const THRAGG_RiskDistribution = {
  render(container) {
    if (!container) return;
    const assessment = THRAGG_DATA.executive_assessment;
    const riskCounts = assessment.statistics ? assessment.statistics.risk_counts : [];

    if (!riskCounts.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-text">No risk data available.</div></div>';
      return;
    }

    const total = riskCounts.reduce((s, r) => s + r.count, 0) || 1;
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const sorted = severityOrder.map(s => riskCounts.find(r => r.name === s)).filter(Boolean);

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0">Risk Distribution</span>
          <span class="badge badge-default">${total} total</span>
        </div>
        <div class="card-body">
          <div class="risk-distribution-chart" id="risk-bars">
            ${sorted.map((r, i) => {
              const pct = total > 0 ? Math.round((r.count / total) * 100) : 0;
              return `
                <div class="risk-bar-row">
                  <span class="risk-bar-label">${r.name}</span>
                  <div class="risk-bar-track">
                    <div class="risk-bar-fill ${r.name.toLowerCase()}"
                         data-pct="${pct}"
                         style="width:0%">
                      <span class="risk-bar-count" style="${pct < 15 ? 'display:none' : ''}">${r.count}</span>
                    </div>
                  </div>
                  <span class="risk-bar-percent">${pct}%</span>
                </div>
              `;
            }).join('')}
          </div>
          <div style="margin-top: var(--space-5); display: flex; gap: var(--space-6); justify-content: center;">
            <div class="scope-card-item" style="border: none; gap: var(--space-2);">
              <span class="scope-label">Average Score</span>
              <span class="scope-value">${assessment.top_risks.length ? Math.round(assessment.top_risks.reduce((s, r) => s + r.score, 0) / assessment.top_risks.length) : 0}</span>
            </div>
            <div class="scope-card-item" style="border: none; gap: var(--space-2);">
              <span class="scope-label">Highest Risk</span>
              <span class="severity-label ${assessment.top_risks[0]?.risk_level.toLowerCase() || 'low'}">${assessment.top_risks[0]?.risk_level || 'N/A'}</span>
            </div>
            <div class="scope-card-item" style="border: none; gap: var(--space-2);">
              <span class="scope-label">Risk Chains</span>
              <span class="scope-value">${assessment.observations.length}</span>
            </div>
          </div>
        </div>
      </div>
    `;

    // Animate bars after render
    requestAnimationFrame(() => {
      container.querySelectorAll('.risk-bar-fill').forEach((bar) => {
        const pct = parseInt(bar.dataset.pct);
        THRAGG_Animations.animateProgressBar(bar, pct, 1200);
      });
    });
  }
};
