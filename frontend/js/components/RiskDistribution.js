/* ==========================================================================
   THRAGG — Risk Distribution Component
   ========================================================================== */

const THRAGG_RiskDistribution = {
  render(container) {
    if (!container) return;
    const assessment = THRAGG_DATA.executive_assessment;
    const riskCounts = assessment.statistics ? assessment.statistics.risk_counts : [];

    if (!riskCounts.length) {
      container.innerHTML = `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin-bottom: var(--space-4);">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
          <div class="empty-state-title" style="font-size: var(--font-size-lg); font-weight: var(--font-weight-semibold); color: var(--text-primary); margin-bottom: var(--space-2);">No Risks Identified</div>
          <div class="empty-state-text" style="color: var(--text-secondary); max-width: 400px; text-align: center;">
            The intelligence engine did not identify any immediate risks or vulnerabilities within the current dataset scope.
          </div>
        </div>
      `;
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
                      <span class="risk-bar-count" data-count="${r.count}" style="${pct < 15 ? 'display:none' : ''}">0</span>
                    </div>
                  </div>
                  <span class="risk-bar-percent" data-pct="${pct}">0%</span>
                </div>
              `;
            }).join('')}
          </div>
          <div style="margin-top: var(--space-5); display: flex; gap: var(--space-6); justify-content: center;">
            <div class="scope-card-item" style="border: none; gap: var(--space-2);">
              <span class="scope-label">Average Score</span>
              <span class="scope-value" data-count="${assessment.top_risks.length ? Math.round(assessment.top_risks.reduce((s, r) => s + r.score, 0) / assessment.top_risks.length) : 0}">0</span>
            </div>
            <div class="scope-card-item" style="border: none; gap: var(--space-2);">
              <span class="scope-label">Highest Risk</span>
              <span class="severity-label ${assessment.top_risks[0]?.risk_level.toLowerCase() || 'low'}">${assessment.top_risks[0]?.risk_level || 'N/A'}</span>
            </div>
            <div class="scope-card-item" style="border: none; gap: var(--space-2);">
              <span class="scope-label">Risk Chains</span>
              <span class="scope-value" data-count="${assessment.observations.length}">0</span>
            </div>
          </div>
        </div>
      </div>
    `;

    // Animate bars and counters after render
    requestAnimationFrame(() => {
      container.querySelectorAll('.risk-bar-fill').forEach((bar) => {
        const pct = parseInt(bar.dataset.pct);
        THRAGG_Animations.animateProgressBar(bar, pct, 1200);
      });
      container.querySelectorAll('.risk-bar-count[data-count], .scope-value[data-count]').forEach((el) => {
        const target = parseInt(el.dataset.count);
        THRAGG_Animations.countUp(el, target, 1200);
      });
      container.querySelectorAll('.risk-bar-percent[data-pct]').forEach((el) => {
        const target = parseInt(el.dataset.pct);
        THRAGG_Animations.countUp(el, target, 1200, '', '%');
      });
    });
  }
};
