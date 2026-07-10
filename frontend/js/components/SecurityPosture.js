/* ==========================================================================
   THRAGG — Security Posture Component
   ========================================================================== */

const THRAGG_SecurityPosture = {
  render(container) {
    if (!container) return;
    const assessment = THRAGG_DATA.executive_assessment;
    const posture = assessment.security_posture;
    const color = THRAGG_Charts.severityColor(posture);
    const stats = assessment.statistics;
    const riskCounts = stats ? stats.risk_counts : [];

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0">Security Posture</span>
          <span class="severity-label ${posture.toLowerCase()}">${posture}</span>
        </div>
        <div class="card-body">
          <div style="display:flex; gap: var(--space-8); align-items: center;">
            <div style="flex-shrink:0; position: relative;">
              <canvas id="posture-donut" width="140" height="140"></canvas>
            </div>
            <div style="flex:1; min-width: 0;">
              <div class="card-value ${posture.toLowerCase()}" style="font-size:var(--font-size-3xl); margin-bottom: var(--space-2);">
                ${posture}
              </div>
              <p style="font-size: var(--font-size-sm); color: var(--text-secondary); line-height: 1.6; margin-bottom: var(--space-3);">
                ${assessment.overall_summary}
              </p>
              <div style="display: flex; gap: var(--space-4); flex-wrap: wrap;">
                ${riskCounts.map(r => `
                  <div>
                    <div class="metric-label">${r.name}</div>
                    <div class="metric-value" data-count="${r.count}" style="color: ${THRAGG_Charts.severityColor(r.name)}; font-size: var(--font-size-lg);">
                      0
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Render donut chart
    requestAnimationFrame(() => {
      const canvas = document.getElementById('posture-donut');
      if (canvas) {
        const segments = riskCounts.length > 0 ? riskCounts.map(r => ({
          count: r.count,
          color: THRAGG_Charts.severityColor(r.name)
        })) : [{ count: 1, color: '#64748b' }];
        THRAGG_Charts.donut(canvas, segments, 140);
      }

      // Animate risk count numbers
      container.querySelectorAll('.metric-value[data-count]').forEach((el) => {
        const target = parseInt(el.dataset.count);
        THRAGG_Animations.countUp(el, target, 800);
      });
    });
  }
};
