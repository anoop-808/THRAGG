/* ==========================================================================
   THRAGG — KPI Cards Component
   ========================================================================== */

const THRAGG_KPICards = {
  render(container) {
    if (!container) return;
    const assessment = THRAGG_DATA.executive_assessment;
    const snapshot = THRAGG_DATA.framework_snapshot;
    const stats = assessment.statistics;

    const kpis = [
      { label: 'Total Findings', value: snapshot.finding_count, icon: '🔍', color: '#6c5ce7', trend: null },
      { label: 'Active Risks', value: stats ? stats.total_correlations : 0, icon: '⚡', color: '#f97316', trend: 'up', trendLabel: '+3 new' },
      { label: 'Attack Chains', value: stats ? stats.total_attack_chains : 0, icon: '🔗', color: '#00d2ff', trend: null },
      { label: 'Entities', value: snapshot.resolved_entity_count, icon: '📦', color: '#22c55e', trend: null },
      { label: 'Relationships', value: snapshot.relationship_count, icon: '🔀', color: '#eab308', trend: null },
      { label: 'Posture Score', value: assessment.top_risks.reduce((max, r) => Math.max(max, r.score), 0), icon: '🎯', color: '#3b82f6', trend: 'down', trendLabel: '-5 pts' }
    ];

    container.innerHTML = kpis.map((kpi, i) => `
      <div class="kpi-card" style="animation-delay: ${i * 60}ms">
        <div class="kpi-icon" style="background: ${kpi.color}15; color: ${kpi.color}">
          ${kpi.icon}
        </div>
        <div class="kpi-label">${kpi.label}</div>
        <div class="kpi-value" data-count="${kpi.value}" style="color: ${kpi.color}">
          ${kpi.value}
        </div>
        ${kpi.trend ? `
          <div class="kpi-trend ${kpi.trend}">
            <span>${kpi.trend === 'up' ? '↑' : '↓'}</span>
            <span>${kpi.trendLabel}</span>
          </div>
        ` : ''}
      </div>
    `).join('');

    // Animate counters
    container.querySelectorAll('.kpi-value[data-count]').forEach((el) => {
      const target = parseInt(el.dataset.count);
      THRAGG_Animations.countUp(el, target, 800);
    });
  }
};
