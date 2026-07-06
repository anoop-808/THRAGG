/* ==========================================================================
   THRAGG — Activity Timeline Component
   ========================================================================== */

const THRAGG_ActivityTimeline = {
  /* ── Generate timeline events from data ────────────────────────────── */
  getEvents() {
    const events = [];

    // From attack chains
    (THRAGG_DATA.attack_chains || []).forEach((chain) => {
      events.push({
        time: chain.created_at,
        title: `Attack Chain: ${chain.title || chain.id}`,
        detail: `${chain.steps ? chain.steps.length : 0} steps · ${chain.severity}`,
        severity: chain.severity,
        type: 'chain'
      });
    });

    // From correlations
    (THRAGG_DATA.correlations || []).forEach((corr) => {
      events.push({
        time: corr.timestamp,
        title: `Correlation: ${corr.title}`,
        detail: `${corr.category} · ${corr.mitre.join(', ')}`,
        severity: corr.severity,
        type: 'correlation'
      });
    });

    // From risk assessments
    (THRAGG_DATA.risk_assessments || []).forEach((risk) => {
      events.push({
        time: risk.created_at,
        title: `Risk Assessment: ${risk.summary.substring(0, 60)}${risk.summary.length > 60 ? '...' : ''}`,
        detail: `Score: ${risk.score} · ${risk.risk_level}`,
        severity: risk.risk_level,
        type: 'risk'
      });
    });

    // Sort by time descending
    events.sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());

    return events.slice(0, 15);
  },

  render(container) {
    if (!container) return;
    const events = this.getEvents();

    if (!events.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-text">No recent activity.</div></div>';
      return;
    }

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0">Activity Timeline</span>
          <span class="badge badge-default">${events.length} events</span>
        </div>
        <div class="card-body">
          <div class="activity-timeline">
            ${events.map((ev, i) => `
              <div class="activity-item stagger-item" style="animation-delay: ${i * 30}ms">
                <div class="activity-dot ${(ev.severity || 'low').toLowerCase()}"></div>
                <div class="activity-time">${THRAGG_Charts.timeAgo(ev.time)}</div>
                <div class="activity-title">${ev.title}</div>
                <div class="activity-detail">${ev.detail}</div>
                <div style="margin-top: var(--space-1); display: flex; gap: var(--space-1);">
                  <span class="severity-label ${(ev.severity || 'info').toLowerCase()}">${ev.severity || 'INFO'}</span>
                  <span class="tag">${ev.type}</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }
};
