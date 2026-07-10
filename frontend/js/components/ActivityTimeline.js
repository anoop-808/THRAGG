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

  _listenerAttached: false,

  render(container) {
    if (!container) return;
    const events = this.getEvents();

    if (!this._listenerAttached && typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('CONTEXT_CHANGED', (context) => this._highlightContext(context, container));
      THRAGG_EventBus.on('REPLAY_STEP_CHANGED', (data) => {
        if (data && data.step) this._highlightReplay(data.step, container);
      });
      THRAGG_EventBus.on('REPLAY_STOPPED', () => this._highlightContext(null, container));
      this._listenerAttached = true;
    }

    if (!events.length) {
      container.innerHTML = `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin-bottom: var(--space-4);">
            <circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline>
          </svg>
          <div class="empty-state-title" style="font-size: var(--font-size-lg); font-weight: var(--font-weight-semibold); color: var(--text-primary); margin-bottom: var(--space-2);">No Recent Activity</div>
          <div class="empty-state-text" style="color: var(--text-secondary); max-width: 400px; text-align: center;">
            No significant correlations or intelligence events have been logged recently.
          </div>
        </div>
      `;
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
              <div class="activity-item stagger-item" style="animation-delay: ${i * 30}ms; cursor: pointer; transition: all 0.2s; border-radius: var(--radius-md);" 
                   onclick="if(typeof THRAGG_InvestigationSession !== 'undefined') THRAGG_InvestigationSession.setContext(
                     '${ev.type === 'chain' ? 'Attack Chain' : ev.type === 'correlation' ? 'Correlation' : ev.type === 'risk' ? 'Finding' : 'Finding'}', 
                     '${ev.title.includes(': ') ? ev.title.split(': ')[1] : ev.title}'
                   );"
                   onmouseover="this.style.background='var(--bg-glass-hover)'" onmouseout="this.style.background='transparent'">
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
  },

  _highlightContext(context, container) {
    if (!container) return;
    const items = container.querySelectorAll('.activity-item');
    items.forEach(item => {
      item.classList.remove('active', 'dimmed', 'completed');
      if (context && context.type) {
        if (item.innerHTML.includes(context.id) || (context.type === 'Timeline' && item.innerHTML.includes(context.id))) {
           item.classList.add('active');
           item.scrollIntoView({ behavior: 'smooth', block: 'center' });
        } else {
           item.classList.add('dimmed');
        }
      }
    });
  },

  _highlightReplay(step, container) {
    if (!container) return;
    const items = container.querySelectorAll('.activity-item');
    
    // We try to match by checking if the item time is close, or if the title contains the source_id
    items.forEach(item => {
      item.classList.remove('active', 'dimmed', 'completed');
      
      const timeStr = THRAGG_Charts.timeAgo(step.timestamp); // Not exact but close enough for visual
      
      if (item.innerHTML.includes(step.source_id) || item.innerHTML.includes(step.title)) {
        item.classList.add('active');
        item.scrollIntoView({ behavior: 'smooth', block: 'center' });
      } else {
        item.classList.add('dimmed');
      }
    });
  }
};
