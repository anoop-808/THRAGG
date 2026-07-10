/* ==========================================================================
   THRAGG — Finding Explorer
   ========================================================================== */

const THRAGG_FindingExplorer = {
  container: null,
  filters: { severity: 'ALL', type: 'ALL' },

  render(container) {
    if (!container) return;
    this.container = container;

    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('GLOBAL_FILTER_CHANGED', (filters) => {
        this.filters = filters;
        this._updateDOM();
      });
      THRAGG_EventBus.on('CONTEXT_CHANGED', (context) => {
        this._highlightContext(context);
      });
    }

    if (typeof THRAGG_GlobalSearch !== 'undefined') {
      this.filters = THRAGG_GlobalSearch.filters;
    }

    this._renderDOM();
  },

  _renderDOM() {
    const obs = THRAGG_DATA.executive_assessment?.observations || [];

    let html = `
      <div class="card">
        <div class="card-header">
          <div>
            <h3 style="margin:0;">Intelligence Findings</h3>
            <div style="font-size:var(--font-size-sm); color:var(--text-muted); margin-top:4px;">
              ${obs.length} findings require triage.
            </div>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="THRAGG_App.navigate('mitre')">View MITRE</button>
        </div>
        <div class="card-body" style="padding:var(--space-4); display:flex; flex-direction:column; gap:var(--space-3);" id="finding-explorer-list">
          ${this._buildListHTML(obs)}
        </div>
      </div>
    `;

    this.container.innerHTML = html;
    this._updateDOM();
  },

  _buildListHTML(obs) {
    return obs.map(o => {
      let color = 'var(--text-muted)';
      if (o.severity === 'CRITICAL') color = 'var(--status-critical)';
      if (o.severity === 'HIGH') color = 'var(--status-high)';
      if (o.severity === 'MEDIUM') color = 'var(--status-medium)';

      return `
        <div class="glass-card finding-item" data-severity="${o.severity}" style="padding:var(--space-4); cursor:pointer; transition:all 0.2s;" onclick="if(typeof THRAGG_InvestigationSession !== 'undefined') THRAGG_InvestigationSession.setContext('Finding', '${o.summary.substring(0, 30)}')">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:var(--space-3);">
            <div style="display:flex; align-items:center; gap:var(--space-3);">
              <div class="status-dot" style="background:${color};"></div>
              <span style="font-weight:var(--font-weight-bold);">${o.severity}</span>
            </div>
            <div style="font-size:var(--font-size-sm); color:var(--brand-primary); font-family:var(--font-mono);">
              ${o.mitre_tactics.join(', ')}
            </div>
          </div>
          <div style="font-size:var(--font-size-lg); color:var(--text-primary); margin-bottom:var(--space-2);">
            ${o.summary}
          </div>
        </div>
      `;
    }).join('');
  },

  _updateDOM() {
    if (!this.container) return;
    const items = this.container.querySelectorAll('.finding-item');
    
    items.forEach(item => {
      const sev = item.dataset.severity;
      let show = true;
      if (this.filters.severity !== 'ALL' && sev !== this.filters.severity) show = false;

      if (show) {
        item.style.display = 'block';
      } else {
        item.style.display = 'none';
      }
    });
  },

  _highlightContext(context) {
    if (!this.container) return;
    const items = this.container.querySelectorAll('.finding-item');
    items.forEach(item => {
      item.classList.remove('active', 'dimmed');
      if (context && context.type) {
         if ((context.type === 'Finding' || context.type === 'correlation') && item.textContent.includes(context.id)) {
           item.classList.add('active');
           item.scrollIntoView({ behavior: 'smooth', block: 'center' });
         } else {
           item.classList.add('dimmed');
         }
      }
    });
  }
};
