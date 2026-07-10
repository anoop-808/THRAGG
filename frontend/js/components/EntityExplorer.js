/* ==========================================================================
   THRAGG — Entity Explorer
   ========================================================================== */

const THRAGG_EntityExplorer = {
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

    // Default filters
    if (typeof THRAGG_GlobalSearch !== 'undefined') {
      this.filters = THRAGG_GlobalSearch.filters;
    }

    this._renderDOM();
  },

  _renderDOM() {
    const entities = THRAGG_DATA.entities || [];
    
    let html = `
      <div class="card">
        <div class="card-header">
          <div>
            <h3 style="margin:0;">Normalized Entities</h3>
            <div style="font-size:var(--font-size-sm); color:var(--text-muted); margin-top:4px;">
              ${entities.length} total entities identified in this session.
            </div>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="THRAGG_App.navigate('graph')">View Graph</button>
        </div>
        <div class="card-body" style="padding:0;">
          <table style="width:100%; text-align:left; border-collapse:collapse;">
            <thead>
              <tr style="border-bottom:1px solid var(--border-glass);">
                <th style="padding:var(--space-4) var(--space-6); color:var(--text-secondary); font-weight:var(--font-weight-medium);">Entity ID</th>
                <th style="padding:var(--space-4) var(--space-6); color:var(--text-secondary); font-weight:var(--font-weight-medium);">Type</th>
                <th style="padding:var(--space-4) var(--space-6); color:var(--text-secondary); font-weight:var(--font-weight-medium);">Confidence</th>
                <th style="padding:var(--space-4) var(--space-6); color:var(--text-secondary); font-weight:var(--font-weight-medium); text-align:right;">Actions</th>
              </tr>
            </thead>
            <tbody id="entity-explorer-tbody">
              ${this._buildRowsHTML(entities)}
            </tbody>
          </table>
        </div>
      </div>
    `;

    this.container.innerHTML = html;
    this._updateDOM();
  },

  _buildRowsHTML(entities) {
    return entities.map(e => `
      <tr class="entity-row" data-type="${e.type}" style="border-bottom:1px solid var(--border-glass);">
        <td style="padding:var(--space-4) var(--space-6); font-family:var(--font-mono);">${e.id}</td>
        <td style="padding:var(--space-4) var(--space-6);">
          <span class="badge" style="background:var(--bg-glass-hover); border:1px solid var(--border-medium);">${e.type}</span>
        </td>
        <td style="padding:var(--space-4) var(--space-6);">
          <div style="display:flex; align-items:center; gap:8px;">
            <div style="width:100px; height:4px; background:var(--bg-glass-hover); border-radius:2px;">
              <div style="width:${e.confidence}%; height:100%; background:var(--brand-primary); border-radius:2px;"></div>
            </div>
            <span style="font-size:var(--font-size-sm); color:var(--text-muted);">${e.confidence}%</span>
          </div>
        </td>
        <td style="padding:var(--space-4) var(--space-6); text-align:right;">
          <button class="btn btn-ghost btn-sm" onclick="if(typeof THRAGG_InvestigationSession !== 'undefined') THRAGG_InvestigationSession.setContext('Entity', '${e.id}')">Inspect</button>
        </td>
      </tr>
    `).join('');
  },

  _updateDOM() {
    if (!this.container) return;
    const rows = this.container.querySelectorAll('.entity-row');
    let visibleCount = 0;

    rows.forEach(row => {
      const type = row.dataset.type;
      
      let show = true;
      if (this.filters.type !== 'ALL' && type !== this.filters.type) show = false;

      // Note: We don't filter entities by Severity easily since they don't have a direct severity in THRAGG_DATA, 
      // but we could map it if needed. For now, entity type is the primary entity filter.

      if (show) {
        row.style.display = 'table-row';
        visibleCount++;
      } else {
        row.style.display = 'none';
      }
    });

    // Handle empty state
    const tbody = document.getElementById('entity-explorer-tbody');
    if (visibleCount === 0 && tbody) {
      // Just hide all rows, maybe show a "No entities match filters" 
      // We'll leave it as a blank table for now to keep the code simple.
    }
  },

  _highlightContext(context) {
    if (!this.container) return;
    const rows = this.container.querySelectorAll('.entity-row');
    rows.forEach(row => {
      row.classList.remove('active', 'dimmed');
      if (context && context.type) {
         if (context.type === 'Entity' && row.querySelector('td').textContent.includes(context.id)) {
           row.classList.add('active');
           row.scrollIntoView({ behavior: 'smooth', block: 'center' });
         } else {
           row.classList.add('dimmed');
         }
      }
    });
  }
};
