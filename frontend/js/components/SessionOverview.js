/* ==========================================================================
   THRAGG — Session Overview
   ========================================================================== */

const THRAGG_SessionOverview = {
  render(container) {
    if (!container) return;
    
    const scope = THRAGG_DATA.assessment_scope || {};
    const framework = THRAGG_DATA.framework_snapshot || {};
    
    // Fallback data if structure is slightly different
    const executionTime = framework.execution_time || 'N/A';
    const activeModules = framework.active_modules || [];
    
    let html = `
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(350px, 1fr)); gap:var(--space-6);">
        
        <div class="card">
          <div class="card-header">
            <h3 style="margin:0;">Evidence & Scope</h3>
          </div>
          <div class="card-body">
            <div style="display:flex; flex-direction:column; gap:var(--space-4);">
              <div style="display:flex; justify-content:space-between; padding-bottom:var(--space-3); border-bottom:1px solid var(--border-glass);">
                <span style="color:var(--text-muted);">Target Organizations</span>
                <span style="font-weight:var(--font-weight-medium);">${(scope.target_organizations || []).join(', ') || 'None'}</span>
              </div>
              <div style="display:flex; justify-content:space-between; padding-bottom:var(--space-3); border-bottom:1px solid var(--border-glass);">
                <span style="color:var(--text-muted);">Included Domains</span>
                <span style="font-weight:var(--font-weight-medium);">${(scope.included_domains || []).join(', ') || 'None'}</span>
              </div>
              <div style="display:flex; justify-content:space-between; padding-bottom:var(--space-3); border-bottom:1px solid var(--border-glass);">
                <span style="color:var(--text-muted);">Excluded Domains</span>
                <span style="font-weight:var(--font-weight-medium);">${(scope.excluded_domains || []).join(', ') || 'None'}</span>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3 style="margin:0;">Execution DNA</h3>
          </div>
          <div class="card-body">
            <div style="display:flex; flex-direction:column; gap:var(--space-4);">
              <div style="display:flex; justify-content:space-between; padding-bottom:var(--space-3); border-bottom:1px solid var(--border-glass);">
                <span style="color:var(--text-muted);">Execution Date</span>
                <span style="font-family:var(--font-mono); font-size:var(--font-size-sm);">${executionTime}</span>
              </div>
              <div style="display:flex; justify-content:space-between; padding-bottom:var(--space-3); border-bottom:1px solid var(--border-glass);">
                <span style="color:var(--text-muted);">Active Modules</span>
                <span style="font-weight:var(--font-weight-medium);">${activeModules.length} Modules</span>
              </div>
              <div style="display:flex; flex-wrap:wrap; gap:var(--space-2); margin-top:var(--space-2);">
                ${activeModules.map(m => `<span class="badge" style="background:var(--bg-glass-hover);">${m}</span>`).join('')}
              </div>
            </div>
          </div>
        </div>

      </div>
    `;

    container.innerHTML = html;
  }
};
