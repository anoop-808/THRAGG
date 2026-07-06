/* ==========================================================================
   THRAGG — Assessment Scope Component
   ========================================================================== */

const THRAGG_AssessmentScope = {
  render(container) {
    if (!container) return;
    const scope = THRAGG_DATA.executive_assessment.assessment_scope;

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0">Assessment Scope</span>
          <span class="badge badge-info">${scope.modules_run.length} modules</span>
        </div>
        <div class="card-body" style="padding:0;">
          <div style="padding: var(--space-4) var(--space-5);">
            <div class="metric-label" style="margin-bottom: var(--space-2);">Modules Executed</div>
            <div style="display: flex; gap: var(--space-2); flex-wrap: wrap;">
              ${scope.modules_run.map(m => `
                <span class="domain-label ${m.toLowerCase()}">${m}</span>
              `).join('')}
            </div>
          </div>
          <div class="divider" style="margin:0;"></div>
          <div style="padding: var(--space-4) var(--space-5);">
            <div class="metric-label" style="margin-bottom: var(--space-2);">Evidence Sources</div>
            <div style="display: flex; flex-direction: column; gap: var(--space-1);">
              ${scope.evidence_files.map(f => `
                <div style="font-size: var(--font-size-xs); color: var(--text-muted); font-family: var(--font-mono);">
                  📄 ${f}
                </div>
              `).join('')}
            </div>
          </div>
          ${scope.assessment_limitations.length > 0 ? `
            <div class="divider" style="margin:0;"></div>
            <div style="padding: var(--space-4) var(--space-5);">
              <div class="metric-label" style="margin-bottom: var(--space-2);">Limitations</div>
              <ul style="list-style: disc; padding-left: var(--space-4);">
                ${scope.assessment_limitations.map(l => `
                  <li style="font-size: var(--font-size-xs); color: var(--text-muted); margin-bottom: var(--space-1);">${l}</li>
                `).join('')}
              </ul>
            </div>
          ` : ''}
        </div>
      </div>
    `;
  }
};
