/* ==========================================================================
   THRAGG — Attack Chain Explorer Component
   ========================================================================== */

const THRAGG_AttackChainExplorer = {
  render(container) {
    if (!container) return;
    const chains = THRAGG_DATA.attack_chains;

    if (!chains || !chains.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-text">No attack chains detected.</div></div>';
      return;
    }

    container.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: var(--space-4);">
        ${chains.map((chain, ci) => {
          const steps = chain.steps || chain.timeline || [];
          const severity = chain.severity || 'MEDIUM';
          return `
            <div class="chain-card stagger-item" style="animation-delay: ${ci * 100}ms">
              <div class="chain-card-header">
                <div>
                  <div style="display: flex; align-items: center; gap: var(--space-2); margin-bottom: var(--space-1);">
                    <span class="severity-label ${severity.toLowerCase()}">${severity}</span>
                    <span class="badge badge-default">${steps.length} steps</span>
                    <span class="badge badge-default">${chain.mitre_techniques.length} MITRE</span>
                  </div>
                  <div style="font-size: var(--font-size-md); font-weight: var(--font-weight-semibold); color: var(--text-primary);">
                    ${chain.title || `Attack Chain ${chain.id}`}
                  </div>
                </div>
                <span style="font-size: var(--font-size-xs); color: var(--text-muted); font-family: var(--font-mono);">
                  ${chain.id}
                </span>
              </div>
              <div class="chain-card-body">
                <p style="font-size: var(--font-size-sm); color: var(--text-secondary); margin-bottom: var(--space-4); line-height: 1.6;">
                  ${chain.description}
                </p>
                <div style="display: flex; flex-direction: column;">
                  ${steps.map((step, si) => `
                    <div class="chain-step">
                      <div class="chain-step-number">${si + 1}</div>
                      <div class="chain-step-content">
                        <div class="chain-step-title">
                          ${step.technique || step.stage || step.description || 'Step ' + (si + 1)}
                        </div>
                        <div class="chain-step-detail">
                          ${step.description || step.technique || ''}
                          ${step.entity ? ` · <span style="color: var(--text-secondary)">${step.entity}</span>` : ''}
                        </div>
                        <div class="chain-step-mitre">
                          ${step.mitre_id ? `<span class="tag tag-mitre">${step.mitre_id}</span>` : ''}
                          ${step.mitre_techniques ? step.mitre_techniques.map(m => `<span class="tag tag-mitre">${m}</span>`).join('') : ''}
                          ${step.stage ? `<span class="tag">${step.stage}</span>` : ''}
                        </div>
                      </div>
                    </div>
                  `).join('')}
                </div>
              </div>
              <div class="card-footer">
                <span>${chain.participating_entities ? `${chain.participating_entities.length} entities involved` : ''}</span>
                <div style="display: flex; gap: var(--space-2);">
                  ${chain.mitre_techniques.map(m => `<span class="tag tag-mitre">${m}</span>`).join('')}
                </div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }
};
