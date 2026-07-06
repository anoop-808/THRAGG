/* ==========================================================================
   THRAGG — Traceability Explorer Component
   ========================================================================== */

const THRAGG_TraceabilityExplorer = {
  render(container) {
    if (!container) return;
    const trace = THRAGG_DATA.executive_assessment.traceability;
    const recs = THRAGG_DATA.executive_assessment.executive_recommendations || [];

    if (!trace || !recs.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-text">No traceability data available.</div></div>';
      return;
    }

    // Build recommendation-to-observation map
    const recToObs = {};
    if (trace.recommendation_to_observations) {
      trace.recommendation_to_observations.forEach(([recId, obsIds]) => {
        recToObs[recId] = obsIds;
      });
    }

    // Build observation-to-chain map
    const obsToChain = {};
    if (trace.observation_to_attack_chains) {
      trace.observation_to_attack_chains.forEach(([obsId, chainIds]) => {
        obsToChain[obsId] = chainIds;
      });
    }

    const obsToCorr = {};
    if (trace.observation_to_correlations) {
      trace.observation_to_correlations.forEach(([obsId, corrIds]) => {
        obsToCorr[obsId] = corrIds;
      });
    }

    container.innerHTML = `
      <div class="trace-tree">
        ${recs.slice(0, 8).map((rec, ri) => {
          const obsIds = recToObs[rec.id] || [];
          return `
            <div class="trace-item stagger-item" style="animation-delay: ${ri * 60}ms">
              <div style="display: flex; align-items: center; gap: var(--space-2); margin-bottom: var(--space-2);">
                <span class="badge badge-${rec.priority.toLowerCase()}">${rec.priority}</span>
                <span style="font-size: var(--font-size-sm); font-weight: var(--font-weight-medium); color: var(--text-primary);">
                  ${rec.title}
                </span>
              </div>
              <div class="trace-path">
                <span class="trace-path-step current">${rec.id}</span>
                <span class="trace-arrow">→</span>
                ${obsIds.length ? obsIds.map(obsId => `
                  <span class="trace-path-step">${obsId}</span>
                `).join('<span class="trace-arrow">→</span>') : '<span class="trace-path-step" style="opacity:0.3">(no observations)</span>'}
                ${obsIds.length > 0 ? `
                  <span class="trace-arrow">→</span>
                  ${obsIds.map(obsId => {
                    const chains = obsToChain[obsId] || [];
                    const corrs = obsToCorr[obsId] || [];
                    const items = [...chains, ...corrs];
                    return items.length ? items.map(id => `<span class="trace-path-step">${id}</span>`).join('<span class="trace-arrow">→</span>') : '';
                  }).join('')}
                ` : ''}
                <span class="trace-arrow">→</span>
                <span class="trace-path-step" style="color: var(--color-low);">Evidence</span>
              </div>
              <div style="margin-top: var(--space-2); font-size: var(--font-size-xs); color: var(--text-muted);">
                ${rec.description}
              </div>
              ${rec.references && rec.references.length ? `
                <div style="margin-top: var(--space-2); display: flex; gap: var(--space-1);">
                  ${rec.references.map(ref => `<span class="tag">${ref}</span>`).join('')}
                </div>
              ` : ''}
            </div>
          `;
        }).join('')}
      </div>
    `;
  }
};
