/* ==========================================================================
   THRAGG — Traceability Explorer Component (Interactive)
   ========================================================================== */

const THRAGG_TraceabilityExplorer = {
  render(container) {
    if (!container) return;
    const trace = THRAGG_DATA.executive_assessment.traceability;
    const recs = THRAGG_DATA.executive_assessment.executive_recommendations || [];

    if (!trace || !recs.length) {
      container.innerHTML = `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin-bottom: var(--space-4);">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
            <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
            <line x1="12" y1="22.08" x2="12" y2="12"></line>
          </svg>
          <div class="empty-state-title" style="font-size: var(--font-size-lg); font-weight: var(--font-weight-semibold); color: var(--text-primary); margin-bottom: var(--space-2);">No Traceability Lineage</div>
          <div class="empty-state-text" style="color: var(--text-secondary); max-width: 400px; text-align: center;">
            No end-to-end evidence chains could be established between raw findings and executive recommendations.
          </div>
        </div>
      `;
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
      <div class="trace-tree" style="display: flex; flex-direction: column; gap: var(--space-4);">
        ${recs.slice(0, 8).map((rec, ri) => {
          const obsIds = recToObs[rec.id] || [];
          const sevColor = rec.priority === 'CRITICAL' ? 'var(--color-critical)' : rec.priority === 'HIGH' ? 'var(--color-high)' : rec.priority === 'MEDIUM' ? 'var(--color-medium)' : 'var(--color-low)';
          
          let breadcrumbHtml = `<span class="trace-path-step current" style="border-color: ${sevColor}">${rec.id}</span>`;
          
          if (obsIds.length) {
            breadcrumbHtml += `<span class="trace-arrow">→</span>`;
            breadcrumbHtml += obsIds.map(obsId => {
              const chains = obsToChain[obsId] || [];
              const corrs = obsToCorr[obsId] || [];
              
              let stepHtml = `<span class="trace-path-step interactive-trace" onmouseenter="THRAGG_TraceabilityExplorer.hoverStep(event, '${obsId}')" onmouseleave="THRAGG_TraceabilityExplorer.hoverStep(event, null)">${obsId}</span>`;
              
              const items = [...chains, ...corrs];
              if (items.length) {
                stepHtml += `<span class="trace-arrow">→</span>` + items.map(id => 
                  `<span class="trace-path-step interactive-trace" onmouseenter="THRAGG_TraceabilityExplorer.hoverStep(event, '${id}')" onmouseleave="THRAGG_TraceabilityExplorer.hoverStep(event, null)" onclick="if(typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('CHAIN_SELECTED', {id: '${id}'})">${id}</span>`
                ).join('<span class="trace-arrow">→</span>');
              }
              return stepHtml;
            }).join('<span class="trace-arrow">/</span>');
          } else {
            breadcrumbHtml += `<span class="trace-arrow">→</span><span class="trace-path-step" style="opacity:0.3">(no observations)</span>`;
          }
          breadcrumbHtml += `<span class="trace-arrow">→</span><span class="trace-path-step" style="background: rgba(34,197,94,0.1); border-color: var(--color-low); color: var(--color-low);">Raw Evidence</span>`;

          return `
            <div class="trace-item stagger-item card" style="animation-delay: ${ri * 60}ms; border-left: 3px solid ${sevColor};">
              <div class="card-body">
                <div style="display: flex; align-items: center; gap: var(--space-2); margin-bottom: var(--space-3);">
                  <span class="badge badge-${rec.priority.toLowerCase()}">${rec.priority}</span>
                  <span style="font-size: var(--font-size-sm); font-weight: var(--font-weight-medium); color: var(--text-primary);">
                    ${rec.title}
                  </span>
                </div>
                
                <div class="trace-path" style="display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); margin-bottom: var(--space-3); padding: var(--space-3); background: rgba(0,0,0,0.2); border-radius: var(--radius-sm);">
                  ${breadcrumbHtml}
                </div>
                
                <div style="font-size: var(--font-size-xs); color: var(--text-muted); line-height: 1.5; max-width: 800px;">
                  ${rec.description}
                </div>
                
                ${rec.references && rec.references.length ? `
                  <div style="margin-top: var(--space-3); display: flex; gap: var(--space-1);">
                    ${rec.references.map(ref => `<span class="tag tag-mitre">${ref}</span>`).join('')}
                  </div>
                ` : ''}
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;

    // Global listener for resetting chain selections
    if (typeof THRAGG_EventBus !== 'undefined' && !this.isBound) {
      this.isBound = true;
    }
  },

  hoverStep(e, id) {
    if (!id) {
      document.querySelectorAll('.interactive-trace').forEach(el => el.classList.remove('highlight'));
      return;
    }
    
    e.target.classList.add('highlight');
    // We could emit a global event here if we know what `id` is (obs or chain)
    if (typeof THRAGG_EventBus !== 'undefined') {
      if (id.startsWith('CHAIN')) {
        // Find the chain to get its entities
        const chain = (THRAGG_DATA.attack_chains || []).find(c => c.id === id);
        if (chain && chain.participating_entities) {
          // Highlight entities in graph without fully selecting them
          THRAGG_EventBus.emit('CHAIN_SELECTED', chain);
        }
      } else if (id.startsWith('CORR') || id.startsWith('OBS')) {
         // Could search correlations
      }
    }
  }
};
