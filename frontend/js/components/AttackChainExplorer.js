/* ==========================================================================
   THRAGG — Attack Chain Explorer Component (Interactive Timeline)
   ========================================================================== */

const THRAGG_AttackChainExplorer = {
  render(container) {
    if (!container) return;
    const chains = THRAGG_DATA.attack_chains;

    if (!chains || !chains.length) {
      container.innerHTML = `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin-bottom: var(--space-4);">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M12 8v4M12 16h.01"/>
          </svg>
          <div class="empty-state-title" style="font-size: var(--font-size-lg); font-weight: var(--font-weight-semibold); color: var(--text-primary); margin-bottom: var(--space-2);">No Attack Chains Discovered</div>
          <div class="empty-state-text" style="color: var(--text-secondary); max-width: 400px; text-align: center; margin-bottom: var(--space-4);">
            The intelligence engine did not identify any correlated sequences of adversary behavior matching known MITRE ATT&CK patterns.
          </div>
          <button class="btn btn-secondary" onclick="if(typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('RECOMMENDATIONS_REQUESTED')">
            Review Preventative Recommendations
          </button>
        </div>
      `;
      return;
    }

    container.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: var(--space-6);">
        ${chains.map((chain, ci) => {
          const steps = chain.steps || chain.timeline || [];
          const severity = chain.severity || 'MEDIUM';
          const sevColor = severity === 'CRITICAL' ? 'var(--color-critical)' : severity === 'HIGH' ? 'var(--color-high)' : severity === 'MEDIUM' ? 'var(--color-medium)' : 'var(--color-low)';
          
          return `
            <div class="card stagger-item chain-timeline-container" id="chain-container-${chain.id}" style="animation-delay: ${ci * 100}ms; border-top: 3px solid ${sevColor}; cursor: pointer;" onclick="THRAGG_AttackChainExplorer.selectChain('${chain.id}')">
              <div class="card-header" style="padding-bottom: 0;">
                <div>
                  <div style="display: flex; align-items: center; gap: var(--space-2); margin-bottom: var(--space-2);">
                    <span class="severity-label ${severity.toLowerCase()}">${severity}</span>
                    <span class="badge badge-default">${steps.length} stages</span>
                    <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${chain.id}</span>
                  </div>
                  <div style="font-size: var(--font-size-lg); font-weight: var(--font-weight-bold); color: var(--text-primary); margin-bottom: var(--space-2);">
                    ${chain.title || `Attack Narrative: ${chain.id}`}
                  </div>
                  <p style="font-size: var(--font-size-sm); color: var(--text-secondary); line-height: 1.6; max-width: 800px;">
                    ${chain.description}
                  </p>
                </div>
              </div>
              
              <div class="card-body" style="padding-top: var(--space-6); padding-bottom: var(--space-6); overflow-x: auto;">
                <div style="display: flex; position: relative; padding-bottom: var(--space-4); min-width: max-content;">
                  <!-- Connecting Line Background -->
                  <div style="position: absolute; top: 16px; left: 24px; right: 24px; height: 2px; background: rgba(255,255,255,0.05); z-index: 1;"></div>
                  <!-- Connecting Line Fill (Animated via JS on select) -->
                  <div class="timeline-progress-line" id="timeline-progress-${chain.id}" style="position: absolute; top: 16px; left: 24px; width: 0; height: 2px; background: ${sevColor}; z-index: 2; transition: width 1.2s var(--transition-spring);"></div>
                  
                  ${steps.map((step, si) => {
                    const mitreIds = step.mitre_id ? [step.mitre_id] : (step.mitre_techniques || []);
                    return `
                      <div class="timeline-step" 
                           style="position: relative; z-index: 3; display: flex; flex-direction: column; align-items: center; width: 180px; flex-shrink: 0;"
                           onclick="THRAGG_AttackChainExplorer.selectStep(event, '${chain.id}', '${step.entity}')"
                           onmouseenter="if(typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('MITRE_HOVERED', ${JSON.stringify(mitreIds)})"
                           onmouseleave="if(typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('MITRE_HOVERED', null)">
                        
                        <div class="timeline-node" id="node-${chain.id}-${si}" style="width: 32px; height: 32px; border-radius: 50%; background: var(--bg-elevated); border: 2px solid ${sevColor}; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: bold; color: var(--text-primary); margin-bottom: var(--space-3); transition: all var(--transition-spring); box-shadow: 0 0 0 4px var(--bg-surface);">
                          ${si + 1}
                        </div>
                        
                        <div style="text-align: center;">
                          <div style="font-size: 12px; font-weight: var(--font-weight-semibold); color: var(--text-primary); margin-bottom: 4px;">
                            ${step.technique || step.stage || 'Stage ' + (si+1)}
                          </div>
                          ${step.entity ? `
                            <div style="font-family: var(--font-mono); font-size: 10px; color: var(--brand-cyan); margin-bottom: 8px;">
                              ${step.entity}
                            </div>
                          ` : ''}
                          <div style="display: flex; flex-wrap: wrap; gap: 4px; justify-content: center;">
                            ${mitreIds.map(m => `<span class="tag tag-mitre" style="font-size: 9px; padding: 2px 4px;">${m}</span>`).join('')}
                          </div>
                        </div>
                      </div>
                    `;
                  }).join('')}
                </div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;

    // Global listener for resetting chain selections
    if (typeof THRAGG_EventBus !== 'undefined' && !this.isBound) {
      this.isBound = true;
      THRAGG_EventBus.on('ENTITY_DESELECTED', () => this.clearSelection());
    }
  },

  selectChain(chainId) {
    if (typeof THRAGG_EventBus !== 'undefined') {
      const chain = THRAGG_DATA.attack_chains.find(c => c.id === chainId);
      if (chain) {
        THRAGG_EventBus.emit('CHAIN_SELECTED', chain);
      }
    }

    // Visual updates
    document.querySelectorAll('.chain-timeline-container').forEach(el => {
      if (el.id === `chain-container-${chainId}`) {
        el.classList.remove('dimmed');
        el.classList.add('highlight');
        
        // Animate progress line
        const line = document.getElementById(`timeline-progress-${chainId}`);
        if (line) {
          line.style.width = 'calc(100% - 48px)'; // Fill to the last node
        }
        
        // Highlight nodes
        const nodes = el.querySelectorAll('.timeline-node');
        nodes.forEach((n, i) => {
          setTimeout(() => {
            n.style.background = n.style.borderColor;
            n.style.color = '#fff';
            n.style.transform = 'scale(1.2)';
            n.style.boxShadow = `0 0 16px ${n.style.borderColor}`;
          }, i * 150); // Stagger animation
        });
      } else {
        el.classList.add('dimmed');
        el.classList.remove('highlight');
        
        // Reset others
        const line = document.getElementById(`timeline-progress-${el.id.replace('chain-container-', '')}`);
        if (line) line.style.width = '0';
        
        const nodes = el.querySelectorAll('.timeline-node');
        nodes.forEach(n => {
          n.style.background = 'var(--bg-elevated)';
          n.style.color = 'var(--text-primary)';
          n.style.transform = 'scale(1)';
          n.style.boxShadow = `0 0 0 4px var(--bg-surface)`;
        });
      }
    });
  },
  
  selectStep(e, chainId, entityId) {
    e.stopPropagation(); // prevent chain selection
    this.selectChain(chainId); // Select chain context first
    
    if (entityId && typeof THRAGG_EventBus !== 'undefined') {
      setTimeout(() => {
        THRAGG_EventBus.emit('ENTITY_SELECTED', entityId);
      }, 50); // Let chain event propagate first
    }
  },

  clearSelection() {
    document.querySelectorAll('.chain-timeline-container').forEach(el => {
      el.classList.remove('dimmed');
      el.classList.remove('highlight');
      
      const line = document.getElementById(`timeline-progress-${el.id.replace('chain-container-', '')}`);
      if (line) line.style.width = '0';
      
      const nodes = el.querySelectorAll('.timeline-node');
      nodes.forEach(n => {
        n.style.background = 'var(--bg-elevated)';
        n.style.color = 'var(--text-primary)';
        n.style.transform = 'scale(1)';
        n.style.boxShadow = `0 0 0 4px var(--bg-surface)`;
      });
    });
  }
};
