/* ==========================================================================
   THRAGG — MITRE ATT&CK Coverage Component (Interactive)
   ========================================================================== */

const THRAGG_MITRECoverage = {
  getTechniques() {
    const techniques = {};
    const correlations = THRAGG_DATA.correlations || [];
    const chains = THRAGG_DATA.attack_chains || [];

    // From correlations
    correlations.forEach((corr) => {
      (corr.mitre || []).forEach((m) => {
        techniques[m] = (techniques[m] || 0) + 1;
      });
    });

    // From attack chains
    chains.forEach((chain) => {
      (chain.mitre_techniques || []).forEach((m) => {
        techniques[m] = (techniques[m] || 0) + 1;
      });
    });

    return techniques;
  },

  MITRE_REFERENCE: {
    'T1046': { name: 'Network Service Discovery', tactic: 'Discovery', stage: 'Initial Access' },
    'T1021.004': { name: 'Remote Services: SSH', tactic: 'Lateral Movement', stage: 'Lateral Movement' },
    'T1110': { name: 'Brute Force', tactic: 'Credential Access', stage: 'Credential Access' },
    'T1078': { name: 'Valid Accounts', tactic: 'Defense Evasion', stage: 'Initial Access' },
    'T1530': { name: 'Data from Cloud Storage', tactic: 'Collection', stage: 'Exfiltration' },
    'T1048': { name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration', stage: 'Exfiltration' },
    'T1098': { name: 'Account Manipulation', tactic: 'Persistence', stage: 'Persistence' },
    'T1528': { name: 'Steal Application Access Token', tactic: 'Credential Access', stage: 'Credential Access' },
    'T1190': { name: 'Exploit Public-Facing Application', tactic: 'Initial Access', stage: 'Initial Access' },
    'T1078.004': { name: 'Valid Accounts: Cloud Accounts', tactic: 'Defense Evasion', stage: 'Initial Access' },
    'T1550.001': { name: 'Use Alternate Authentication Material', tactic: 'Defense Evasion', stage: 'Lateral Movement' },
    'T1087': { name: 'Account Discovery', tactic: 'Discovery', stage: 'Discovery' },
    'T1136': { name: 'Create Account', tactic: 'Persistence', stage: 'Persistence' },
    'T1556': { name: 'Modify Authentication Process', tactic: 'Credential Access', stage: 'Credential Access' }
  },

  render(container) {
    if (!container) return;
    const techniques = this.getTechniques();
    const entries = Object.entries(techniques);

    if (!entries.length) {
      container.innerHTML = `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin-bottom: var(--space-4);">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
            <line x1="3" y1="9" x2="21" y2="9"/>
            <line x1="9" y1="21" x2="9" y2="9"/>
          </svg>
          <div class="empty-state-title" style="font-size: var(--font-size-lg); font-weight: var(--font-weight-semibold); color: var(--text-primary); margin-bottom: var(--space-2);">No MITRE Mapping Found</div>
          <div class="empty-state-text" style="color: var(--text-secondary); max-width: 400px; text-align: center;">
            No adversary behaviors matching the MITRE ATT&CK framework were identified in the current intelligence dataset.
          </div>
        </div>
      `;
      return;
    }

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0">MITRE ATT&CK Coverage</span>
          <span class="badge badge-default">${entries.length} techniques</span>
        </div>
        <div class="card-body">
          <div class="mitre-grid">
            ${entries.map(([id, count]) => {
              const info = this.MITRE_REFERENCE[id];
              const maxCount = Math.max(...entries.map(([, c]) => c));
              const coverage = count / maxCount;
              const coverageClass = coverage > 0.8 ? 'coverage-full' : coverage > 0.3 ? 'coverage-partial' : 'coverage-none';
              return `
                <div class="mitre-cell ${coverageClass} interactive-mitre" id="mitre-${id.replace('.', '-')}" 
                     style="transition: all var(--transition-base); cursor: pointer;"
                     onclick="if(typeof THRAGG_InvestigationSession !== 'undefined') THRAGG_InvestigationSession.setContext('MITRE', '${id}')"
                     onmouseenter="if(typeof THRAGG_InvestigationSession !== 'undefined') THRAGG_InvestigationSession.setHoverPreview('MITRE', '${id}')"
                     onmouseleave="if(typeof THRAGG_InvestigationSession !== 'undefined') THRAGG_InvestigationSession.clearHoverPreview()">
                  <div class="mitre-cell-id">${id}</div>
                  <div class="mitre-cell-name">${info ? info.name : 'Unknown Technique'}</div>
                  ${info ? `<div style="font-size: 9px; color: var(--text-muted); margin-top: var(--space-1);">${info.tactic}</div>` : ''}
                  <div class="mitre-cell-coverage">
                    <div class="progress-bar">
                      <div class="progress-bar-fill brand" style="width: ${Math.min(coverage * 100, 100)}%"></div>
                    </div>
                  </div>
                  <div style="margin-top: var(--space-1); font-size: 10px; color: var(--text-muted);">
                    ${count} ${count === 1 ? 'match' : 'matches'}
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>
      </div>
    `;

    // Listen for MITRE events
    if (typeof THRAGG_EventBus !== 'undefined' && !this.isBound) {
      this.isBound = true;

      const updateHighlights = (context) => {
        const cells = document.querySelectorAll('.interactive-mitre');
        if (!context || !context.type) {
          cells.forEach(c => {
            c.classList.remove('dimmed', 'active', 'preview');
          });
          return;
        }

        cells.forEach(c => {
          c.classList.remove('dimmed', 'active', 'preview');
          const mId = c.id.replace('mitre-', '').replace('-', '.');
          
          let matches = false;
          if (context.type === 'MITRE' && context.id === mId) matches = true;
          else if (context.type === 'Finding' || context.type === 'Observation' || context.type === 'Correlation') {
            const finding = (THRAGG_DATA.executive_assessment?.observations || []).find(o => o.summary.includes(context.id) || o.id === context.id) || 
                            (THRAGG_DATA.correlations || []).find(c => c.title === context.id || c.id === context.id);
            if (finding && finding.mitre_tactics && finding.mitre_tactics.includes(mId)) matches = true;
            if (finding && finding.mitre && finding.mitre.includes(mId)) matches = true;
          }
          else if (context.type === 'Attack Chain') {
            const chain = (THRAGG_DATA.attack_chains || []).find(c => c.id === context.id || c.title === context.id);
            if (chain && chain.mitre_techniques && chain.mitre_techniques.includes(mId)) matches = true;
          }

          if (matches) {
            c.classList.add(context.isPreview ? 'preview' : 'active');
          } else {
            c.classList.add('dimmed');
          }
        });
      };

      THRAGG_EventBus.on('CONTEXT_CHANGED', updateHighlights);
      THRAGG_EventBus.on('HOVER_PREVIEW', (ctx) => updateHighlights(ctx ? { ...ctx, isPreview: true } : null));

      THRAGG_EventBus.on('REPLAY_STEP_CHANGED', (data) => {
        if (!data || !data.step) return;
        const cells = document.querySelectorAll('.interactive-mitre');
        
        const completed = new Set();
        if (typeof THRAGG_ReplayEngine !== 'undefined') {
          for (let i = 0; i < data.index; i++) {
             const ev = THRAGG_ReplayEngine.events[i];
             if (ev.mitre) ev.mitre.forEach(m => completed.add(m));
          }
        }
        const current = new Set(data.step.mitre || []);

        cells.forEach(c => {
          c.classList.remove('dimmed', 'active', 'preview', 'replay-completed', 'replay-glow');
          const mId = c.id.replace('mitre-', '').replace('-', '.');
          if (current.has(mId)) {
            c.classList.add('active', 'replay-glow');
            c.style.boxShadow = '0 0 15px var(--brand-primary)';
          } else if (completed.has(mId)) {
            c.classList.add('active', 'replay-completed');
            c.style.boxShadow = 'none';
          } else {
            c.classList.add('dimmed');
            c.style.boxShadow = 'none';
          }
        });
      });

      THRAGG_EventBus.on('REPLAY_STOPPED', () => {
        const cells = document.querySelectorAll('.interactive-mitre');
        cells.forEach(c => {
           c.classList.remove('dimmed', 'active', 'preview', 'replay-completed', 'replay-glow');
           c.style.boxShadow = 'none';
        });
      });
    }
  }
};
