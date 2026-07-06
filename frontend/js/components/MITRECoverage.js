/* ==========================================================================
   THRAGG — MITRE ATT&CK Coverage Component
   ========================================================================== */

const THRAGG_MITRECoverage = {
  /* ── MITRE techniques found in the dataset ─────────────────────────── */
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

  /* ── MITRE technique reference ─────────────────────────────────────── */
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
      container.innerHTML = '<div class="empty-state"><div class="empty-state-text">No MITRE techniques mapped.</div></div>';
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
                <div class="mitre-cell ${coverageClass}">
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
  }
};
