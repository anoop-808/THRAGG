/* ==========================================================================
   THRAGG — Main Application Shell
   ========================================================================== */

const THRAGG_App = {
  currentView: 'executive',

  /* ── Initialize the application ────────────────────────────────────── */
  async init() {
    this._renderShell();
    this._initAtmosphere();
    this._initNavigation();
    
    if (typeof THRAGG_CaseManager !== 'undefined') {
      await THRAGG_CaseManager.init();
    }
    
    this.navigate('executive');
    // Initialize utilities
    if (typeof THRAGG_GlobalIndex !== 'undefined') THRAGG_GlobalIndex.init();
    if (typeof THRAGG_CommandPalette !== 'undefined') THRAGG_CommandPalette.init();
    if (typeof THRAGG_KeyboardShortcuts !== 'undefined') THRAGG_KeyboardShortcuts.init();
    
    // Initialize Replay Engine
    if (typeof THRAGG_ReplayEngine !== 'undefined') THRAGG_ReplayEngine.init();
    if (typeof THRAGG_ReplayControls !== 'undefined') THRAGG_ReplayControls.init();
  },

  /* ── Render the app shell layout ───────────────────────────────────── */
  _renderShell() {
    const root = document.getElementById('app');
    if (!root) return;

    root.innerHTML = `
      <div class="app-shell" id="app-shell">
        <aside class="sidebar" id="sidebar"></aside>
        <header class="topnav" id="topnav"></header>
        <main class="main-content" id="main-content"></main>
        <aside class="context-panel" id="context-panel"></aside>
      </div>
      <div id="toast-container"></div>
    `;

    // Render sidebar and top navigation
    THRAGG_Sidebar.render(document.getElementById('sidebar'), this.currentView);
    THRAGG_TopNavigation.render(document.getElementById('topnav'), this.currentView);
    
    // Initialize context panel
    if (typeof THRAGG_ContextPanel !== 'undefined') {
      THRAGG_ContextPanel.init(document.getElementById('context-panel'));
    }

    // Initialize session
    if (typeof THRAGG_InvestigationSession !== 'undefined') {
      THRAGG_InvestigationSession.init();
    }
  },

  /* ── Command Center Atmosphere ─────────────────────────────────────── */
  _initAtmosphere() {
    const shell = document.getElementById('app-shell');
    if (!shell) return;
    
    // Analyze intelligence dataset
    const assessment = THRAGG_DATA.executive_assessment;
    if (assessment && assessment.top_risks && assessment.top_risks.length > 0) {
      const highestRisk = assessment.top_risks[0].risk_level;
      if (highestRisk === 'CRITICAL' || highestRisk === 'HIGH') {
        shell.classList.add('state-critical');
        return;
      }
    }
    
    // Default healthy/idle
    shell.classList.add('state-healthy');

    // Global listener to shift atmosphere when interacting with entities
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('ENTITY_SELECTED', (id) => {
        if (id) {
          shell.classList.add('state-active');
        } else {
          shell.classList.remove('state-active');
        }
      });
      THRAGG_EventBus.on('CHAIN_SELECTED', (chain) => {
        if (chain) shell.classList.add('state-active');
        else shell.classList.remove('state-active');
      });
    }
  },

  /* ── Toast Notifications ───────────────────────────────────────────── */
  showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const icon = type === 'success' ? '✓' : 'ℹ';
    
    toast.innerHTML = `
      <div style="font-weight: bold; width: 16px; text-align: center;">${icon}</div>
      <div>${message}</div>
    `;
    
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.animation = 'toast-out 0.3s var(--ease-out) forwards';
      setTimeout(() => {
        if (container.contains(toast)) container.removeChild(toast);
      }, 300);
    }, duration);
  },

  /* ── Navigate to a view ────────────────────────────────────────────── */
  navigate(viewId) {
    if (this.currentView === 'graph' && typeof THRAGG_KnowledgeGraph !== 'undefined') {
      THRAGG_KnowledgeGraph.destroy();
    }
    this.currentView = viewId;
    this._renderView(viewId);

    // Update navigation highlights
    THRAGG_Sidebar.setActive(viewId);
    THRAGG_TopNavigation.updateView(viewId);

    // Scroll to top
    const main = document.getElementById('main-content');
    if (main) main.scrollTop = 0;
  },

  /* ── Render the current view ───────────────────────────────────────── */
  _renderView(viewId) {
    const container = document.getElementById('main-content');
    if (!container) return;

    const views = {
      active_case:   () => this._renderCaseWorkspace(container),
      new_case:      () => { THRAGG_CaseManager.createCase().then(() => this.navigate('active_case')); },
      archive_case:  () => this._renderCaseArchive(container),
      executive:     () => this._renderExecutiveOverview(container),
      posture:       () => this._renderSecurityPosture(container),
      risks:         () => this._renderRiskDistribution(container),
      domains:       () => this._renderDomainCoverage(container),
      chains:        () => this._renderAttackChains(container),
      mitre:         () => this._renderMITRE(container),
      traceability:  () => this._renderTraceability(container),
      graph:         () => this._renderKnowledgeGraph(container),
      entities:      () => this._renderEntityExplorer(container),
      findings:      () => this._renderFindingExplorer(container),
      session:       () => this._renderSessionOverview(container),
      recommendations: () => this._renderRecommendations(container),
      timeline:      () => this._renderActivityTimeline(container),
      downloads:     () => this._renderReportDownloads(container),
      replay_timeline: () => this._renderReplayTimeline(container),
      report_composer: () => this._renderReportComposer(container),
      report_preview:  () => this._renderReportPreview(container)
    };

    const renderFn = views[viewId];
    if (renderFn) {
      renderFn();
    } else {
      this._renderExecutiveOverview(container);
    }

    // Apply staggered animations
    container.querySelectorAll('.stagger-children > *').forEach((el, i) => {
      (el).style.animationDelay = `${i * 50}ms`;
    });
  },
  
  /* ── Case Management Views ─────────────────────────────────────────── */
  _renderReportDownloads(container) {
    // Redirect to the new Report Composer
    this._renderReportComposer(container);
  },

  _renderReportComposer(container) {
    container.innerHTML = `<div class="view-container animate-fade-in-up" id="report-composer-container"></div>`;
    requestAnimationFrame(() => {
      if (typeof THRAGG_ReportComposer !== 'undefined') {
        THRAGG_ReportComposer.render(document.getElementById('report-composer-container'));
      }
    });
  },

  _renderReportPreview(container) {
    container.innerHTML = `<div class="view-container animate-fade-in-up" id="report-preview-container" style="height:100%;"></div>`;
    requestAnimationFrame(() => {
      if (typeof THRAGG_ReportPreview !== 'undefined') {
        THRAGG_ReportPreview.render(document.getElementById('report-preview-container'));
      }
    });
  },

  _renderCaseWorkspace(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up" id="case-workspace-container"></div>
    `;
    requestAnimationFrame(() => {
      if (typeof THRAGG_CaseWorkspace !== 'undefined') {
        THRAGG_CaseWorkspace.render(document.getElementById('case-workspace-container'));
      }
    });
  },

  _renderReplayTimeline(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up" id="replay-timeline-container"></div>
    `;
    requestAnimationFrame(() => {
      if (typeof THRAGG_ReplayTimeline !== 'undefined') {
        THRAGG_ReplayTimeline.render(document.getElementById('replay-timeline-container'));
      }
    });
  },

  _renderCaseArchive(container) {
    const cases = THRAGG_CaseManager.getAllCases();
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Investigation Archive</div>
          <div class="page-subtitle">View and manage all past and present investigations</div>
        </div>
        <div class="grid grid-2" style="margin-top:var(--space-6);">
          ${cases.map(c => `
            <div class="card" style="cursor:pointer; transition:transform 0.2s;" onclick="THRAGG_CaseManager.setActiveCase('${c.id}').then(()=>THRAGG_App.navigate('active_case'))" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='none'">
              <div class="card-body">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <div style="font-weight:bold; font-size:var(--font-size-md);">${c.title}</div>
                  <span class="tag">${c.status}</span>
                </div>
                <div style="font-size:var(--font-size-sm); color:var(--text-muted); margin-top:var(--space-2);">
                  ID: ${c.id} · Created: ${new Date(c.created_at).toLocaleDateString()}
                </div>
                <div style="font-size:var(--font-size-sm); color:var(--text-secondary); margin-top:var(--space-3);">
                  ${c.bookmarks.length} Bookmarks · ${c.notes.length} Notes
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  },

  /* ── View: Executive Overview ──────────────────────────────────────── */
  _renderExecutiveOverview(container) {
    const assessment = THRAGG_DATA.executive_assessment;
    const snapshot = THRAGG_DATA.framework_snapshot;

    container.innerHTML = `
      <div class="view-container executive-overview">
        <div class="view-header animate-fade-in-up" style="margin-bottom: var(--space-8);">
          <div class="page-title" style="font-size: var(--font-size-4xl); font-weight: var(--font-weight-bold); letter-spacing: var(--letter-spacing-tight);">Executive Overview</div>
          <div class="page-subtitle" style="font-size: var(--font-size-md); color: var(--text-muted); margin-top: var(--space-2);">Comprehensive security intelligence summary · Generated ${THRAGG_Charts.formatTimestamp(THRAGG_DATA.generated_at)}</div>
        </div>

        <!-- Intelligence Core -->
        <div class="intelligence-core-container" id="intelligence-core" style="margin-bottom: var(--space-6);">
          <div class="core-overlay">
            <div class="core-overlay-title">THRAGG Intelligence Core</div>
            <div class="core-overlay-subtitle">Security Domain Orchestration</div>
          </div>
          <div class="core-info-panel">
            <div class="core-info-item">${snapshot.finding_count} findings</div>
            <div class="core-info-item">${snapshot.relationship_count} relationships</div>
          </div>
          <div class="core-domains" id="core-domains"></div>
        </div>

        <!-- KPI Cards -->
        <div class="grid grid-3" style="margin-bottom: var(--space-6);" id="kpi-cards"></div>

        <!-- Assessment Scope -->
        <div class="grid grid-2" style="margin-bottom: var(--space-6);">
          <div id="scope-section"></div>
          <div id="posture-section"></div>
        </div>

        <!-- Summary -->
        <div class="glass-card" style="margin-bottom: var(--space-8); padding: var(--space-6);">
          <div class="section-title" style="font-size: var(--font-size-xl); margin-bottom: var(--space-4);">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: var(--space-2);">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>
            </svg>
            Intelligence Summary
          </div>
          <p style="font-size: var(--font-size-md); color: var(--text-secondary); line-height: var(--line-height-relaxed); max-width: 900px;">
            ${assessment.overall_summary}
          </p>
          <div style="display: flex; gap: var(--space-3); margin-top: var(--space-5); flex-wrap: wrap;">
            ${assessment.top_priorities.slice(0, 3).map(p => `
              <span class="tag" style="font-size: var(--font-size-sm); padding: var(--space-2) var(--space-3); background: var(--bg-elevated); border: 1px solid var(--border-medium);">${p}</span>
            `).join('')}
          </div>
        </div>

        <!-- Quick actions -->
        <div style="display: flex; gap: var(--space-3); margin-bottom: var(--space-6);">
          <button class="btn btn-primary" onclick="THRAGG_App.navigate('risks')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2"/><rect x="9" y="3" width="6" height="4" rx="1"/><path d="M9 14l2 2 4-4"/>
            </svg>
            View Risk Distribution
          </button>
          <button class="btn btn-secondary" onclick="THRAGG_App.navigate('chains')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 4-6"/>
            </svg>
            Explore Attack Chains
          </button>
          <button class="btn btn-ghost" onclick="THRAGG_App.navigate('recommendations')">
            View Recommendations →
          </button>
        </div>
      </div>
    `;

    // Initialize sub-components
    requestAnimationFrame(() => {
      THRAGG_IntelligenceCore.init('intelligence-core');
      THRAGG_KPICards.render(document.getElementById('kpi-cards'));
      THRAGG_AssessmentScope.render(document.getElementById('scope-section'));
      THRAGG_SecurityPosture.render(document.getElementById('posture-section'));

      // Build domain legend
      const legend = document.getElementById('core-domains');
      if (legend) {
        const domains = [
          { id: 'network', label: 'Network', color: '#00d2ff' },
          { id: 'cloud', label: 'Cloud', color: '#6c5ce7' },
          { id: 'identity', label: 'Identity', color: '#f97316' },
          { id: 'web', label: 'Web', color: '#22c55e' },
          { id: 'logs', label: 'Logs', color: '#eab308' }
        ];
        legend.innerHTML = domains.map(d => `
          <div class="core-domain-item">
            <span class="core-domain-dot" style="background: ${d.color}"></span>
            ${d.label}
          </div>
        `).join('');
      }
    });
  },

  /* ── View: Security Posture ────────────────────────────────────────── */
  _renderSecurityPosture(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Security Posture</div>
          <div class="page-subtitle">Overall security health assessment</div>
        </div>
        <div style="margin-bottom: var(--space-6);" id="posture-full"></div>
        <div class="grid grid-2">
          <div id="scope-section-2"></div>
          <div>
            <div class="card">
              <div class="card-header">
                <span class="section-title" style="margin:0;">Executive Summary</span>
              </div>
              <div class="card-body">
                <p style="font-size: var(--font-size-sm); color: var(--text-secondary); line-height: 1.7;">
                  ${THRAGG_DATA.executive_assessment.overall_summary}
                </p>
                <div style="margin-top: var(--space-4);">
                  <div class="metric-label" style="margin-bottom: var(--space-2);">Top Priorities</div>
                  <ul style="display: flex; flex-direction: column; gap: var(--space-2);">
                    ${THRAGG_DATA.executive_assessment.top_priorities.slice(0, 5).map(p => `
                      <li style="display: flex; align-items: center; gap: var(--space-2); font-size: var(--font-size-sm); color: var(--text-secondary);">
                        <span style="color: var(--color-high);">●</span>
                        ${p}
                      </li>
                    `).join('')}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_SecurityPosture.render(document.getElementById('posture-full'));
      THRAGG_AssessmentScope.render(document.getElementById('scope-section-2'));
    });
  },

  /* ── View: Risk Distribution ───────────────────────────────────────── */
  _renderRiskDistribution(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Risk Distribution</div>
          <div class="page-subtitle">Risk assessment breakdown by severity and contributing factors</div>
        </div>
        <div class="grid grid-2" style="margin-bottom: var(--space-6);">
          <div id="risk-dist-chart"></div>
          <div id="risk-top-table"></div>
        </div>
        <div id="risk-contributions"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_RiskDistribution.render(document.getElementById('risk-dist-chart'));
      this._renderTopRisksTable(document.getElementById('risk-top-table'));
      this._renderRiskContributions(document.getElementById('risk-contributions'));
    });
  },

  _renderTopRisksTable(container) {
    const risks = THRAGG_DATA.risk_assessments || [];
    if (!container || !risks.length) return;

    container.innerHTML = `
      <div class="card" style="height: 100%;">
        <div class="card-header">
          <span class="section-title" style="margin:0;">Top Risk Assessments</span>
          <span class="badge badge-default">${risks.length} total</span>
        </div>
        <div class="card-body" style="padding:0; overflow-x: auto;">
          <table class="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Score</th>
                <th>Level</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              ${risks.slice(0, 5).map(r => `
                <tr>
                  <td style="font-family: var(--font-mono); font-size: var(--font-size-xs);">${r.id}</td>
                  <td><span style="font-family: var(--font-mono); font-weight: var(--font-weight-semibold); color: ${THRAGG_Charts.severityColor(r.risk_level)};">${r.score}</span></td>
                  <td><span class="severity-label ${r.risk_level.toLowerCase()}">${r.risk_level}</span></td>
                  <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${r.summary}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  _renderRiskContributions(container) {
    const risks = THRAGG_DATA.risk_assessments || [];
    if (!container || !risks.length) return;

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0;">Contributing Factors</span>
          <span class="badge badge-info">Per-risk score breakdown</span>
        </div>
        <div class="card-body" style="padding:0;">
          <div style="display: flex; flex-direction: column;">
            ${risks.slice(0, 3).map((risk, ri) => `
              <div style="padding: var(--space-4) var(--space-5); ${ri < risks.length - 1 ? 'border-bottom: 1px solid var(--border-glass);' : ''}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-3);">
                  <span style="font-size: var(--font-size-sm); font-weight: var(--font-weight-medium); color: var(--text-primary);">
                    ${risk.id}: ${risk.summary.substring(0, 60)}${risk.summary.length > 60 ? '...' : ''}
                  </span>
                  <span class="severity-label ${risk.risk_level.toLowerCase()}">${risk.risk_level} · ${risk.score}</span>
                </div>
                <div style="display: flex; flex-direction: column; gap: var(--space-2);">
                  ${(risk.contributions || []).map(c => {
                    const pct = c.max_contribution > 0 ? Math.round((c.score / c.max_contribution) * 100) : 0;
                    return `
                      <div>
                        <div style="display: flex; justify-content: space-between; font-size: var(--font-size-xs); margin-bottom: var(--space-1);">
                          <span style="color: var(--text-secondary);">${c.factor_name}</span>
                          <span style="color: var(--text-muted);">${c.score}/${c.max_contribution}</span>
                        </div>
                        <div class="progress-bar">
                          <div class="progress-bar-fill brand" style="width: ${pct}%"></div>
                        </div>
                        <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">${c.reason}</div>
                      </div>
                    `;
                  }).join('')}
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  },

  /* ── View: Domain Coverage ─────────────────────────────────────────── */
  _renderDomainCoverage(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Domain Coverage</div>
          <div class="page-subtitle">Security domain analysis and findings distribution</div>
        </div>
        <div style="margin-bottom: var(--space-6);" id="domains-grid"></div>
        <div class="grid grid-2">
          <div class="card">
            <div class="card-header">
              <span class="section-title" style="margin:0;">Domain Summary</span>
            </div>
            <div class="card-body">
              <p style="font-size: var(--font-size-sm); color: var(--text-secondary); line-height: 1.7;">
                Five security domains were assessed during this intelligence run. Each domain represents a distinct security analysis module that contributed findings, entities, and relationships to the overall assessment.
              </p>
              <div style="margin-top: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3);">
                ${[
                  { domain: 'Network', desc: 'External service exposure, open ports, and network reconnaissance results', findings: 12, color: '#00d2ff' },
                  { domain: 'Cloud', desc: 'Cloud resource configuration, public access, and data exposure risks', findings: 8, color: '#6c5ce7' },
                  { domain: 'Identity', desc: 'User privilege analysis, authentication controls, and identity risks', findings: 10, color: '#f97316' },
                  { domain: 'Web', desc: 'Web application vulnerabilities, dependency analysis, and security headers', findings: 7, color: '#22c55e' },
                  { domain: 'Logs', desc: 'Authentication events, system logs, and anomalous activity detection', findings: 10, color: '#eab308' }
                ].map(d => `
                  <div style="display: flex; gap: var(--space-3); align-items: flex-start;">
                    <div style="width: 4px; height: 40px; border-radius: var(--radius-sm); background: ${d.color}; flex-shrink: 0;"></div>
                    <div style="flex:1;">
                      <div style="font-size: var(--font-size-sm); font-weight: var(--font-weight-medium); color: var(--text-primary);">${d.domain}</div>
                      <div style="font-size: var(--font-size-xs); color: var(--text-muted);">${d.desc}</div>
                    </div>
                    <div style="font-size: var(--font-size-lg); font-weight: var(--font-weight-bold); color: ${d.color};">${d.findings}</div>
                  </div>
                `).join('')}
              </div>
            </div>
          </div>
          <div class="card">
            <div class="card-header">
              <span class="section-title" style="margin:0;">Observations</span>
            </div>
            <div class="card-body">
              ${(THRAGG_DATA.executive_assessment.observations || []).length === 0 ? `
                <div class="empty-state">
                  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin-bottom: var(--space-4);">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                  </svg>
                  <div class="empty-state-title" style="font-size: var(--font-size-lg); font-weight: var(--font-weight-semibold); color: var(--text-primary); margin-bottom: var(--space-2);">No Observations Identified</div>
                  <div class="empty-state-text" style="color: var(--text-secondary); max-width: 400px; text-align: center;">
                    The intelligence engine did not identify any actionable observations within the current assessment scope.
                  </div>
                </div>
              ` : `
              <div style="display: flex; flex-direction: column; gap: var(--space-3);">
                ${(THRAGG_DATA.executive_assessment.observations || []).slice(0, 5).map(obs => `
                  <div style="padding: var(--space-3); background: rgba(255,255,255,0.02); border-radius: var(--radius-md); border-left: 3px solid ${THRAGG_Charts.severityColor(obs.severity)};">
                    <div style="font-size: var(--font-size-xs); font-weight: var(--font-weight-semibold); color: ${THRAGG_Charts.severityColor(obs.severity)}; margin-bottom: var(--space-1);">${obs.severity} · ${obs.category}</div>
                    <div style="font-size: var(--font-size-sm); color: var(--text-secondary);">${obs.summary}</div>
                  </div>
                `).join('')}
              </div>
              `}
            </div>
          </div>
        </div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_DomainCoverage.render(document.getElementById('domains-grid'));
    });
  },

  /* ── View: Attack Chains ───────────────────────────────────────────── */
  _renderAttackChains(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Attack Chain Explorer</div>
          <div class="page-subtitle">Correlated attack narratives with step-by-step analysis</div>
        </div>
        <div id="chains-container"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_AttackChainExplorer.render(document.getElementById('chains-container'));
    });
  },

  /* ── View: MITRE Coverage ──────────────────────────────────────────── */
  _renderMITRE(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">MITRE ATT&CK Coverage</div>
          <div class="page-subtitle">Techniques identified across all attack chains and correlations</div>
        </div>
        <div id="mitre-content"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_MITRECoverage.render(document.getElementById('mitre-content'));
    });
  },

  /* ── View: Traceability ────────────────────────────────────────────── */
  _renderTraceability(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Traceability Explorer</div>
          <div class="page-subtitle">End-to-end evidence chain from recommendation to raw finding</div>
        </div>
        <div id="traceability-content"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_TraceabilityExplorer.render(document.getElementById('traceability-content'));
    });
  },

  /* ── View: Knowledge Graph ─────────────────────────────────────────── */
  _renderKnowledgeGraph(container) {
    container.innerHTML = `
      <div class="view-container view-container--canvas animate-fade-in-up">
        <div class="view-header" style="flex-shrink: 0; padding: var(--space-8) var(--space-8) var(--space-5);">
          <div class="page-title">Knowledge Graph</div>
          <div class="page-subtitle">Relationship graph of resolved entities and their connections</div>
        </div>
        <div id="kg-content" style="flex: 1; min-height: 0; display: flex; flex-direction: column;"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_KnowledgeGraph.render(document.getElementById('kg-content'));
    });
  },

  /* ── View: Recommendations ─────────────────────────────────────────── */
  _renderRecommendations(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Recommendations</div>
          <div class="page-subtitle">Prioritized actions to improve security posture</div>
        </div>
        <div id="recs-content"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_Recommendations.render(document.getElementById('recs-content'));
    });
  },

  /* ── View: Activity Timeline ───────────────────────────────────────── */
  _renderActivityTimeline(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Activity Timeline</div>
          <div class="page-subtitle">Chronological sequence of security events and detections</div>
        </div>
        <div id="timeline-content" style="max-width: 700px;"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_ActivityTimeline.render(document.getElementById('timeline-content'));
    });
  },

  /* ── View: Report Downloads ────────────────────────────────────────── */
  _renderReportDownloads(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Report Downloads</div>
          <div class="page-subtitle">Export intelligence in multiple formats</div>
        </div>
        <div id="downloads-content"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_ReportDownloads.render(document.getElementById('downloads-content'));
    });
  },

  /* ── View: Entity Explorer ─────────────────────────────────────────── */
  _renderEntityExplorer(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Entity Explorer</div>
          <div class="page-subtitle">Search, filter, and inspect normalized entities</div>
        </div>
        <div id="entities-content"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_EntityExplorer.render(document.getElementById('entities-content'));
    });
  },

  /* ── View: Finding Explorer ────────────────────────────────────────── */
  _renderFindingExplorer(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Finding Explorer</div>
          <div class="page-subtitle">Triage and filter security findings</div>
        </div>
        <div id="findings-content"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_FindingExplorer.render(document.getElementById('findings-content'));
    });
  },

  /* ── View: Session Overview ────────────────────────────────────────── */
  _renderSessionOverview(container) {
    container.innerHTML = `
      <div class="view-container animate-fade-in-up">
        <div class="view-header">
          <div class="page-title">Session Overview</div>
          <div class="page-subtitle">Execution footprint and data source details</div>
        </div>
        <div id="session-content"></div>
      </div>
    `;

    requestAnimationFrame(() => {
      THRAGG_SessionOverview.render(document.getElementById('session-content'));
    });
  },

  /* ── Initialize navigation event delegation ────────────────────────── */
  _initNavigation() {
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.ctrlKey || e.metaKey) return;
      const navMap = {
        '1': 'executive', '2': 'posture', '3': 'risks',
        '4': 'domains', '5': 'chains', '6': 'mitre',
        '7': 'traceability', '8': 'graph', '9': 'recommendations'
      };
      if (navMap[e.key]) {
        this.navigate(navMap[e.key]);
      }
    });
  },

  /* ── Global search ─────────────────────────────────────────────────── */
  _initGlobalSearch() {
    const searchInput = document.getElementById('global-search');
    if (!searchInput) return;

    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && searchInput.value.trim()) {
        // Simple search: navigate to relevant view
        const query = searchInput.value.toLowerCase();
        if (query.includes('chain') || query.includes('attack')) {
          this.navigate('chains');
        } else if (query.includes('risk') || query.includes('score')) {
          this.navigate('risks');
        } else if (query.includes('mitre') || query.includes('technique')) {
          this.navigate('mitre');
        } else if (query.includes('recommend') || query.includes('fix')) {
          this.navigate('recommendations');
        } else if (query.includes('entity') || query.includes('graph')) {
          this.navigate('graph');
        } else {
          this.navigate('executive');
        }
        searchInput.value = '';
      }
    });
  }
};

/* ── Bootstrap on DOM ready ──────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const parts = window.location.pathname.split('/');
    const sessionId = parts[parts.length - 1];
    if (!sessionId || sessionId === 'dashboard') {
      throw new Error('No session ID found in URL.');
    }

    const res = await fetch(`/api/results/${sessionId}`);
    if (!res.ok) {
      throw new Error(`Failed to load intelligence data (Status: ${res.status})`);
    }

    window.THRAGG_DATA = await res.json();
    window.THRAGG_SESSION_ID = sessionId;
    
    // Add brief artificial delay to ensure the premium splash screen is seen briefly
    setTimeout(() => {
      THRAGG_App.init();
    }, 800);
  } catch (err) {
    const splash = document.getElementById('loading-splash');
    if (splash) {
      splash.innerHTML = `
        <div style="color:var(--color-critical); text-align:center;">
          <h2 style="margin-bottom:12px;">Data Load Failed</h2>
          <p>${err.message}</p>
          <button style="margin-top:20px; padding:10px 20px; background:var(--brand-primary); border:none; border-radius:4px; color:white; cursor:pointer;" onclick="window.location.href='/'">Return to Upload</button>
        </div>
      `;
    }
  }
});
