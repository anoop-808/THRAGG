/* ==========================================================================
   THRAGG — Top Navigation
   ========================================================================== */

const THRAGG_TopNavigation = {
  /* ── Render the top nav ────────────────────────────────────────────── */
  render(container, currentView) {
    if (!container) return;

    // Clear any existing clock interval to prevent leaks
    if (this._clockInterval) {
      clearInterval(this._clockInterval);
      this._clockInterval = null;
    }

    container.innerHTML = `
      <div class="topnav-left" id="topnav-breadcrumb-container">
        <div class="topnav-breadcrumb">
          <span style="cursor:pointer;" onclick="THRAGG_InvestigationSession.clearContext()">Session</span>
          <span style="margin: 0 8px; color: var(--text-muted)">›</span>
          <span id="current-view-label" style="color:var(--brand-light)">${this._viewLabel(currentView)}</span>
        </div>
      </div>
      <div class="topnav-right">
        <div class="topnav-filters">
          <select id="global-filter-severity">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select id="global-filter-type">
            <option value="ALL">All Types</option>
            <option value="ip">IP</option>
            <option value="domain">Domain</option>
            <option value="hash">File Hash</option>
            <option value="user">User</option>
          </select>
        </div>
        <div class="topnav-search">
          <button class="btn btn-secondary" style="width:100%; justify-content:flex-start; font-weight:var(--font-weight-normal);" onclick="if(typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('TOGGLE_COMMAND_PALETTE')">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:var(--space-2);">
              <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
            </svg>
            Search intelligence, cases, and actions... (Ctrl+K)
          </button>
        </div>
        <div class="topnav-actions">
          <button class="btn btn-secondary" style="margin-right: 8px; font-size: 11px;" onclick="if(typeof THRAGG_EventBus !== 'undefined') { THRAGG_EventBus.emit('REPLAY_START_REQUEST'); if(typeof THRAGG_App !== 'undefined') THRAGG_App.navigate('replay_timeline'); }">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="margin-right:4px;"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Replay Mode
          </button>
          <button class="topnav-btn" title="Notifications" onclick="alert('Notifications panel coming soon')">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/>
            </svg>
            <span class="badge-dot"></span>
          </button>
          <button class="topnav-btn" title="Settings">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="3"/><path d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
            </svg>
          </button>
        </div>
      </div>
    `;

    this._updateClock();
    this._initSearchListeners();
    this._initListeners();
  },

  _initSearchListeners() {
    const input = document.getElementById('global-search');
    const dropdown = document.getElementById('search-results');
    if (!input || !dropdown) return;

    input.addEventListener('input', (e) => {
      const q = e.target.value.trim();
      if (!q) {
        dropdown.classList.add('hidden');
        return;
      }
      const results = THRAGG_GlobalSearch.search(q);
      if (results.length === 0) {
        dropdown.innerHTML = '<div class="search-item"><div class="search-item-desc">No results found</div></div>';
      } else {
        dropdown.innerHTML = results.map(r => `
          <div class="search-item" data-target="${r.target}" data-label="${r.label}">
            <div class="search-item-title">${r.label} <span class="badge" style="font-size:10px;margin-left:8px;">${r.type}</span></div>
            <div class="search-item-desc">${r.desc}</div>
          </div>
        `).join('');
      }
      dropdown.classList.remove('hidden');
    });

    dropdown.addEventListener('click', (e) => {
      const item = e.target.closest('.search-item');
      if (item && item.dataset.target) {
        THRAGG_App.navigate(item.dataset.target);
        dropdown.classList.add('hidden');
        input.value = '';
      }
    });

    document.addEventListener('click', (e) => {
      if (!input.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.classList.add('hidden');
      }
    });

    this._updateClock();
  },

  /* ── Listeners ─────────────────────────────────────────────────────── */
  _initListeners() {
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('CONTEXT_CHANGED', () => this.updateBreadcrumbs());
    }
  },

  /* ── Dynamic Breadcrumbs ───────────────────────────────────────────── */
  updateBreadcrumbs() {
    const container = document.getElementById('topnav-breadcrumb-container');
    if (!container) return;

    if (typeof THRAGG_InvestigationSession === 'undefined' || !THRAGG_InvestigationSession.history.length) {
      // Default view
      const viewLabel = this._viewLabel(typeof THRAGG_App !== 'undefined' ? THRAGG_App.currentView : 'executive');
      container.innerHTML = `
        <div class="topnav-breadcrumb" style="animation: fadeInUp 0.3s ease;">
          <span style="cursor:pointer; transition:color 0.2s;" onmouseover="this.style.color='var(--brand-primary)'" onmouseout="this.style.color=''">Session</span>
          <span style="margin: 0 8px; color: var(--text-muted)">›</span>
          <span id="current-view-label" style="color:var(--brand-light)">${viewLabel}</span>
        </div>
      `;
      return;
    }

    const history = THRAGG_InvestigationSession.history;
    const currentIndex = THRAGG_InvestigationSession.currentIndex;

    let html = `<div class="topnav-breadcrumb" style="animation: fadeInUp 0.3s ease;">
      <span style="cursor:pointer; transition:color 0.2s;" onmouseover="this.style.color='var(--brand-primary)'" onmouseout="this.style.color=''" onclick="THRAGG_InvestigationSession.clearContext()">Session</span>`;

    for (let i = 0; i <= currentIndex; i++) {
      const item = history[i];
      if (!item.type || !item.id) continue;
      
      const isLast = i === currentIndex;
      html += `
        <span style="margin: 0 8px; color: var(--text-muted)">›</span>
        <span style="cursor:${isLast ? 'default' : 'pointer'}; color:${isLast ? 'var(--brand-light)' : 'var(--text-secondary)'}; transition:color 0.2s;"
              ${!isLast ? `onmouseover="this.style.color='var(--brand-primary)'" onmouseout="this.style.color='var(--text-secondary)'" onclick="THRAGG_InvestigationSession.jumpTo(${i})"` : ''}>
          ${item.id}
        </span>
      `;
    }
    
    html += `</div>`;
    container.innerHTML = html;
  },

  /* ── Update breadcrumb label (Fallback) ────────────────────────────── */
  updateView(currentView) {
    if (typeof THRAGG_InvestigationSession !== 'undefined' && THRAGG_InvestigationSession.activeContext) return;
    const label = document.getElementById('current-view-label');
    if (label) label.textContent = this._viewLabel(currentView);
  },

  /* ── Live clock ────────────────────────────────────────────────────── */
  _updateClock() {
    const el = document.getElementById('topnav-time');
    if (!el) return;

    const update = () => {
      const now = new Date();
      el.textContent = now.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short'
      });
    };
    update();
    this._clockInterval = setInterval(update, 1000);
  },

  /* ── Friendly view label ───────────────────────────────────────────── */
  _viewLabel(viewId) {
    const labels = {
      executive: 'Executive Overview',
      posture: 'Security Posture',
      risks: 'Risk Distribution',
      domains: 'Domain Coverage',
      chains: 'Attack Chains',
      mitre: 'MITRE Coverage',
      traceability: 'Traceability Explorer',
      graph: 'Knowledge Graph',
      recommendations: 'Recommendations',
      timeline: 'Activity Timeline',
      downloads: 'Report Downloads'
    };
    return labels[viewId] || 'Dashboard';
  }
};
