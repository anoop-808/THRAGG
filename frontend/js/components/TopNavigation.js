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
      <div class="topnav-left">
        <div class="topnav-breadcrumb">
          <span>THRAGG</span>
          <span>›</span>
          <span id="current-view-label">${this._viewLabel(currentView)}</span>
        </div>
      </div>
      <div class="topnav-right">
        <div class="topnav-search">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="opacity:0.5">
            <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
          </svg>
          <input type="text" placeholder="Search findings, entities, chains..." id="global-search">
        </div>
        <div class="topnav-time" id="topnav-time"></div>
        <div class="topnav-actions">
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
  },

  /* ── Update breadcrumb label ───────────────────────────────────────── */
  updateView(currentView) {
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
