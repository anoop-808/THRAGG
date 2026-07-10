/* ==========================================================================
   THRAGG — Sidebar Navigation
   ========================================================================== */

const THRAGG_Sidebar = {
  /* ── Navigation items grouped by section ───────────────────────────── */
  sections: [
    {
      name: 'Investigations',
      items: [
        { id: 'active_case', label: 'Active Case', icon: 'security' },
        { id: 'new_case', label: 'New Investigation', icon: 'dashboard' },
        { id: 'archive_case', label: 'Investigation Archive', icon: 'layers' }
      ]
    },
    {
      name: 'Overview',
      items: [
        { id: 'executive', label: 'Executive Overview', icon: 'dashboard' }
      ]
    },
    {
      name: 'Intelligence',
      items: [
        { id: 'posture', label: 'Security Posture', icon: 'security' },
        { id: 'risks', label: 'Risk Distribution', icon: 'assessment' },
        { id: 'domains', label: 'Domain Coverage', icon: 'layers' }
      ]
    },
    {
      name: 'Analysis',
      items: [
        { id: 'chains', label: 'Attack Chains', icon: 'timeline' },
        { id: 'mitre', label: 'MITRE Coverage', icon: 'grid_view' },
        { id: 'traceability', label: 'Traceability', icon: 'account_tree' }
      ]
    },
    {
      name: 'Investigation',
      items: [
        { id: 'entities', label: 'Entity Explorer', icon: 'search' },
        { id: 'findings', label: 'Finding Explorer', icon: 'bug' },
        { id: 'session', label: 'Session Overview', icon: 'info' }
      ]
    },
    {
      name: 'Resources',
      items: [
        { id: 'graph', label: 'Knowledge Graph', icon: 'hub' },
        { id: 'recommendations', label: 'Recommendations', icon: 'lightbulb' }
      ]
    },
    {
      name: 'Reports',
      items: [
        { id: 'timeline', label: 'Activity Timeline', icon: 'schedule' },
        { id: 'downloads', label: 'Report Downloads', icon: 'download' }
      ]
    }
  ],

  /* ── Icon SVG paths ────────────────────────────────────────────────── */
  icons: {
    dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="4" rx="1"/><rect x="14" y="10" width="7" height="11" rx="1"/><rect x="3" y="13" width="7" height="8" rx="1"/></svg>',
    security: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    assessment: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2"/><rect x="9" y="3" width="6" height="4" rx="1"/><path d="M9 14l2 2 4-4"/></svg>',
    layers: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>',
    timeline: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 4-6"/></svg>',
    grid_view: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
    account_tree: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-8M6 12H2"/><path d="M10 6h4v12h-4z"/><circle cx="10" cy="6" r="2"/><circle cx="10" cy="18" r="2"/><circle cx="6" cy="12" r="2"/><circle cx="18" cy="12" r="2"/></svg>',
    hub: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 2v7m0 6v7M2 12h7m6 0h7"/></svg>',
    lightbulb: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18h6"/><path d="M10 22h4"/><path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0018 8 6 6 0 006 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 018.91 14"/></svg>',
    schedule: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
    download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    bug: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="M12 11h4"/><path d="M12 16h4"/><path d="M8 11h.01"/><path d="M8 16h.01"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
  },

  /* ── Render the sidebar ────────────────────────────────────────────── */
  render(container, activeView) {
    if (!container) return;

    let html = `
      <div class="sidebar-brand">
        <div class="sidebar-brand-icon">T</div>
        <span class="sidebar-brand-name">THRAGG</span>
        <span class="sidebar-brand-version">v1.0</span>
      </div>
      <nav class="sidebar-nav">
    `;

    this.sections.forEach((section) => {
      html += `<div class="sidebar-nav-section">${section.name}</div>`;
      section.items.forEach((item) => {
        const isActive = item.id === activeView;
        html += `
          <div class="sidebar-nav-item ${isActive ? 'active' : ''}"
               data-view="${item.id}"
               onclick="THRAGG_App.navigate('${item.id}')">
            <span class="sidebar-nav-icon">${this.icons[item.icon] || ''}</span>
            ${item.label}
          </div>
        `;
      });
    });

    html += `
      </nav>
      <div class="sidebar-footer">
        <div class="sidebar-footer-info">
          <span class="sidebar-footer-dot"></span>
          <span>All systems operational</span>
        </div>
      </div>
    `;

    container.innerHTML = html;
  },

  /* ── Update active state ───────────────────────────────────────────── */
  setActive(viewId) {
    const items = document.querySelectorAll('.sidebar-nav-item');
    items.forEach((item) => {
      item.classList.toggle('active', item.dataset.view === viewId);
    });
  }
};
