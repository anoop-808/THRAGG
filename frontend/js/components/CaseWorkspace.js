/* ==========================================================================
   THRAGG — Case Workspace Component
   ========================================================================== */

const THRAGG_CaseWorkspace = {
  _listenerAttached: false,

  render(container) {
    if (!container) return;

    if (!this._listenerAttached && typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('CASE_SELECTED', () => this.render(container));
      THRAGG_EventBus.on('CASE_UPDATED', () => this.render(container));
      THRAGG_EventBus.on('CASE_STATUS_CHANGED', () => this.render(container));
      THRAGG_EventBus.on('BOOKMARK_ADDED', () => this.render(container));
      THRAGG_EventBus.on('BOOKMARK_REMOVED', () => this.render(container));
      THRAGG_EventBus.on('NOTE_CREATED', () => this.render(container));
      this._listenerAttached = true;
    }

    const c = THRAGG_CaseManager.getActiveCase();

    if (!c) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-title" style="font-size: var(--font-size-lg); color: var(--text-primary);">No Active Investigation</div>
          <div class="empty-state-text" style="color: var(--text-secondary);">Select or create an investigation to begin.</div>
          <button class="btn btn-primary" style="margin-top: var(--space-4);" onclick="THRAGG_CaseManager.createCase().then(()=>THRAGG_App.navigate('active_case'))">Start New Investigation</button>
        </div>
      `;
      return;
    }

    // Resolve bookmarks using THRAGG_DATA
    const resolvedBookmarks = c.bookmarks.map(b => {
      let title = b.id;
      let severity = null;
      const t = b.type.toLowerCase();
      
      if (t === 'entity') {
        const ent = (THRAGG_DATA.resolved_entities || []).find(e => e.id === b.id) || (THRAGG_DATA.entities || []).find(e => e.id === b.id);
        if (ent) title = ent.primary_identifier || ent.attributes?.hostname || ent.attributes?.name || ent.id;
      } else if (t === 'finding' || t === 'observation' || t === 'correlation') {
        const finding = (THRAGG_DATA.executive_assessment?.observations || []).find(o => o.summary.includes(b.id) || o.id === b.id) || 
                        (THRAGG_DATA.correlations || []).find(co => co.title === b.id || co.id === b.id);
        if (finding) {
           title = finding.summary || finding.title;
           severity = finding.severity || finding.risk_level;
        }
      } else if (t === 'attack chain' || t === 'attack_chain') {
        const chain = (THRAGG_DATA.attack_chains || []).find(ch => ch.id === b.id || ch.title === b.id);
        if (chain) {
          title = chain.title;
          severity = chain.severity;
        }
      }

      if (title.length > 50) title = title.substring(0, 50) + '...';
      
      return { ...b, title, severity };
    });

    const severityColor = THRAGG_Charts ? THRAGG_Charts.severityColor(c.severity) : 'var(--text-muted)';
    
    let html = `
      <div class="view-header">
        <div style="display:flex; justify-content:space-between; align-items:flex-start;">
          <div>
            <div class="page-title" style="display:flex; align-items:center; gap:var(--space-2);">
              <span id="case-title-display">${c.title}</span>
              <button class="btn-icon" style="color:var(--text-muted); cursor:pointer;" onclick="const t = prompt('Rename investigation:', '${c.title}'); if(t) THRAGG_CaseManager.renameCase('${c.id}', t);" title="Rename Case">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
              </button>
            </div>
            <div class="page-subtitle">Investigation ID: <span style="font-family:var(--font-mono);">${c.id}</span> · Created: ${new Date(c.created_at).toLocaleString()}</div>
          </div>
          <div style="display:flex; gap:var(--space-3);">
            <div style="display:flex; flex-direction:column; gap:4px;">
              <span style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">Status</span>
              <select class="form-select" style="background:var(--bg-glass); border:1px solid var(--border-medium); color:var(--text-primary); border-radius:4px; padding:4px 8px; font-size:12px; cursor:pointer;" onchange="THRAGG_CaseManager.setStatus(this.value)">
                ${['Open', 'Monitoring', 'Escalated', 'Resolved', 'Closed'].map(s => `<option value="${s}" ${c.status === s ? 'selected' : ''}>${s}</option>`).join('')}
              </select>
            </div>
            <div style="display:flex; flex-direction:column; gap:4px;">
              <span style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">Severity</span>
              <select class="form-select" style="background:var(--bg-glass); border:1px solid var(--border-medium); color:${severityColor}; border-radius:4px; padding:4px 8px; font-size:12px; cursor:pointer;" onchange="THRAGG_CaseManager.setSeverity(this.value)">
                ${['Informational', 'Low', 'Medium', 'High', 'Critical'].map(s => `<option value="${s}" ${c.severity === s ? 'selected' : ''}>${s}</option>`).join('')}
              </select>
            </div>
          </div>
        </div>
      </div>
      
      <div class="grid grid-2" style="margin-top:var(--space-6);">
        <!-- Left Column: Bookmarks & Notes -->
        <div style="display:flex; flex-direction:column; gap:var(--space-6);">
          
          <!-- Bookmarks -->
          <div class="card stagger-item">
            <div class="card-header">
              <span class="section-title" style="margin:0;">Bookmarked Intelligence</span>
              <span class="badge badge-default">${c.bookmarks.length}</span>
            </div>
            <div class="card-body">
              ${c.bookmarks.length === 0 ? `
                <div class="empty-state-text" style="padding:16px; text-align:center;">No items bookmarked. Pivot through the workspace and click 'Add to Investigation'.</div>
              ` : `
                <div style="display:flex; flex-direction:column; gap:var(--space-2);">
                  ${resolvedBookmarks.map(b => `
                    <div style="display:flex; justify-content:space-between; align-items:center; padding:var(--space-2) var(--space-3); background:var(--bg-glass); border-radius:var(--radius-sm); border:1px solid var(--border-glass);">
                      <div style="display:flex; align-items:center; gap:12px; cursor:pointer;" onclick="THRAGG_InvestigationSession.setContext('${b.type}', '${b.id}')">
                        <span class="tag">${b.type}</span>
                        <div>
                          <div style="font-size:var(--font-size-sm); color:var(--text-primary); font-family:var(--font-mono);">${b.title}</div>
                          ${b.severity ? `<div style="font-size:10px; color:${THRAGG_Charts ? THRAGG_Charts.severityColor(b.severity) : 'inherit'};">${b.severity}</div>` : ''}
                        </div>
                      </div>
                      <button class="btn-icon" style="color:var(--color-critical); opacity:0.6; cursor:pointer;" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=0.6" onclick="THRAGG_CaseManager.removeBookmark('${b.type}', '${b.id}')" title="Remove Bookmark">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                      </button>
                    </div>
                  `).join('')}
                </div>
              `}
            </div>
          </div>
          
          <!-- Notes -->
          <div class="card stagger-item">
            <div class="card-header">
              <span class="section-title" style="margin:0;">Analyst Notes</span>
            </div>
            <div class="card-body" style="display:flex; flex-direction:column; gap:var(--space-4);">
              <div style="display:flex; gap:var(--space-2);">
                <textarea id="case-note-input" style="flex:1; background:var(--bg-elevated); border:1px solid var(--border-medium); color:var(--text-primary); border-radius:var(--radius-sm); padding:var(--space-2) var(--space-3); font-size:var(--font-size-sm); resize:vertical; min-height:60px;" placeholder="Add an investigation note..."></textarea>
                <button class="btn btn-primary btn-sm" style="align-self:flex-end;" onclick="
                  const val = document.getElementById('case-note-input').value;
                  if(val) THRAGG_CaseManager.addNote(val);
                ">Add</button>
              </div>
              <div style="display:flex; flex-direction:column; gap:var(--space-3); max-height:400px; overflow-y:auto; padding-right:4px;">
                ${c.notes.slice().reverse().map(n => `
                  <div style="padding:var(--space-3); background:rgba(255,255,255,0.02); border-left:2px solid var(--brand-primary); border-radius:0 var(--radius-sm) var(--radius-sm) 0;">
                    <div style="font-size:12px; color:var(--text-secondary); white-space:pre-wrap; line-height:1.5;">${n.content}</div>
                    <div style="font-size:10px; color:var(--text-muted); margin-top:8px; display:flex; justify-content:space-between;">
                      <span>${n.author}</span>
                      <span>${new Date(n.timestamp).toLocaleString()}</span>
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>
          </div>
          
        </div>
        
        <!-- Right Column: Timeline -->
        <div class="card stagger-item">
          <div class="card-header">
            <span class="section-title" style="margin:0;">Case Timeline</span>
          </div>
          <div class="card-body" style="max-height:800px; overflow-y:auto; padding-right:8px;">
            <div class="activity-timeline">
              ${c.timeline.slice().reverse().map(ev => `
                <div class="activity-item" style="padding-bottom:16px;">
                  <div class="activity-dot info"></div>
                  <div class="activity-time">${THRAGG_Charts ? THRAGG_Charts.timeAgo(ev.timestamp) : new Date(ev.timestamp).toLocaleTimeString()}</div>
                  <div class="activity-title" style="font-size:13px;">${ev.action}</div>
                  <div class="activity-detail" style="font-size:11px;">${ev.details}</div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
      </div>
    `;

    container.innerHTML = html;
  }
};
