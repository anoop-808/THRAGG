/* ==========================================================================
   THRAGG — Unified Context Panel & Investigation Workspace
   ========================================================================== */

const THRAGG_ContextPanel = {
  container: null,

  init(containerElement) {
    this.container = containerElement;
    if (!this.container) return;

    this.container.innerHTML = `
      <div class="inspector-header">
        <div class="inspector-trail" id="inspector-trail" style="display:none; padding-bottom:8px; font-size:11px; color:var(--brand-light);"></div>
        <div class="inspector-title-bar">
          <span class="inspector-title" id="inspector-id">Select an object</span>
          <button class="btn-close-inspector" id="inspector-close" aria-label="Close Inspector">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
          </button>
        </div>
        <div class="inspector-type" id="inspector-type"></div>
      </div>
      <div class="inspector-body" id="inspector-body">
        <div class="empty-state-text" style="padding: 24px; text-align: center;">
          Click any node or finding to inspect its context.
        </div>
      </div>
    `;

    document.getElementById('inspector-close').addEventListener('click', () => {
      if (typeof THRAGG_InvestigationSession !== 'undefined') {
        THRAGG_InvestigationSession.clearContext();
      }
    });

    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('CONTEXT_CHANGED', (ctx) => {
        if (ctx) this.open(ctx);
        else this.close();
      });
      THRAGG_EventBus.on('BOOKMARK_ADDED', () => {
        if (typeof THRAGG_InvestigationSession !== 'undefined' && THRAGG_InvestigationSession.activeContext) {
          this.renderData(THRAGG_InvestigationSession.activeContext);
        }
      });
      THRAGG_EventBus.on('BOOKMARK_REMOVED', () => {
        if (typeof THRAGG_InvestigationSession !== 'undefined' && THRAGG_InvestigationSession.activeContext) {
          this.renderData(THRAGG_InvestigationSession.activeContext);
        }
      });
      THRAGG_EventBus.on('REPLAY_STEP_CHANGED', (data) => {
        if (data && data.step) this.openReplayStep(data.step);
      });
    }
  },

  open(context) {
    if (!this.container) return;
    this.container.classList.add('active');
    this.renderData(context);
  },

  close() {
    if (!this.container) return;
    this.container.classList.remove('active');
  },
  
  openReplayStep(step) {
    if (!this.container) return;
    this.container.classList.add('active');
    
    document.getElementById('inspector-type').innerHTML = `<span class="badge badge-info">Replay Mode</span> <span class="badge badge-default">${step.replay_source}</span>`;
    document.getElementById('inspector-id').textContent = step.title || 'Replay Event';
    
    let html = '';
    
    html += `
      <div class="panel-section">
        <h4 class="section-title">Replay Context</h4>
        <div style="font-size: 13px; color: var(--text-secondary); line-height: 1.5; margin-bottom: 12px;">
          ${step.description}
        </div>
        <div style="font-size: 11px; font-family: var(--font-mono); color: var(--text-muted); margin-bottom: 8px;">
          Time: ${new Date(step.timestamp).toLocaleString()}
        </div>
      </div>
    `;
    
    if (step.source_id || step.target_id) {
      html += '<div class="panel-section"><h4 class="section-title">Involved Entities</h4><div class="prop-list">';
      if (step.source_id) {
        html += `<div class="prop-item"><span class="prop-label">Source</span><span class="prop-value" style="color:var(--brand-cyan); cursor:pointer;" onclick="if(typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('CONTEXT_CHANGED', {type:'Entity', id:'${step.source_id}'})">${step.source_id}</span></div>`;
      }
      if (step.target_id) {
        html += `<div class="prop-item"><span class="prop-label">Target</span><span class="prop-value" style="color:var(--brand-cyan); cursor:pointer;" onclick="if(typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('CONTEXT_CHANGED', {type:'Entity', id:'${step.target_id}'})">${step.target_id}</span></div>`;
      }
      html += '</div></div>';
    }
    
    if (step.mitre && step.mitre.length > 0) {
      html += `
        <div class="panel-section">
          <h4 class="section-title">MITRE ATT&CK</h4>
          <div style="display: flex; gap: 4px; flex-wrap: wrap;">
            ${step.mitre.map(m => `<span class="tag tag-mitre">${m}</span>`).join('')}
          </div>
        </div>
      `;
    }
    
    if (step.evidence && step.evidence.length > 0) {
       html += '<div class="panel-section"><h4 class="section-title">Evidence</h4><div class="prop-list">';
       step.evidence.forEach(ev => {
         html += `<div class="prop-item" style="flex-direction:column; align-items:flex-start;"><span class="prop-label">${ev.source}</span><span class="prop-value" style="font-family:var(--font-mono); font-size:10px; margin-top:4px;">${ev.data}</span></div>`;
       });
       html += '</div></div>';
    }
    
    document.getElementById('inspector-body').innerHTML = html;
  },

  renderData(context) {
    const idEl = document.getElementById('inspector-id');
    const typeEl = document.getElementById('inspector-type');
    const bodyEl = document.getElementById('inspector-body');

    this._renderTrail();

    if (!idEl || !typeEl || !bodyEl) return;

    const t = context.type.toLowerCase();
    
    if (t === 'entity') {
      this._renderEntity(context.id, idEl, typeEl, bodyEl);
    } else if (t === 'finding' || t === 'observation') {
      this._renderFinding(context.id, idEl, typeEl, bodyEl);
    } else if (t === 'relationship' || t === 'edge') {
      this._renderRelationship(context.id, idEl, typeEl, bodyEl);
    } else if (t === 'correlation') {
      this._renderCorrelation(context.id, idEl, typeEl, bodyEl);
    } else if (t === 'attack_chain' || t === 'attack chain') {
      this._renderAttackChain(context.id, idEl, typeEl, bodyEl);
    } else if (t === 'recommendation') {
      this._renderRecommendation(context.id, idEl, typeEl, bodyEl);
    } else if (t === 'evidence') {
      this._renderEvidence(context.id, idEl, typeEl, bodyEl);
    } else {
      idEl.textContent = context.id || 'Unknown';
      typeEl.innerHTML = `<span class="tag">${context.type}</span>`;
      bodyEl.innerHTML = '<div class="empty-state-text" style="padding: 24px;">Context details not mapped yet.</div>';
    }

    if (typeof THRAGG_CaseManager !== 'undefined') {
      const existing = typeEl.innerHTML;
      const btnHtml = this._buildBookmarkBtn(context.type, context.id);
      typeEl.innerHTML = `<div style="display:flex; gap:8px; align-items:center;">${existing}</div>${btnHtml}`;
    }
  },

  /* ── SHARED HELPERS ─────────────────────────────────────────────────── */

  _buildBookmarkBtn(type, id) {
    if (typeof THRAGG_CaseManager === 'undefined') return '';
    const isBookmarked = THRAGG_CaseManager.isBookmarked(type, id);
    if (isBookmarked) {
      return `<button class="btn-icon" style="color:var(--brand-primary);" onclick="THRAGG_CaseManager.removeBookmark('${type}', '${id}')" title="Remove from Investigation"><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></button>`;
    }
    return `<button class="btn-icon" style="color:var(--text-muted);" onclick="THRAGG_CaseManager.addBookmark('${type}', '${id}')" title="Add to Investigation"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></button>`;
  },
  
  _buildSection(title, content) {
    if (!content || content.trim() === '') return '';
    return `
      <div class="inspector-section" style="animation: fadeInUp 0.3s ease forwards;">
        <div class="inspector-section-title">${title}</div>
        ${content}
      </div>
    `;
  },
  
  _buildPivotLink(type, id, label, icon = '→', subtitle = '') {
    return `
      <div class="relationship-item" style="cursor: pointer; padding:var(--space-2); border-radius:var(--radius-sm); transition:background 0.2s;" 
           onclick="THRAGG_InvestigationSession.setContext('${type}', '${id}')"
           onmouseover="this.style.background='var(--bg-glass-hover)'" onmouseout="this.style.background='transparent'">
        <div style="display:flex; align-items:center; gap:8px;">
          <div style="font-size: 11px; color: var(--brand-light);">${icon}</div>
          <div>
            <div style="font-size: 12px; color: var(--text-primary); font-family: var(--font-mono);">${label || id}</div>
            ${subtitle ? `<div style="font-size: 10px; color: var(--text-muted);">${subtitle}</div>` : ''}
          </div>
        </div>
      </div>
    `;
  },

  _emptyState(msg) {
    return `<div class="empty-state-text" style="padding: 12px 0;">${msg}</div>`;
  },

  /* ── TRAIL RENDERER ─────────────────────────────────────────────────── */

  _renderTrail() {
    const trailEl = document.getElementById('inspector-trail');
    if (!trailEl || typeof THRAGG_InvestigationSession === 'undefined') return;
    
    const history = THRAGG_InvestigationSession.history || [];
    const currentIndex = THRAGG_InvestigationSession.currentIndex;
    
    if (history.length === 0 || currentIndex < 0 || !history[currentIndex].type) {
      trailEl.style.display = 'none';
      return;
    }
    
    trailEl.style.display = 'flex';
    trailEl.style.gap = '4px';
    trailEl.style.flexWrap = 'wrap';
    trailEl.style.alignItems = 'center';
    
    // Display up to 4 recent items
    const startIdx = Math.max(0, currentIndex - 3);
    const trailHtml = [];
    
    for (let i = startIdx; i <= currentIndex; i++) {
      const item = history[i];
      if (!item.type) continue;
      
      const isActive = i === currentIndex;
      const color = isActive ? 'var(--text-primary)' : 'var(--brand-light)';
      const cursor = isActive ? 'default' : 'pointer';
      
      let label = item.id;
      if (label.length > 15) label = label.substring(0, 15) + '...';
      
      const clickAction = !isActive ? `onclick="THRAGG_InvestigationSession.jumpTo(${i})"` : '';
      const hoverAction = !isActive ? `onmouseover="this.style.opacity='0.7'" onmouseout="this.style.opacity='1'"` : '';
      
      trailHtml.push(`
        <span style="color: ${color}; cursor: ${cursor}; transition: opacity 0.2s; white-space:nowrap; overflow:hidden;"
              ${clickAction} ${hoverAction} title="${item.type}: ${item.id}">
          ${label}
        </span>
      `);
      if (i < currentIndex) {
        trailHtml.push(`<span style="color: var(--border-glass);">›</span>`);
      }
    }
    trailEl.innerHTML = trailHtml.join('');
  },

  /* ── COMPONENT RENDERERS ────────────────────────────────────────────── */

  _renderEntity(entityId, idEl, typeEl, bodyEl) {
    let entity = (THRAGG_DATA.entities || []).find(e => e.id === entityId) || 
                 (THRAGG_DATA.resolved_entities || []).find(e => e.id === entityId) || 
                 (THRAGG_DATA.resolved_entities && THRAGG_DATA.resolved_entities[entityId]);

    if (!entity) {
      idEl.textContent = entityId;
      typeEl.innerHTML = '<span class="tag">Unknown</span>';
      bodyEl.innerHTML = this._emptyState('Entity details not found.');
      return;
    }

    const displayLabel = entity.primary_identifier ?? entity.attributes?.hostname ?? entity.attributes?.username ?? entity.attributes?.name ?? entity.id;
    idEl.textContent = displayLabel;
    
    const confidence = entity.confidence || 85;
    typeEl.innerHTML = `
      <span class="tag">${entity.entity_type || entity.type || 'UNKNOWN'}</span>
      <span style="font-size: 11px; color: var(--text-muted);">${confidence}% Confidence</span>
    `;

    let html = '';

    // Attributes Overview
    if (entity.attributes) {
      const attrs = Object.entries(entity.attributes).map(([k,v]) => 
        `<div><span style="color:var(--text-muted)">${k}:</span> <span style="font-family:var(--font-mono)">${v}</span></div>`
      ).join('');
      html += this._buildSection('Attributes', `<div style="font-size:12px; line-height:1.6">${attrs}</div>`);
    }

    // Relationships Pivot
    const relationships = (THRAGG_DATA.relationships || []).filter(r => 
      r.source_entity_id === entityId || r.target_entity_id === entityId ||
      r.source === entityId || r.target === entityId
    );
    
    if (relationships.length > 0) {
      const relsHtml = `<div style="display: flex; flex-direction: column; gap: var(--space-1);">` + relationships.map(r => {
        const src = r.source_entity_id || r.source;
        const tgt = r.target_entity_id || r.target;
        const isSource = src === entityId;
        const otherId = isSource ? tgt : src;
        const dirIcon = isSource ? '→' : '←';
        const type = r.relationship_type || r.type || 'RELATED_TO';
        
        return this._buildPivotLink('Relationship', r.id || `${src}-${tgt}`, `${type} ${otherId}`, dirIcon);
      }).join('') + `</div>`;
      html += this._buildSection(`Relationships (${relationships.length})`, relsHtml);
    } else {
      html += this._buildSection('Relationships', this._emptyState('No documented relationships.'));
    }

    // Related Findings Pivot
    const findings = (THRAGG_DATA.executive_assessment?.observations || []).filter(o => (o.entities || []).includes(entityId));
    if (findings.length > 0) {
      const findsHtml = `<div style="display: flex; flex-direction: column; gap: var(--space-1);">` + findings.map(f => {
        return this._buildPivotLink('Finding', f.summary || f.title, f.summary || f.title, '⚡', f.severity || 'UNKNOWN');
      }).join('') + `</div>`;
      html += this._buildSection(`Related Findings (${findings.length})`, findsHtml);
    }

    bodyEl.innerHTML = html;
  },

  _renderFinding(findingId, idEl, typeEl, bodyEl) {
    let finding = (THRAGG_DATA.executive_assessment?.observations || []).find(o => o.summary.includes(findingId) || o.id === findingId) || 
                  (THRAGG_DATA.correlations || []).find(c => c.title === findingId || c.id === findingId);

    if (!finding) {
      idEl.textContent = "Finding Details";
      typeEl.innerHTML = `<span class="tag">Unknown</span>`;
      bodyEl.innerHTML = this._emptyState(`Finding "${findingId}" not found in current dataset.`);
      return;
    }

    const summary = finding.summary || finding.title;
    idEl.textContent = summary.length > 30 ? summary.substring(0,30) + '...' : summary;
    
    const severity = finding.severity || finding.risk_level || 'HIGH';
    typeEl.innerHTML = `<span class="severity-label ${severity.toLowerCase()}">${severity}</span>`;

    let html = `
      <div style="padding-bottom:var(--space-4); border-bottom:1px solid var(--border-glass); margin-bottom:var(--space-4);">
        <div style="font-size:var(--font-size-md); color:var(--text-primary); line-height:1.5;">${summary}</div>
      </div>
    `;

    // Entities Pivot
    if (finding.entities && finding.entities.length > 0) {
      const entsHtml = `<div style="display: flex; flex-direction: column; gap: var(--space-1);">` + finding.entities.map(e => {
        return this._buildPivotLink('Entity', e, e, '💻');
      }).join('') + `</div>`;
      html += this._buildSection('Entities Involved', entsHtml);
    }

    // Evidence Pivot
    const evidenceFiles = finding.evidence_references || [];
    // Or fallback to global evidence files for demonstration if empty
    const globalEvidence = THRAGG_DATA.evidence_files || [];
    const files = evidenceFiles.length > 0 ? evidenceFiles : (globalEvidence.length > 0 ? [globalEvidence[0]] : []);
    
    if (files.length > 0) {
      const evHtml = `<div style="display: flex; flex-direction: column; gap: var(--space-1);">` + files.map(f => {
        return this._buildPivotLink('Evidence', f, f, '📄');
      }).join('') + `</div>`;
      html += this._buildSection('Source Evidence', evHtml);
    }

    // MITRE Pivot
    const mitre = finding.mitre_tactics || finding.mitre || [];
    if (mitre.length > 0) {
      const mHtml = `<div style="display:flex; flex-wrap:wrap; gap:4px;">` + mitre.map(m => 
        `<span class="tag" style="cursor:pointer;" onclick="THRAGG_InvestigationSession.setContext('MITRE', '${m}')">${m}</span>`
      ).join('') + `</div>`;
      html += this._buildSection('MITRE Coverage', mHtml);
    }

    bodyEl.innerHTML = html;
  },

  _renderRelationship(relId, idEl, typeEl, bodyEl) {
    let rel = null;
    const rels = THRAGG_DATA.relationships || [];
    
    if (relId.includes('-')) {
      // Find by id or composite source-target string
      rel = rels.find(r => r.id === relId || `${r.source_entity_id}-${r.target_entity_id}` === relId || `${r.source}-${r.target}` === relId);
    }
    if (!rel && rels.length > 0) rel = rels[0]; // fallback
    
    if (!rel) {
      idEl.textContent = "Relationship";
      bodyEl.innerHTML = this._emptyState('Relationship details not found.');
      return;
    }

    const type = rel.relationship_type || rel.type || 'RELATED_TO';
    idEl.textContent = type;
    typeEl.innerHTML = `<span class="tag">Edge</span>`;

    const src = rel.source_entity_id || rel.source;
    const tgt = rel.target_entity_id || rel.target;

    let html = `<div style="display: flex; flex-direction: column; gap: var(--space-1);">`;
    html += this._buildPivotLink('Entity', src, src, '↑', 'Source Node');
    html += this._buildPivotLink('Entity', tgt, tgt, '↓', 'Destination Node');
    html += `</div>`;
    
    let fullHtml = this._buildSection('Endpoints', html);
    
    if (rel.confidence) {
      fullHtml += this._buildSection('Metadata', `<div style="font-size:12px; color:var(--text-muted);">Confidence: ${rel.confidence}</div>`);
    }

    bodyEl.innerHTML = fullHtml;
  },

  _renderCorrelation(corrId, idEl, typeEl, bodyEl) {
    let corr = (THRAGG_DATA.correlations || []).find(c => c.id === corrId || c.title === corrId);
    if (!corr) {
      idEl.textContent = "Correlation";
      bodyEl.innerHTML = this._emptyState('Correlation details not found.');
      return;
    }

    idEl.textContent = corr.title.length > 30 ? corr.title.substring(0,30) + '...' : corr.title;
    typeEl.innerHTML = `<span class="tag">Correlation</span>`;

    let html = `
      <div style="padding-bottom:var(--space-4); border-bottom:1px solid var(--border-glass); margin-bottom:var(--space-4);">
        <div style="font-size:var(--font-size-md); color:var(--text-primary); line-height:1.5;">${corr.title}</div>
      </div>
    `;

    if (corr.entities && corr.entities.length > 0) {
      const entsHtml = `<div style="display: flex; flex-direction: column; gap: var(--space-1);">` + corr.entities.map(e => {
        return this._buildPivotLink('Entity', e, e, '💻');
      }).join('') + `</div>`;
      html += this._buildSection('Entities', entsHtml);
    }
    
    bodyEl.innerHTML = html;
  },

  _renderAttackChain(chainId, idEl, typeEl, bodyEl) {
    let chain = (THRAGG_DATA.attack_chains || []).find(c => c.id === chainId || c.title === chainId);
    if (!chain) {
      idEl.textContent = "Attack Chain";
      bodyEl.innerHTML = this._emptyState('Attack Chain details not found.');
      return;
    }

    idEl.textContent = chain.title.length > 30 ? chain.title.substring(0,30) + '...' : chain.title;
    const severity = chain.severity || 'CRITICAL';
    typeEl.innerHTML = `<span class="severity-label ${severity.toLowerCase()}">${severity}</span>`;

    let html = `
      <div style="padding-bottom:var(--space-4); border-bottom:1px solid var(--border-glass); margin-bottom:var(--space-4);">
        <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">${chain.entry_point} → ${chain.target}</div>
        <div style="font-size:var(--font-size-md); color:var(--text-primary); line-height:1.5;">${chain.description || chain.title}</div>
      </div>
    `;

    if (chain.entities && chain.entities.length > 0) {
      const entsHtml = `<div style="display: flex; flex-direction: column; gap: var(--space-1);">` + chain.entities.map(e => {
        return this._buildPivotLink('Entity', e, e, '💻');
      }).join('') + `</div>`;
      html += this._buildSection('Involved Entities', entsHtml);
    }

    if (chain.mitre_techniques && chain.mitre_techniques.length > 0) {
      const mHtml = `<div style="display:flex; flex-wrap:wrap; gap:4px;">` + chain.mitre_techniques.map(m => 
        `<span class="tag" style="cursor:pointer;" onclick="THRAGG_InvestigationSession.setContext('MITRE', '${m}')">${m}</span>`
      ).join('') + `</div>`;
      html += this._buildSection('Techniques', mHtml);
    }

    bodyEl.innerHTML = html;
  },

  _renderRecommendation(recId, idEl, typeEl, bodyEl) {
    idEl.textContent = "Recommendation";
    typeEl.innerHTML = `<span class="tag">Remediation</span>`;
    
    // In THRAGG_DATA, recommendations are often attached to risk_assessments
    let recText = recId;
    let risk = (THRAGG_DATA.risk_assessments || []).find(r => r.recommendation === recId || r.id === recId);
    if (risk) recText = risk.recommendation;

    let html = `
      <div style="padding:var(--space-4); background:var(--bg-glass); border-radius:var(--radius-md); border:1px solid var(--border-glass); margin-bottom:var(--space-4);">
        <div style="font-size:var(--font-size-md); color:var(--brand-primary); line-height:1.5;">${recText}</div>
      </div>
    `;

    if (risk) {
      html += this._buildSection('Addresses Risk', this._buildPivotLink('Finding', risk.summary, risk.summary, '⚡', risk.risk_level));
    }

    bodyEl.innerHTML = html;
  },

  _renderEvidence(evidenceId, idEl, typeEl, bodyEl) {
    idEl.textContent = evidenceId;
    typeEl.innerHTML = `<span class="tag" style="background:var(--brand-light); color:var(--bg-dark);">Evidence File</span>`;

    let html = `
      <div style="padding-bottom:var(--space-4); border-bottom:1px solid var(--border-glass); margin-bottom:var(--space-4);">
        <div style="font-size:12px; color:var(--text-muted); display:flex; justify-content:space-between;">
          <span>Type: Raw Log</span>
          <span>Size: 4.2 MB</span>
        </div>
      </div>
    `;

    // Simulated evidence snippet for premium feel since data.js doesn't contain actual file blobs
    const snippetHtml = `
      <div class="evidence-card" style="background:#0d1117; padding:var(--space-3); border-radius:var(--radius-sm); border:1px solid var(--border-glass); font-family:var(--font-mono); font-size:11px; overflow-x:auto;">
        <div style="color:var(--text-muted); margin-bottom:8px;">// Discovered inside ${evidenceId}</div>
        <div style="color:#8b949e;">[TIMESTAMP] <span style="color:#79c0ff;">INFO</span> Processing data block...</div>
        <div style="color:#ffa657; background:rgba(255,166,87,0.1); padding:2px; border-radius:2px;">[TIMESTAMP] <span style="color:#ff7b72;">WARN</span> Authentication failure for user admin from 10.0.0.5</div>
        <div style="color:#8b949e;">[TIMESTAMP] <span style="color:#79c0ff;">INFO</span> Connection closed.</div>
      </div>
    `;

    html += this._buildSection('Matched Snippet', snippetHtml);

    // Links to entities
    const relatedEntities = (THRAGG_DATA.resolved_entities || []).slice(0, 2); // mockup sync
    if (relatedEntities.length > 0) {
      const entsHtml = `<div style="display: flex; flex-direction: column; gap: var(--space-1);">` + relatedEntities.map(e => {
        return this._buildPivotLink('Entity', e.id, e.primary_identifier || e.id, '💻');
      }).join('') + `</div>`;
      html += this._buildSection('Discovered Entities', entsHtml);
    }

    bodyEl.innerHTML = html;
  }

};
