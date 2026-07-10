/* ==========================================================================
   THRAGG — Replay Timeline Component
   Renders the chronological steps of the attack progression replay.
   ========================================================================== */

const THRAGG_ReplayTimeline = {
  _listenerAttached: false,

  render(container) {
    if (!container) return;

    if (!this._listenerAttached && typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('REPLAY_STEP_CHANGED', (data) => this._highlightStep(data.index));
      THRAGG_EventBus.on('REPLAY_STOPPED', () => {
        // Clear active states
        document.querySelectorAll('.replay-timeline-item').forEach(el => el.classList.remove('active', 'completed'));
      });
      this._listenerAttached = true;
    }

    if (typeof THRAGG_ReplayEngine === 'undefined' || THRAGG_ReplayEngine.events.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-title">No Replay Sequence Available</div>
          <div class="empty-state-text">Start a replay from an attack chain or let the engine reconstruct one automatically.</div>
        </div>
      `;
      return;
    }

    const events = THRAGG_ReplayEngine.events;
    
    let html = `
      <div class="view-header">
        <div class="page-title">Replay Timeline</div>
        <div class="page-subtitle">Reconstructed Attack Sequence (${events.length} Steps)</div>
      </div>
      <div style="margin-top: var(--space-6);">
        <div style="display: flex; flex-direction: column; gap: 0; position: relative; padding-left: 20px;">
          <div style="position: absolute; top: 0; bottom: 0; left: 24px; width: 2px; background: rgba(255,255,255,0.05);"></div>
          
          ${events.map((ev, i) => `
            <div class="replay-timeline-item" id="replay-step-${i}" style="position: relative; display: flex; gap: var(--space-4); padding-bottom: var(--space-6); cursor: pointer;" onclick="if(typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('REPLAY_SEEK_REQUEST', ${i})">
              
              <div class="replay-step-node" style="width: 10px; height: 10px; border-radius: 50%; background: var(--bg-surface); border: 2px solid var(--border-medium); z-index: 2; margin-top: 6px; box-shadow: 0 0 0 4px var(--bg-surface); transition: all 0.3s ease;"></div>
              
              <div class="card" style="flex: 1; transition: all 0.3s ease;">
                <div class="card-body" style="padding: var(--space-4);">
                  <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: var(--space-2);">
                    <div style="font-size: var(--font-size-md); font-weight: bold; color: var(--text-primary);">
                      Stage ${i + 1}: ${ev.title}
                    </div>
                    <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">
                      ${new Date(ev.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                  
                  <div style="font-size: var(--font-size-sm); color: var(--text-secondary); margin-bottom: var(--space-3);">
                    ${ev.description}
                  </div>
                  
                  <div style="display: flex; gap: var(--space-4); font-size: 12px;">
                    ${ev.source_id ? `<div><span style="color:var(--text-muted)">Source:</span> <span style="font-family:var(--font-mono); color:var(--brand-cyan)">${ev.source_id}</span></div>` : ''}
                    ${ev.target_id ? `<div><span style="color:var(--text-muted)">Target:</span> <span style="font-family:var(--font-mono); color:var(--brand-cyan)">${ev.target_id}</span></div>` : ''}
                  </div>
                  
                  ${ev.mitre && ev.mitre.length > 0 ? `
                    <div style="margin-top: var(--space-3); display: flex; gap: var(--space-2); flex-wrap: wrap;">
                      ${ev.mitre.map(m => `<span class="tag tag-mitre">${m}</span>`).join('')}
                    </div>
                  ` : ''}
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
      
      <style>
        .replay-timeline-item.active .replay-step-node {
          background: var(--color-critical);
          border-color: var(--color-critical);
          box-shadow: 0 0 10px var(--color-critical);
        }
        .replay-timeline-item.active .card {
          border-color: var(--color-critical);
          background: rgba(255, 59, 48, 0.05);
        }
        .replay-timeline-item.completed .replay-step-node {
          background: var(--brand-primary);
          border-color: var(--brand-primary);
        }
        .replay-timeline-item:hover .card {
          border-color: var(--brand-light);
        }
      </style>
    `;
    
    container.innerHTML = html;
    
    if (typeof THRAGG_ReplayEngine !== 'undefined' && THRAGG_ReplayEngine.currentIndex >= 0) {
      this._highlightStep(THRAGG_ReplayEngine.currentIndex);
    }
  },

  _highlightStep(index) {
    const items = document.querySelectorAll('.replay-timeline-item');
    items.forEach((item, i) => {
      item.classList.remove('active', 'completed');
      if (i === index) {
        item.classList.add('active');
        item.scrollIntoView({ behavior: 'smooth', block: 'center' });
      } else if (i < index) {
        item.classList.add('completed');
      }
    });
  }
};
