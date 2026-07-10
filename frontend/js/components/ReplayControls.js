/* ==========================================================================
   THRAGG — Replay Controls
   Global floating toolbar for Attack Replay Engine
   ========================================================================== */

const THRAGG_ReplayControls = {
  containerId: 'replay-controls-overlay',
  
  init() {
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('REPLAY_STARTED', () => this.show());
      THRAGG_EventBus.on('REPLAY_STOPPED', () => this.hide());
      THRAGG_EventBus.on('REPLAY_FINISHED', () => this.updateState('FINISHED'));
      THRAGG_EventBus.on('REPLAY_PAUSED', () => this.updateState('PAUSED'));
      THRAGG_EventBus.on('REPLAY_RESUMED', () => this.updateState('PLAYING'));
      THRAGG_EventBus.on('REPLAY_STEP_CHANGED', (data) => this.updateProgress(data));
    }
  },

  show() {
    let el = document.getElementById(this.containerId);
    if (!el) {
      el = document.createElement('div');
      el.id = this.containerId;
      el.style.position = 'fixed';
      el.style.bottom = '24px';
      el.style.left = '50%';
      el.style.transform = 'translateX(-50%)';
      el.style.zIndex = '9999';
      el.style.display = 'flex';
      el.style.flexDirection = 'column';
      el.style.gap = '8px';
      el.style.background = 'rgba(7, 11, 20, 0.85)';
      el.style.backdropFilter = 'blur(12px)';
      el.style.border = '1px solid var(--border-medium)';
      el.style.borderRadius = 'var(--radius-md)';
      el.style.padding = '12px 24px';
      el.style.boxShadow = '0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255,255,255,0.05)';
      el.style.minWidth = '400px';
      document.body.appendChild(el);
    }
    
    this.render();
    el.style.display = 'flex';
  },

  hide() {
    const el = document.getElementById(this.containerId);
    if (el) el.style.display = 'none';
  },

  render() {
    const el = document.getElementById(this.containerId);
    if (!el) return;

    const state = typeof THRAGG_ReplayEngine !== 'undefined' ? THRAGG_ReplayEngine.state : 'STOPPED';
    const speed = typeof THRAGG_ReplayEngine !== 'undefined' ? THRAGG_ReplayEngine.speed : 1;

    el.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div style="font-size:12px; font-weight:bold; color:var(--brand-primary); letter-spacing:1px; text-transform:uppercase;">
          Attack Replay Mode
        </div>
        <div style="display:flex; gap:8px;">
          <select id="replay-speed-select" style="background:var(--bg-glass); border:1px solid var(--border-medium); color:var(--text-primary); border-radius:4px; font-size:11px; padding:2px 4px;" onchange="THRAGG_EventBus.emit('REPLAY_SPEED_REQUEST', parseFloat(this.value))">
            <option value="0.5" ${speed === 0.5 ? 'selected' : ''}>0.5x</option>
            <option value="1" ${speed === 1 ? 'selected' : ''}>1.0x</option>
            <option value="2" ${speed === 2 ? 'selected' : ''}>2.0x</option>
            <option value="4" ${speed === 4 ? 'selected' : ''}>4.0x</option>
          </select>
          <button class="btn-icon" title="Stop Replay (Home)" style="color:var(--text-muted);" onclick="THRAGG_EventBus.emit('REPLAY_STOP_REQUEST')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12"/></svg>
          </button>
        </div>
      </div>
      
      <div style="display:flex; align-items:center; gap:16px; margin-top:4px;">
        <button class="btn-icon" title="Previous (Left Arrow)" onclick="THRAGG_EventBus.emit('REPLAY_PREV_REQUEST')">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
        </button>
        
        <button class="btn-icon" id="replay-play-pause" title="Play/Pause (Space)" onclick="
          if(THRAGG_ReplayEngine.state === 'PLAYING') THRAGG_EventBus.emit('REPLAY_PAUSE_REQUEST');
          else if (THRAGG_ReplayEngine.state === 'FINISHED') THRAGG_EventBus.emit('REPLAY_START_REQUEST');
          else THRAGG_EventBus.emit('REPLAY_RESUMED');
        ">
          ${state === 'PLAYING' 
            ? `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>` 
            : `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>`}
        </button>
        
        <button class="btn-icon" title="Next (Right Arrow)" onclick="THRAGG_EventBus.emit('REPLAY_NEXT_REQUEST')">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
        </button>

        <div style="flex:1; margin-left:8px; display:flex; flex-direction:column; gap:4px;">
          <input type="range" id="replay-progress-slider" min="0" max="100" value="0" style="width:100%; cursor:pointer; accent-color:var(--brand-primary);" oninput="
            if (typeof THRAGG_ReplayEngine !== 'undefined') {
              const total = THRAGG_ReplayEngine.events.length;
              const idx = Math.floor((this.value / 100) * (total - 1));
              THRAGG_EventBus.emit('REPLAY_SEEK_REQUEST', idx);
            }
          ">
          <div style="display:flex; justify-content:space-between; font-size:10px; color:var(--text-muted); font-family:var(--font-mono);">
            <span id="replay-step-label">Step 0 / 0</span>
            <span id="replay-time-label">00:00:00</span>
          </div>
        </div>
      </div>
    `;
  },

  updateState(state) {
    const btn = document.getElementById('replay-play-pause');
    if (btn) {
      btn.innerHTML = state === 'PLAYING'
        ? `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>`
        : `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>`;
    }
  },

  updateProgress(data) {
    const slider = document.getElementById('replay-progress-slider');
    const stepLabel = document.getElementById('replay-step-label');
    const timeLabel = document.getElementById('replay-time-label');

    if (slider && data.total > 1) {
      slider.value = (data.index / (data.total - 1)) * 100;
    }
    
    if (stepLabel) {
      stepLabel.textContent = `Step ${data.index + 1} / ${data.total}`;
    }

    if (timeLabel && data.step && data.step.timestamp) {
      timeLabel.textContent = new Date(data.step.timestamp).toLocaleTimeString();
    }
  }
};
