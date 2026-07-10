/* ==========================================================================
   THRAGG — Command Palette
   Interactive overlay for Global Search, Actions, and Navigation (Ctrl+K).
   ========================================================================== */

const THRAGG_CommandPalette = {
  isOpen: false,
  query: '',
  selectedIndex: 0,
  results: [],
  recentSearches: [],

  init() {
    this._renderOverlay();
    
    // Load recent searches from StorageProvider
    if (typeof THRAGG_StorageProvider !== 'undefined') {
      THRAGG_StorageProvider.get('RECENT_SEARCHES').then(res => {
        if (res && Array.isArray(res)) this.recentSearches = res;
      });
    }

    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('TOGGLE_COMMAND_PALETTE', () => {
        this.isOpen ? this.close() : this.open();
      });
    }
  },

  _renderOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'command-palette-overlay';
    overlay.className = 'command-palette-overlay hidden';
    overlay.innerHTML = `
      <div class="command-palette">
        <div class="cp-header">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--text-muted); margin-right: var(--space-3);">
            <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
          </svg>
          <input type="text" id="cp-input" class="cp-input" placeholder="Search intelligence, cases, and actions..." autocomplete="off">
          <div class="cp-badge">ESC</div>
        </div>
        
        <div class="cp-filters" id="cp-filters">
          <span style="font-size:var(--font-size-xs); color:var(--text-muted); margin-right:var(--space-2);">FILTERS:</span>
          <select id="cp-filter-severity" onchange="THRAGG_CommandPalette.updateFilters()" class="cp-select">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select id="cp-filter-type" onchange="THRAGG_CommandPalette.updateFilters()" class="cp-select">
            <option value="ALL">All Types</option>
            <option value="Entity">Entities</option>
            <option value="Finding">Findings</option>
            <option value="Attack Chain">Attack Chains</option>
            <option value="Case">Cases</option>
          </select>
        </div>

        <div class="cp-results" id="cp-results"></div>

        <div class="cp-footer">
          <div class="cp-shortcut"><span>↑↓</span> to navigate</div>
          <div class="cp-shortcut"><span>Enter</span> to select</div>
          <div class="cp-shortcut"><span>Tab</span> for actions</div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    // CSS
    const style = document.createElement('style');
    style.innerHTML = `
      .command-palette-overlay { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(7, 11, 20, 0.85); backdrop-filter: blur(8px); z-index: 10000; display: flex; align-items: flex-start; justify-content: center; padding-top: 12vh; opacity: 1; transition: opacity 0.2s; }
      .command-palette-overlay.hidden { opacity: 0; pointer-events: none; }
      .command-palette { width: 100%; max-width: 700px; background: var(--bg-surface); border: 1px solid var(--border-medium); border-radius: var(--radius-lg); box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); overflow: hidden; display: flex; flex-direction: column; transform: scale(1); transition: transform 0.2s cubic-bezier(0.175, 0.885, 0.32, 1.275); }
      .command-palette-overlay.hidden .command-palette { transform: scale(0.95); }
      
      .cp-header { display: flex; align-items: center; padding: var(--space-4) var(--space-5); border-bottom: 1px solid var(--border-medium); }
      .cp-input { flex: 1; background: transparent; border: none; color: var(--text-primary); font-size: var(--font-size-md); outline: none; font-family: var(--font-sans); }
      .cp-input::placeholder { color: var(--text-muted); }
      .cp-badge { font-size: 10px; font-weight: var(--font-weight-semibold); padding: var(--space-1) var(--space-2); background: var(--bg-glass); border-radius: var(--radius-sm); color: var(--text-muted); }
      
      .cp-filters { padding: var(--space-2) var(--space-5); border-bottom: 1px solid var(--border-medium); display: flex; gap: var(--space-2); align-items: center; background: var(--bg-base); }
      .cp-select { background: var(--bg-glass); color: var(--text-primary); border: 1px solid var(--border-medium); border-radius: var(--radius-sm); padding: var(--space-1) var(--space-2); font-size: var(--font-size-xs); outline: none; cursor: pointer; }
      
      .cp-results { max-height: 400px; overflow-y: auto; padding: var(--space-3) 0; }
      .cp-results::-webkit-scrollbar { width: var(--space-2); }
      .cp-results::-webkit-scrollbar-thumb { background: var(--border-medium); border-radius: var(--radius-sm); }
      
      .cp-item { display: flex; align-items: center; padding: var(--space-3) var(--space-5); cursor: pointer; border-left: 3px solid transparent; transition: background 0.1s; }
      .cp-item:hover, .cp-item.selected { background: var(--bg-glass-hover); border-left-color: var(--brand-primary); }
      .cp-item-icon { width: 32px; height: 32px; border-radius: var(--radius-sm); background: var(--bg-glass); display: flex; align-items: center; justify-content: center; margin-right: var(--space-4); font-size: var(--font-size-base); }
      .cp-item-content { flex: 1; overflow: hidden; }
      .cp-item-title { font-weight: var(--font-weight-medium); color: var(--text-primary); margin-bottom: var(--space-1); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .cp-item-subtitle { font-size: var(--font-size-xs); color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .cp-item-category { font-size: var(--font-size-xs); font-weight: var(--font-weight-semibold); text-transform: uppercase; color: var(--brand-primary); letter-spacing: var(--letter-spacing-wide); padding: 2px var(--space-1); background: var(--bg-glass); border-radius: var(--radius-sm); }
      
      .cp-footer { padding: var(--space-3) var(--space-5); border-top: 1px solid var(--border-medium); display: flex; gap: var(--space-4); background: var(--bg-base); }
      .cp-shortcut { font-size: var(--font-size-xs); color: var(--text-muted); display: flex; align-items: center; gap: var(--space-1); }
      .cp-shortcut span { background: var(--bg-glass); padding: 2px var(--space-1); border-radius: var(--radius-sm); font-weight: var(--font-weight-semibold); color: var(--text-primary); }

      .cp-section-title { font-size: var(--font-size-xs); font-weight: var(--font-weight-semibold); color: var(--text-muted); margin: var(--space-2) var(--space-5); text-transform: uppercase; letter-spacing: var(--letter-spacing-wide); }
      .cp-action-btn { background: var(--bg-glass); border: none; color: var(--text-primary); border-radius: var(--radius-sm); padding: var(--space-1) var(--space-2); font-size: var(--font-size-xs); cursor: pointer; display: none; }
      .cp-item.selected .cp-action-btn { display: inline-block; }
      .cp-action-btn:hover { background: var(--bg-glass-hover); }
    `;
    document.head.appendChild(style);

    // Event Listeners
    const input = document.getElementById('cp-input');
    input.addEventListener('input', (e) => this.handleInput(e.target.value));
    input.addEventListener('keydown', (e) => this.handleKeydown(e));

    // Close on click outside
    overlay.addEventListener('click', (e) => {
      if (e.target.id === 'command-palette-overlay') this.close();
    });
  },

  open() {
    this.isOpen = true;
    document.getElementById('command-palette-overlay').classList.remove('hidden');
    const input = document.getElementById('cp-input');
    input.focus();
    input.select();
    this.handleInput(input.value); // refresh results or show recents
  },

  close() {
    this.isOpen = false;
    document.getElementById('command-palette-overlay').classList.add('hidden');
  },

  updateFilters() {
    const sev = document.getElementById('cp-filter-severity').value;
    const type = document.getElementById('cp-filter-type').value;
    
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('GLOBAL_FILTER_CHANGED', { severity: sev, type: type });
    }
    
    // Re-run search with new filters
    this.handleInput(this.query);
  },

  handleInput(query) {
    this.query = query;
    this.selectedIndex = 0;
    
    if (!query.trim()) {
      // Show recent searches if empty
      this.renderRecentSearches();
      return;
    }

    if (typeof THRAGG_GlobalIndex !== 'undefined') {
      const allResults = THRAGG_GlobalIndex.search(query);
      
      // Apply filters
      const sevFilter = document.getElementById('cp-filter-severity').value;
      const typeFilter = document.getElementById('cp-filter-type').value;

      this.results = allResults.filter(item => {
        let passSev = true;
        let passType = true;
        if (sevFilter !== 'ALL') {
           const s = (item.subtitle.match(/Severity: ([A-Z]+)/)||[])[1];
           if (s && s !== sevFilter) passSev = false;
        }
        if (typeFilter !== 'ALL') {
           if (item.category !== typeFilter) passType = false;
        }
        return passSev && passType;
      });

      this.renderResults();
    }
  },

  renderRecentSearches() {
    const container = document.getElementById('cp-results');
    this.results = []; // No selection items
    if (this.recentSearches.length === 0) {
      container.innerHTML = `<div style="padding: 30px; text-align: center; color: var(--muted); font-size: 13px;">Type to search globally...</div>`;
      return;
    }
    
    let html = `<div class="cp-section-title">Recent Searches</div>`;
    this.recentSearches.forEach(term => {
      html += `
        <div class="cp-item" onclick="document.getElementById('cp-input').value='${term}'; THRAGG_CommandPalette.handleInput('${term}');">
          <div class="cp-item-icon" style="opacity:0.5;">🕒</div>
          <div class="cp-item-content">
            <div class="cp-item-title">${term}</div>
          </div>
        </div>
      `;
    });
    container.innerHTML = html;
  },

  renderResults() {
    const container = document.getElementById('cp-results');
    if (this.results.length === 0) {
      container.innerHTML = `<div style="padding: 30px; text-align: center; color: var(--muted); font-size: 13px;">No results found for "${this.query}"</div>`;
      return;
    }

    let html = '';
    this.results.forEach((item, index) => {
      html += `
        <div class="cp-item ${index === this.selectedIndex ? 'selected' : ''}" id="cp-item-${index}" onclick="THRAGG_CommandPalette.executeAction(${index})">
          <div class="cp-item-icon">${item.icon}</div>
          <div class="cp-item-content">
            <div class="cp-item-title">${item.title}</div>
            <div class="cp-item-subtitle">${item.subtitle}</div>
          </div>
          <div style="display:flex; gap:8px; align-items:center;">
            <button class="cp-action-btn" onclick="event.stopPropagation(); THRAGG_CommandPalette.bookmarkItem(${index})">Bookmark</button>
            <div class="cp-item-category">${item.category}</div>
          </div>
        </div>
      `;
    });
    container.innerHTML = html;

    // Scroll selected into view
    const selectedEl = document.getElementById(`cp-item-${this.selectedIndex}`);
    if (selectedEl) {
      selectedEl.scrollIntoView({ block: 'nearest' });
    }
  },

  handleKeydown(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (this.selectedIndex < this.results.length - 1) {
        this.selectedIndex++;
        this.renderResults();
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (this.selectedIndex > 0) {
        this.selectedIndex--;
        this.renderResults();
      }
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (this.results.length > 0) {
        this.executeAction(this.selectedIndex);
      }
    }
  },

  executeAction(index) {
    const item = this.results[index];
    if (!item) return;

    // Save recent search
    if (this.query.trim()) {
      this.recentSearches = [this.query, ...this.recentSearches.filter(q => q !== this.query)].slice(0, 5);
      if (typeof THRAGG_StorageProvider !== 'undefined') {
        THRAGG_StorageProvider.set('RECENT_SEARCHES', this.recentSearches);
      }
    }

    this.close();

    // Use InvestigationSession if available
    if (typeof THRAGG_InvestigationSession !== 'undefined') {
      let typeMap = {
        'Entity': 'Entity',
        'Finding': 'Finding',
        'Attack Chain': 'Attack Chain',
        'Recommendation': 'Recommendation',
        'Case': 'Case'
      };

      if (typeMap[item.category]) {
        THRAGG_InvestigationSession.setContext({
          type: typeMap[item.category],
          id: item.refId,
          data: item.refData
        });
      }
    }
    
    // Broadcast highlight event for visualizations
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('SEARCH_HIGHLIGHT_REQUEST', item);
    }
  },

  bookmarkItem(index) {
    const item = this.results[index];
    if (item && typeof THRAGG_CaseManager !== 'undefined') {
      THRAGG_CaseManager.addBookmark(item.category, item.refId);
    }
  }
};
