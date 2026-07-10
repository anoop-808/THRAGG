/* ==========================================================================
   THRAGG — Investigation Session Manager
   ========================================================================== */

const THRAGG_InvestigationSession = {
  history: [], // Array of { type, id, uiState: { filters, scrollY, view } }
  currentIndex: -1,
  activeContext: null, // { type, id }
  
  init() {
    this.restoreSession();
  },

  /* ── Commit a new selection to history ───────────────────────────── */
  setContext(type, id) {
    if (!type || !id) return this.clearContext();

    // Prevent duplicate pushes if it's the exact same context
    if (this.activeContext && this.activeContext.type === type && this.activeContext.id === id) {
      return;
    }

    // Capture current UI State before moving forward
    let currentUiState = {};
    if (typeof THRAGG_App !== 'undefined') {
      currentUiState.view = THRAGG_App.currentView;
    }
    if (typeof THRAGG_GlobalSearch !== 'undefined') {
      currentUiState.filters = JSON.parse(JSON.stringify(THRAGG_GlobalSearch.filters));
    }
    const mainContent = document.getElementById('main-content');
    if (mainContent) {
      currentUiState.scrollY = mainContent.scrollTop;
    }

    // If we're not at the end of history, truncate the future
    if (this.currentIndex < this.history.length - 1) {
      this.history = this.history.slice(0, this.currentIndex + 1);
    }

    // Add new context
    const contextObj = { type, id, uiState: currentUiState };
    this.history.push(contextObj);
    this.currentIndex++;
    this.activeContext = contextObj;

    this._persist();

    // Broadcast change
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('CONTEXT_CHANGED', this.activeContext);
    }
  },

  /* ── Lightweight Hover Preview ─────────────────────────────────────── */
  setHoverPreview(type, id) {
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('HOVER_PREVIEW', { type, id });
    }
  },
  
  clearHoverPreview() {
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('HOVER_PREVIEW', null);
    }
  },

  /* ── Clear entirely ────────────────────────────────────────────────── */
  clearContext() {
    if (!this.activeContext) return;
    
    // Add a null context to history to signify returning to base dashboard?
    // Actually, just push a null context so we can navigate back.
    const contextObj = { type: null, id: null, uiState: {} };
    if (this.currentIndex < this.history.length - 1) {
      this.history = this.history.slice(0, this.currentIndex + 1);
    }
    this.history.push(contextObj);
    this.currentIndex++;
    this.activeContext = null;

    this._persist();

    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('CONTEXT_CHANGED', null);
    }
  },

  /* ── Navigation ────────────────────────────────────────────────────── */
  goBack() {
    if (this.currentIndex > 0) {
      this.currentIndex--;
      this._applyHistoryState();
    }
  },

  goForward() {
    if (this.currentIndex < this.history.length - 1) {
      this.currentIndex++;
      this._applyHistoryState();
    }
  },

  jumpTo(index) {
    if (index >= 0 && index < this.history.length) {
      this.currentIndex = index;
      this._applyHistoryState();
    }
  },

  _applyHistoryState() {
    const state = this.history[this.currentIndex];
    this.activeContext = state.type && state.id ? { type: state.type, id: state.id } : null;
    
    // Restore UI State
    if (state.uiState) {
      if (state.uiState.view && typeof THRAGG_App !== 'undefined') {
        if (THRAGG_App.currentView !== state.uiState.view) {
          THRAGG_App.navigate(state.uiState.view);
        }
      }
      if (state.uiState.filters && typeof THRAGG_GlobalSearch !== 'undefined') {
        THRAGG_GlobalSearch.filters = JSON.parse(JSON.stringify(state.uiState.filters));
        if (typeof THRAGG_EventBus !== 'undefined') {
           THRAGG_EventBus.emit('GLOBAL_FILTER_CHANGED', THRAGG_GlobalSearch.filters);
        }
        
        // Update topnav selectors visually
        const sev = document.getElementById('global-filter-severity');
        const typ = document.getElementById('global-filter-type');
        if (sev) sev.value = state.uiState.filters.severity;
        if (typ) typ.value = state.uiState.filters.type;
      }
      
      if (state.uiState.scrollY !== undefined) {
        requestAnimationFrame(() => {
          const mainContent = document.getElementById('main-content');
          if (mainContent) mainContent.scrollTop = state.uiState.scrollY;
        });
      }
    }

    this._persist();
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('CONTEXT_CHANGED', this.activeContext);
    }
  },

  /* ── Persistence ───────────────────────────────────────────────────── */
  _persist() {
    try {
      const data = {
        history: this.history,
        currentIndex: this.currentIndex
      };
      sessionStorage.setItem('THRAGG_InvestigationSession', JSON.stringify(data));
    } catch (e) {
      // Ignore
    }
  },

  restoreSession() {
    try {
      const raw = sessionStorage.getItem('THRAGG_InvestigationSession');
      if (raw) {
        const data = JSON.parse(raw);
        if (data.history && data.currentIndex !== undefined) {
          this.history = data.history;
          this.currentIndex = data.currentIndex;
          
          if (this.currentIndex >= 0 && this.currentIndex < this.history.length) {
             const state = this.history[this.currentIndex];
             this.activeContext = state.type && state.id ? { type: state.type, id: state.id } : null;
             
             // We do NOT immediately broadcast here because App might not be fully initialized.
             // We will let App call this or we defer it.
             setTimeout(() => {
                if (typeof THRAGG_EventBus !== 'undefined') {
                   THRAGG_EventBus.emit('CONTEXT_CHANGED', this.activeContext);
                }
             }, 100);
          }
        }
      }
    } catch (e) {
      // Ignore
    }
  }
};
