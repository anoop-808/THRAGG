/* ==========================================================================
   THRAGG — Keyboard Shortcuts Utility
   ========================================================================== */

const THRAGG_KeyboardShortcuts = {
  init() {
    document.addEventListener('keydown', (e) => {
      // Don't intercept if user is typing in an input
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') {
        // Except for Esc to close things
        if (e.key === 'Escape') {
          e.target.blur();
        }
        return;
      }

      if (e.key === 'Escape') {
        if (typeof THRAGG_InvestigationSession !== 'undefined') {
          THRAGG_InvestigationSession.clearContext();
        }
      }

      if (e.altKey && e.key === 'ArrowLeft') {
        if (typeof THRAGG_InvestigationSession !== 'undefined') {
          THRAGG_InvestigationSession.goBack();
          e.preventDefault();
        }
      }

      if (e.altKey && e.key === 'ArrowRight') {
        if (typeof THRAGG_InvestigationSession !== 'undefined') {
          THRAGG_InvestigationSession.goForward();
          e.preventDefault();
        }
      }

      // Ctrl/Cmd + K: Toggle Command Palette
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (typeof THRAGG_EventBus !== 'undefined') {
          THRAGG_EventBus.emit('TOGGLE_COMMAND_PALETTE');
        }
        return;
      }

      // '/' to Toggle Command Palette
      if (e.key === '/') {
        e.preventDefault();
        if (typeof THRAGG_EventBus !== 'undefined') {
          THRAGG_EventBus.emit('TOGGLE_COMMAND_PALETTE');
        }
        return;
      }

      // E: Jump to Entity Explorer
      if (e.key.toLowerCase() === 'e') {
        THRAGG_App.navigate('entities');
        return;
      }

      // F: Jump to Finding Explorer
      if (e.key.toLowerCase() === 'f') {
        THRAGG_App.navigate('findings');
        return;
      }
      
      // S: Jump to Session Overview
      if (e.key.toLowerCase() === 's') {
        THRAGG_App.navigate('session');
        return;
      }
    });
  }
};
