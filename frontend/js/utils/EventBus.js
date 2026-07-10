/* ==========================================================================
   THRAGG — Event Bus
   Minimal pub/sub for component synchronization. No state duplication.
   ========================================================================== */

const THRAGG_EventBus = {
  listeners: {},

  on(event, callback) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(callback);
  },

  off(event, callback) {
    if (!this.listeners[event]) return;
    this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
  },

  emit(event, data) {
    if (!this.listeners[event]) return;
    this.listeners[event].forEach(callback => {
      try {
        callback(data);
      } catch (err) {
        console.error(`Error in EventBus listener for event ${event}:`, err);
      }
    });
  }
};
