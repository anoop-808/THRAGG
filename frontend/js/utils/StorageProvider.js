/* ==========================================================================
   THRAGG — Storage Provider
   Abstracts persistence mechanisms for offline-first case management.
   ========================================================================== */

class LocalStorageProvider {
  constructor(prefix = 'THRAGG_') {
    this.prefix = prefix;
  }

  async get(key) {
    try {
      const data = localStorage.getItem(this.prefix + key);
      return data ? JSON.parse(data) : null;
    } catch (e) {
      console.error('LocalStorageProvider GET error', e);
      return null;
    }
  }

  async set(key, value) {
    try {
      localStorage.setItem(this.prefix + key, JSON.stringify(value));
      return true;
    } catch (e) {
      console.error('LocalStorageProvider SET error', e);
      return false;
    }
  }

  async remove(key) {
    try {
      localStorage.removeItem(this.prefix + key);
      return true;
    } catch (e) {
      console.error('LocalStorageProvider REMOVE error', e);
      return false;
    }
  }
}

// Default export structure
const THRAGG_StorageProvider = new LocalStorageProvider();
