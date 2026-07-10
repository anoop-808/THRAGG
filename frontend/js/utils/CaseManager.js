/* ==========================================================================
   THRAGG — Investigation Case Manager
   Handles offline-first investigation workspaces.
   ========================================================================== */

const THRAGG_CaseManager = {
  cases: {},
  activeCaseId: null,
  schema_version: '1.0',

  async init() {
    await this.loadState();
    
    // Create a default case if none exist
    if (Object.keys(this.cases).length === 0) {
      await this.createCase('Initial Investigation');
    } else if (!this.activeCaseId) {
      this.activeCaseId = Object.keys(this.cases)[0];
      await this.saveState();
    }
  },

  async loadState() {
    const data = await THRAGG_StorageProvider.get('CASES');
    if (data && data.schema_version === this.schema_version) {
      this.cases = data.cases || {};
      this.activeCaseId = data.activeCaseId || null;
    }
  },

  async saveState() {
    await THRAGG_StorageProvider.set('CASES', {
      schema_version: this.schema_version,
      cases: this.cases,
      activeCaseId: this.activeCaseId
    });
  },

  generateId() {
    return 'case-' + Math.random().toString(36).substr(2, 9);
  },

  async createCase(title) {
    const id = this.generateId();
    const newCase = {
      id,
      title: title || 'New Investigation',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      status: 'Open',
      severity: 'Informational',
      analyst: 'Local Analyst',
      tags: [],
      notes: [],
      bookmarks: [],
      timeline: []
    };
    this.cases[id] = newCase;
    this.activeCaseId = id;
    
    this._appendTimeline('Created Investigation', `Case initialized: ${newCase.title}`, id);
    await this.saveState();
    
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('CASE_CREATED', newCase);
      THRAGG_EventBus.emit('CASE_SELECTED', newCase);
    }
    return newCase;
  },

  async deleteCase(id) {
    if (this.cases[id]) {
      delete this.cases[id];
      if (this.activeCaseId === id) {
        this.activeCaseId = Object.keys(this.cases)[0] || null;
      }
      await this.saveState();
      if (typeof THRAGG_EventBus !== 'undefined') {
        THRAGG_EventBus.emit('CASE_DELETED', id);
        if (this.activeCaseId) {
          THRAGG_EventBus.emit('CASE_SELECTED', this.cases[this.activeCaseId]);
        } else {
          await this.createCase('New Investigation');
        }
      }
    }
  },

  async renameCase(id, newTitle) {
    const c = this.cases[id];
    if (c) {
      const oldTitle = c.title;
      c.title = newTitle;
      c.updated_at = new Date().toISOString();
      this._appendTimeline('Renamed Investigation', `From "${oldTitle}" to "${newTitle}"`, id);
      await this.saveState();
      if (typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('CASE_UPDATED', c);
    }
  },

  async setActiveCase(id) {
    if (this.cases[id]) {
      this.activeCaseId = id;
      await this.saveState();
      if (typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('CASE_SELECTED', this.cases[id]);
    }
  },

  getActiveCase() {
    return this.cases[this.activeCaseId] || null;
  },
  
  getAllCases() {
    return Object.values(this.cases).sort((a,b) => new Date(b.updated_at) - new Date(a.updated_at));
  },

  async addBookmark(type, id) {
    const c = this.getActiveCase();
    if (!c) return;
    
    const exists = c.bookmarks.find(b => b.type === type && b.id === id);
    if (!exists) {
      c.bookmarks.push({ type, id, timestamp: new Date().toISOString() });
      c.updated_at = new Date().toISOString();
      this._appendTimeline('Bookmarked Intelligence', `Added ${type}: ${id}`, c.id);
      await this.saveState();
      if (typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('BOOKMARK_ADDED', { type, id });
      if (typeof THRAGG_App !== 'undefined' && THRAGG_App.showToast) {
        THRAGG_App.showToast(`Bookmarked ${type}`, 'success');
      }
    }
  },

  async removeBookmark(type, id) {
    const c = this.getActiveCase();
    if (!c) return;
    
    const initialLen = c.bookmarks.length;
    c.bookmarks = c.bookmarks.filter(b => !(b.type === type && b.id === id));
    if (c.bookmarks.length !== initialLen) {
      c.updated_at = new Date().toISOString();
      this._appendTimeline('Removed Bookmark', `Removed ${type}: ${id}`, c.id);
      await this.saveState();
      if (typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('BOOKMARK_REMOVED', { type, id });
      if (typeof THRAGG_App !== 'undefined' && THRAGG_App.showToast) {
        THRAGG_App.showToast(`Removed ${type} from investigation`, 'info');
      }
    }
  },
  
  isBookmarked(type, id) {
    const c = this.getActiveCase();
    if (!c) return false;
    return !!c.bookmarks.find(b => b.type === type && b.id === id);
  },

  async addNote(content, related_id = null) {
    const c = this.getActiveCase();
    if (!c || !content.trim()) return;

    const note = {
      id: 'note-' + Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      content: content.trim(),
      related_object_id: related_id,
      author: c.analyst
    };
    c.notes.push(note);
    c.updated_at = new Date().toISOString();
    
    let timelineDetail = 'Added new analyst note';
    if (related_id) timelineDetail += ` related to ${related_id}`;
    this._appendTimeline('Added Analyst Note', timelineDetail, c.id);
    
    await this.saveState();
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('NOTE_CREATED', note);
      THRAGG_EventBus.emit('CASE_UPDATED', c);
    }
  },

  async setStatus(status) {
    const c = this.getActiveCase();
    if (c && c.status !== status) {
      const old = c.status;
      c.status = status;
      c.updated_at = new Date().toISOString();
      this._appendTimeline('Changed Investigation Status', `Changed from ${old} to ${status}`, c.id);
      await this.saveState();
      if (typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('CASE_STATUS_CHANGED', c);
    }
  },

  async setSeverity(severity) {
    const c = this.getActiveCase();
    if (c && c.severity !== severity) {
      const old = c.severity;
      c.severity = severity;
      c.updated_at = new Date().toISOString();
      this._appendTimeline('Changed Investigation Severity', `Changed from ${old} to ${severity}`, c.id);
      await this.saveState();
      if (typeof THRAGG_EventBus !== 'undefined') THRAGG_EventBus.emit('CASE_UPDATED', c);
    }
  },

  _appendTimeline(action, details, caseId) {
    const c = this.cases[caseId];
    if (c) {
      c.timeline.push({
        timestamp: new Date().toISOString(),
        action,
        details
      });
    }
  }
};
