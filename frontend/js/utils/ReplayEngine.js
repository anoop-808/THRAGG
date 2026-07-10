/* ==========================================================================
   THRAGG — Replay Engine
   Reconstructs and orchestrates attack progression playback from THRAGG_DATA.
   ========================================================================== */

const THRAGG_ReplayEngine = {
  state: 'STOPPED', // STOPPED, PLAYING, PAUSED, FINISHED
  speed: 1.0,
  currentIndex: -1,
  events: [],
  timer: null,

  init() {
    this._buildReplaySequence();
    this._bindKeyboardShortcuts();
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('REPLAY_START_REQUEST', (speed) => {
        if (speed) this.speed = speed;
        this.play();
      });
      THRAGG_EventBus.on('REPLAY_PAUSE_REQUEST', () => this.pause());
      THRAGG_EventBus.on('REPLAY_RESUME_REQUEST', () => this.resume());
      THRAGG_EventBus.on('REPLAY_STOP_REQUEST', () => this.stop());
      THRAGG_EventBus.on('REPLAY_NEXT_REQUEST', () => this.next());
      THRAGG_EventBus.on('REPLAY_PREV_REQUEST', () => this.previous());
      THRAGG_EventBus.on('REPLAY_SPEED_REQUEST', (s) => {
        this.speed = s;
        if (this.state === 'PLAYING') {
          this.pause();
          this.resume();
        }
      });
      THRAGG_EventBus.on('REPLAY_SEEK_REQUEST', (index) => {
        if (index >= 0 && index < this.events.length) {
          this.currentIndex = index;
          this._emitStep();
        }
      });
    }
  },

  _buildReplaySequence() {
    this.events = [];
    const data = THRAGG_DATA || {};

    // 1. Priority: Attack Chains
    if (data.attack_chains && data.attack_chains.length > 0) {
      data.attack_chains.forEach(chain => {
        const steps = chain.steps || chain.timeline || [];
        steps.forEach((s, i) => {
          this.events.push({
            id: `replay-chain-${chain.id}-${i}`,
            timestamp: s.timestamp || chain.created_at,
            source_type: 'Entity',
            source_id: s.source_entity || s.entity,
            target_type: 'Entity',
            target_id: s.target_entity,
            title: s.technique || s.stage || `Stage ${i+1}`,
            description: s.description || chain.description,
            mitre: s.mitre_id ? [s.mitre_id] : (s.mitre_techniques || []),
            evidence: s.evidence || [],
            replay_source: 'Attack Chain',
            original_data: s
          });
        });
      });
    }

    // 2. Fallback: Correlations
    if (this.events.length === 0 && data.correlations && data.correlations.length > 0) {
      data.correlations.forEach((c, i) => {
        this.events.push({
          id: `replay-corr-${c.id}-${i}`,
          timestamp: c.timestamp || new Date().toISOString(),
          source_type: 'Correlation',
          source_id: c.id,
          target_type: 'Entity',
          target_id: c.entities && c.entities[0],
          title: c.title || c.category,
          description: c.summary,
          mitre: c.mitre || [],
          evidence: [],
          replay_source: 'Correlation',
          original_data: c
        });
      });
    }

    // 3. Fallback: Relationships
    if (this.events.length === 0 && data.relationships && data.relationships.length > 0) {
      data.relationships.forEach((r, i) => {
        this.events.push({
          id: `replay-rel-${r.id || i}`,
          timestamp: r.first_seen || new Date().toISOString(),
          source_type: 'Entity',
          source_id: r.source_entity_id || r.source,
          target_type: 'Entity',
          target_id: r.target_entity_id || r.target,
          title: r.relationship_type || r.type || 'Connection',
          description: r.description || 'Observed relationship',
          mitre: [],
          evidence: [],
          replay_source: 'Relationship',
          original_data: r
        });
      });
    }

    // 4. Fallback: Findings (Observations)
    if (this.events.length === 0 && data.executive_assessment && data.executive_assessment.observations) {
      data.executive_assessment.observations.forEach((f, i) => {
        this.events.push({
          id: `replay-find-${f.id || i}`,
          timestamp: new Date().toISOString(), // Findings may not have timestamps
          source_type: 'Finding',
          source_id: f.id || `find-${i}`,
          target_type: 'Entity',
          target_id: f.entities && f.entities[0],
          title: f.category || 'Observation',
          description: f.text || f.summary,
          mitre: f.mitre || [],
          evidence: [],
          replay_source: 'Finding',
          original_data: f
        });
      });
    }

    // 5. Fallback: Entities
    if (this.events.length === 0 && data.entities && data.entities.length > 0) {
      data.entities.forEach((e, i) => {
        this.events.push({
          id: `replay-ent-${e.id}`,
          timestamp: new Date().toISOString(),
          source_type: 'Entity',
          source_id: e.id,
          target_type: null,
          target_id: null,
          title: e.primary_identifier || e.attributes?.hostname || e.id,
          description: 'Entity discovered',
          mitre: [],
          evidence: [],
          replay_source: 'Entity',
          original_data: e
        });
      });
    }

    // Sort chronologically by timestamp
    this.events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  },

  _emitState() {
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit(`REPLAY_${this.state}`);
      if (this.state === 'PLAYING' || this.state === 'PAUSED') {
         this._emitStep();
      }
    }
  },

  _emitStep() {
    if (this.currentIndex >= 0 && this.currentIndex < this.events.length) {
      const stepEvent = this.events[this.currentIndex];
      if (typeof THRAGG_EventBus !== 'undefined') {
        THRAGG_EventBus.emit('REPLAY_STEP_CHANGED', {
          step: stepEvent,
          index: this.currentIndex,
          total: this.events.length,
          isFinished: this.currentIndex === this.events.length - 1
        });
      }
    }
  },

  play() {
    if (this.events.length === 0) return;
    if (this.state === 'PLAYING') return;
    if (this.currentIndex >= this.events.length - 1) {
      this.currentIndex = -1; // Restart if finished
    }
    
    this.state = 'PLAYING';
    THRAGG_EventBus.emit('REPLAY_STARTED');
    this.next();
  },

  pause() {
    if (this.state !== 'PLAYING') return;
    this.state = 'PAUSED';
    clearTimeout(this.timer);
    THRAGG_EventBus.emit('REPLAY_PAUSED');
  },

  resume() {
    if (this.state !== 'PAUSED') return;
    this.state = 'PLAYING';
    THRAGG_EventBus.emit('REPLAY_RESUMED');
    this._scheduleNext();
  },

  stop() {
    this.state = 'STOPPED';
    this.currentIndex = -1;
    clearTimeout(this.timer);
    THRAGG_EventBus.emit('REPLAY_STOPPED');
  },

  next() {
    if (this.currentIndex < this.events.length - 1) {
      this.currentIndex++;
      this._emitStep();
      if (this.state === 'PLAYING') {
        this._scheduleNext();
      }
    } else {
      this.state = 'FINISHED';
      THRAGG_EventBus.emit('REPLAY_FINISHED');
    }
  },

  previous() {
    if (this.currentIndex > 0) {
      this.currentIndex--;
      this._emitStep();
    }
  },

  _scheduleNext() {
    clearTimeout(this.timer);
    // Base delay 3000ms divided by speed multiplier. Adjust if reduced motion.
    const isReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const delay = isReducedMotion ? (1000 / this.speed) : (3000 / this.speed);
    
    this.timer = setTimeout(() => {
      this.next();
    }, delay);
  },

  _bindKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      if (this.events.length === 0) return;
      
      switch(e.key) {
        case ' ':
          e.preventDefault();
          if (this.state === 'PLAYING') this.pause();
          else if (this.state === 'PAUSED' || this.state === 'STOPPED') this.play();
          break;
        case 'ArrowLeft':
          this.pause();
          this.previous();
          break;
        case 'ArrowRight':
          this.pause();
          this.next();
          break;
        case 'Home':
          this.stop();
          this.play();
          break;
        case 'End':
          this.pause();
          this.currentIndex = this.events.length - 1;
          this._emitStep();
          break;
      }
    });
  }
};
