/* ==========================================================================
   THRAGG — Global Search & Filter Utility
   ========================================================================== */

const THRAGG_GlobalSearch = {
  index: [],
  filters: {
    severity: 'ALL',
    type: 'ALL'
  },

  init() {
    this._buildIndex();
    this._initFilterBar();
  },

  _buildIndex() {
    this.index = [];
    
    // Index Entities
    (THRAGG_DATA.entities || []).forEach(e => {
      this.index.push({
        type: 'Entity',
        label: e.id,
        desc: `Type: ${e.type} · Confidence: ${e.confidence}%`,
        target: 'entities',
        meta: e
      });
    });

    // Index Findings
    (THRAGG_DATA.executive_assessment.observations || []).forEach(o => {
      this.index.push({
        type: 'Finding',
        label: o.summary.substring(0, 50) + '...',
        desc: `Severity: ${o.severity} · MITRE: ${(o.mitre_tactics||[]).join(', ')}`,
        target: 'findings',
        meta: o
      });
    });

    // Index Attack Chains
    (THRAGG_DATA.attack_chains || []).forEach(c => {
      this.index.push({
        type: 'Attack Chain',
        label: c.title || c.id,
        desc: `Severity: ${c.severity} · Steps: ${c.steps?.length || 0}`,
        target: 'chains',
        meta: c
      });
    });
  },

  _initFilterBar() {
    // We bind to the global inputs if they exist in TopNavigation
    const sevSelect = document.getElementById('global-filter-severity');
    const typeSelect = document.getElementById('global-filter-type');

    if (sevSelect) {
      sevSelect.addEventListener('change', (e) => {
        this.filters.severity = e.target.value;
        if(typeof THRAGG_EventBus !== 'undefined') {
          THRAGG_EventBus.emit('GLOBAL_FILTER_CHANGED', this.filters);
        }
      });
    }

    if (typeSelect) {
      typeSelect.addEventListener('change', (e) => {
        this.filters.type = e.target.value;
        if(typeof THRAGG_EventBus !== 'undefined') {
          THRAGG_EventBus.emit('GLOBAL_FILTER_CHANGED', this.filters);
        }
      });
    }
  },

  search(query) {
    if (!query) return [];
    const lower = query.toLowerCase();
    return this.index.filter(item => 
      item.label.toLowerCase().includes(lower) || 
      item.desc.toLowerCase().includes(lower) ||
      item.type.toLowerCase().includes(lower)
    ).slice(0, 10); // Return top 10 matches
  }
};
