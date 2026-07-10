/* ==========================================================================
   THRAGG — Global Intelligence Index
   Builds a unified, lightweight searchable index from canonical data.
   ========================================================================== */

const THRAGG_GlobalIndex = {
  index: [],
  isIndexed: false,

  init() {
    this.rebuildIndex();
    
    // Incrementally update index on specific events if needed
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.on('CASE_CREATED', () => this.rebuildIndex());
      THRAGG_EventBus.on('CASE_UPDATED', () => this.rebuildIndex());
      THRAGG_EventBus.on('BOOKMARK_ADDED', () => this.rebuildIndex());
    }
  },

  rebuildIndex() {
    const data = window.THRAGG_DATA || {};
    const newIndex = [];

    // 1. Entities
    (data.entities || []).forEach(e => {
      newIndex.push({
        id: `entity-${e.id}`,
        category: 'Entity',
        title: e.id,
        subtitle: `Type: ${e.type} · Confidence: ${e.confidence}%`,
        icon: '🖧',
        weight: 10,
        searchable: [e.id, e.type, e.attributes?.hostname, e.attributes?.username, e.attributes?.name].filter(Boolean).join(' ').toLowerCase(),
        action: 'SELECT_ENTITY',
        refId: e.id,
        refData: e
      });
    });

    // 2. Findings
    (data.executive_assessment?.observations || []).forEach(o => {
      newIndex.push({
        id: `finding-${o.id || o.category}`,
        category: 'Finding',
        title: o.summary.substring(0, 60) + (o.summary.length > 60 ? '...' : ''),
        subtitle: `Severity: ${o.severity} · Category: ${o.category}`,
        icon: '🎯',
        weight: 20, // Higher weight for findings
        searchable: [o.summary, o.category, o.severity, ...(o.mitre_tactics || [])].join(' ').toLowerCase(),
        action: 'SELECT_FINDING',
        refId: o.id || o.category,
        refData: o
      });
    });

    // 3. Attack Chains
    (data.attack_chains || []).forEach(c => {
      newIndex.push({
        id: `chain-${c.id}`,
        category: 'Attack Chain',
        title: c.title || c.id,
        subtitle: `Severity: ${c.severity} · Steps: ${c.steps?.length || 0}`,
        icon: '⛓️',
        weight: 30, // Highest weight
        searchable: [c.title, c.id, c.severity, c.description].join(' ').toLowerCase(),
        action: 'SELECT_CHAIN',
        refId: c.id,
        refData: c
      });
    });

    // 4. Recommendations
    (data.recommendations || []).forEach(r => {
      newIndex.push({
        id: `rec-${r.id}`,
        category: 'Recommendation',
        title: r.title,
        subtitle: `Priority: ${r.priority} · Effort: ${r.effort}`,
        icon: '💡',
        weight: 5,
        searchable: [r.title, r.priority, r.description].join(' ').toLowerCase(),
        action: 'SELECT_RECOMMENDATION',
        refId: r.id,
        refData: r
      });
    });

    // 5. Cases (if CaseManager exists)
    if (typeof THRAGG_CaseManager !== 'undefined') {
      const cases = THRAGG_CaseManager.getAllCases();
      cases.forEach(c => {
        newIndex.push({
          id: `case-${c.id}`,
          category: 'Case',
          title: c.title,
          subtitle: `Status: ${c.status} · Bookmarks: ${c.bookmarks.length}`,
          icon: '📁',
          weight: 25,
          searchable: [c.title, c.id, c.status, c.analyst].join(' ').toLowerCase(),
          action: 'SELECT_CASE',
          refId: c.id,
          refData: c
        });
      });
    }

    this.index = newIndex;
    this.isIndexed = true;
  },

  search(query) {
    if (!query || !query.trim()) return [];
    
    const terms = query.toLowerCase().trim().split(/\s+/);
    
    const results = this.index.map(item => {
      let score = 0;
      let allMatch = true;

      terms.forEach(term => {
        if (item.title.toLowerCase().includes(term)) {
          score += 10;
          if (item.title.toLowerCase().startsWith(term)) score += 5;
        } else if (item.searchable.includes(term)) {
          score += 3;
        } else if (item.category.toLowerCase().includes(term)) {
          score += 1;
        } else {
          allMatch = false;
        }
      });

      // Calculate final score
      const finalScore = allMatch ? (score + item.weight) : 0;
      return { item, score: finalScore };
    });

    return results
      .filter(r => r.score > 0)
      .sort((a, b) => b.score - a.score)
      .map(r => r.item)
      .slice(0, 15); // Top 15 matches
  }
};
