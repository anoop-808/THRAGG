/* ==========================================================================
   THRAGG — Recommendations Component
   ========================================================================== */

const THRAGG_Recommendations = {
  render(container) {
    if (!container) return;
    const recs = THRAGG_DATA.executive_assessment.executive_recommendations || [];

    if (!recs.length) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-text">No recommendations available.</div></div>';
      return;
    }

    container.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: var(--space-3);">
        ${recs.map((rec, i) => `
          <div class="rec-card stagger-item" style="animation-delay: ${i * 80}ms">
            <div class="rec-priority ${rec.priority.toLowerCase()}"></div>
            <div class="rec-content">
              <div class="rec-title">${rec.title}</div>
              <div class="rec-description">${rec.description}</div>
              <div class="rec-meta">
                <span class="badge badge-${rec.priority.toLowerCase()}">${rec.priority}</span>
                <span class="domain-label ${rec.domain?.toLowerCase() || ''}">${rec.domain || 'General'}</span>
                <span class="tag">${rec.category || 'Recommendation'}</span>
                ${rec.expected_benefit ? `<span class="tag">Expected: ${rec.expected_benefit}</span>` : ''}
              </div>
              ${rec.references && rec.references.length ? `
                <div style="margin-top: var(--space-2); font-size: 10px; color: var(--text-muted);">
                  References: ${rec.references.join(', ')}
                </div>
              ` : ''}
            </div>
          </div>
        `).join('')}
      </div>
    `;
  }
};
