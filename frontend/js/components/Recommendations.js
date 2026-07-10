/* ==========================================================================
   THRAGG — Recommendations Component
   ========================================================================== */

const THRAGG_Recommendations = {
  render(container) {
    if (!container) return;
    const recs = THRAGG_DATA.executive_assessment.executive_recommendations || [];

    if (!recs.length) {
      container.innerHTML = `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin-bottom: var(--space-4);">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"></path>
          </svg>
          <div class="empty-state-title" style="font-size: var(--font-size-lg); font-weight: var(--font-weight-semibold); color: var(--text-primary); margin-bottom: var(--space-2);">No Recommendations</div>
          <div class="empty-state-text" style="color: var(--text-secondary); max-width: 400px; text-align: center;">
            No critical action items or architectural recommendations were identified in the current intelligence scope.
          </div>
        </div>
      `;
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
