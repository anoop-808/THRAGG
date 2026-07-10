/* ==========================================================================
   THRAGG — Report Preview
   Renders the HTML layout in-app from the Canonical Report Model.
   ========================================================================== */

const THRAGG_ReportPreview = {
  render(container) {
    if (!container) return;

    if (typeof THRAGG_ReportBuilder === 'undefined' || typeof THRAGG_ReportTemplate === 'undefined') {
      container.innerHTML = `<div class="view-container"><h2>Error: Report utilities not loaded.</h2></div>`;
      return;
    }

    const config = THRAGG_ReportComposer.config;
    const model = THRAGG_ReportBuilder.buildCanonicalModel();
    const html = THRAGG_ReportTemplate.generateHTML(model, config);

    container.innerHTML = `
      <div class="view-container animate-fade-in-up" style="max-width: 1000px; margin: 0 auto; display: flex; flex-direction: column; height: 100%;">
        <div class="view-header" style="margin-bottom: var(--space-4); display: flex; justify-content: space-between; align-items: center; flex-shrink: 0;">
          <div>
            <div class="page-title">Executive Report Preview</div>
            <div class="page-subtitle">Print-ready static rendering. Animations disabled.</div>
          </div>
          <div style="display: flex; gap: 8px;">
            <button class="btn btn-secondary" onclick="THRAGG_App.navigate('report_composer')">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg>
              Back to Composer
            </button>
            <button class="btn btn-primary" onclick="THRAGG_ReportComposer.exportReport('HTML')">Download HTML</button>
          </div>
        </div>
        
        <div style="flex: 1; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; background: #fff;">
          <iframe id="report-preview-frame" style="width: 100%; height: 100%; border: none;"></iframe>
        </div>
      </div>
    `;

    const iframe = document.getElementById('report-preview-frame');
    if (iframe) {
      // Use srcdoc to safely inject the HTML into the iframe isolated context
      iframe.srcdoc = html;
    }
  }
};
