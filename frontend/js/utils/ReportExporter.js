/* ==========================================================================
   THRAGG — Report Exporter
   Converts templates into downloadable files via browser blob APIs.
   ========================================================================== */

const THRAGG_ReportExporter = {
  export(format, model, config) {
    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('REPORT_EXPORT_STARTED', { format, config });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filenameBase = `THRAGG_${config.title ? config.title.replace(/\s+/g, '_') : 'Incident_Report'}_${timestamp}`;

    let content = '';
    let mimeType = 'text/plain';
    let extension = '.txt';

    switch (format.toUpperCase()) {
      case 'HTML':
        content = THRAGG_ReportTemplate.generateHTML(model, config);
        mimeType = 'text/html';
        extension = '.html';
        break;
      case 'MD':
        content = THRAGG_ReportTemplate.generateMarkdown(model, config);
        mimeType = 'text/markdown';
        extension = '.md';
        break;
      case 'JSON':
        content = JSON.stringify({ config, report: model }, null, 2);
        mimeType = 'application/json';
        extension = '.json';
        break;
      case 'TXT':
      default:
        content = THRAGG_ReportTemplate.generateTXT(model, config);
        mimeType = 'text/plain';
        extension = '.txt';
        break;
    }

    this._downloadBlob(content, mimeType, filenameBase + extension);

    if (typeof THRAGG_EventBus !== 'undefined') {
      THRAGG_EventBus.emit('REPORT_EXPORTED', { format, filename: filenameBase + extension });
    }
  },

  _downloadBlob(content, mimeType, filename) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
};
