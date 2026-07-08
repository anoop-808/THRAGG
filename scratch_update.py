import re
from pathlib import Path

path = Path('/home/karna/Projects/THRAGG/frontend/upload/index.html')
content = path.read_text()

# 1. Add new CSS for views and ingestion
new_css = """
    /* ── Views ──────────────────────────────────────────────────────── */
    .view-container {
      display: none;
      width: 100%;
      min-height: 100vh;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      position: absolute;
      inset: 0;
      padding: 40px 20px;
    }
    .view-container.active {
      display: flex;
    }

    /* ── Ingestion Animation ────────────────────────────────────────── */
    #thragg-core {
      width: 80px;
      height: 80px;
      border-radius: 50%;
      background: var(--brand-gradient);
      box-shadow: 0 0 30px rgba(108, 92, 231, 0.4);
      position: relative;
      z-index: 10;
      transition: all 0.3s ease;
    }
    #thragg-core.pulse {
      transform: scale(1.3);
      box-shadow: 0 0 60px rgba(108, 92, 231, 0.8), 0 0 100px rgba(0, 210, 255, 0.4);
    }
    .flying-file {
      position: fixed;
      z-index: 20;
      transition: all 0.6s cubic-bezier(0.25, 1, 0.5, 1);
      /* same styles as .file-item but fixed */
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 14px;
      background: rgba(15, 21, 39, 0.95);
      border: 1px solid var(--brand-primary);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-glow);
    }
    .chamber-header {
      text-align: center;
      margin-bottom: 40px;
    }
    .chamber-title {
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--text-primary);
      margin-bottom: 8px;
    }
    .chamber-session {
      font-family: var(--font-mono);
      font-size: 0.8125rem;
      color: var(--brand-light);
    }
    .chamber-pipeline {
      width: 100%;
      max-width: 600px;
      background: rgba(15, 21, 39, 0.75);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-2xl);
      padding: 32px 40px;
      box-shadow: var(--shadow-lg);
    }
    .chamber-pipeline .pipeline-step {
      padding: 14px 0;
    }
    .chamber-pipeline .pipeline-step:not(:last-child)::after {
      top: 46px;
      height: calc(100% - 30px);
    }
"""

content = content.replace("    /* ── Reset ──────────────────────────────────────────────────────── */", new_css + "\n    /* ── Reset ──────────────────────────────────────────────────────── */")

# 2. Modify body HTML to include views
body_start = content.find('<body>') + 6
body_end = content.find('<script>')

old_body = content[body_start:body_end]

new_body = """
  <!-- View 1: Upload (Landing) -->
  <div class="view-container active" id="view-upload">
""" + old_body.replace('<div class="page">', '<div>').replace('<!-- Footer -->', '</div><!-- Footer -->')

# Remove the old status panel and pipeline from View 1
new_body = re.sub(r'<!-- Divider \+ Status panel.*?</div>\s*</div>\s*<!-- Footer -->', '\n    </div>\n    <!-- Footer -->', new_body, flags=re.DOTALL)

# Add View 2 and View 3
new_body += """
  <!-- View 2: Ingestion -->
  <div class="view-container" id="view-ingestion">
    <div id="thragg-core"></div>
    <div style="margin-top:40px; font-weight:600; color:var(--brand-light); letter-spacing:0.1em; text-transform:uppercase;">Ingesting Evidence</div>
  </div>

  <!-- View 3: Analysis Chamber -->
  <div class="view-container" id="view-chamber">
    <div class="chamber-header">
      <div class="chamber-title">Intelligence Analysis Chamber</div>
      <div class="chamber-session" id="chamber-session-id"></div>
    </div>
    <div class="chamber-pipeline">
      <div class="pipeline" id="chamber-pipeline">
        <!-- Stages will be populated by JS -->
      </div>
      <div class="error-box" id="chamber-error-box" style="margin-top:24px;">
        <strong>Analysis Failed</strong>
        <span id="chamber-error-detail"></span>
        <button class="btn btn-ghost" style="margin-top:12px; width:100%; justify-content:center;" onclick="window.location.reload()">Start Over</button>
      </div>
    </div>
  </div>
"""
content = content[:body_start] + new_body + content[body_end:]

# 3. Rewrite JS to handle the new views and hybrid progress

js_start = content.find('<script>')
js_end = content.find('</script>') + 9

new_js = """<script>
    /* ================================================================
       THRAGG UX — Hybrid Progress & Ingestion
       ================================================================ */

    const MAX_FILE_BYTES  = 10 * 1024 * 1024;
    const MAX_TOTAL_BYTES = 50 * 1024 * 1024;
    const ALLOWED_EXTS    = new Set(['.log', '.xml', '.json', '.html', '.txt']);
    const POLL_INTERVAL   = 2000;

    let selectedFiles = [];
    let pollTimer     = null;
    let currentSessionId = null;

    // DOM Elements
    const dropZone       = document.getElementById('drop-zone');
    const fileInput      = document.getElementById('file-input');
    const fileList       = document.getElementById('file-list');
    const sizeTracker    = document.getElementById('size-tracker');
    const sizeBar        = document.getElementById('size-bar');
    const sizeLabel      = document.getElementById('size-label');
    const errorBox       = document.getElementById('error-box');
    const errorTitle     = document.getElementById('error-title');
    const errorDetail    = document.getElementById('error-detail');
    const btnAnalyze     = document.getElementById('btn-analyze');
    const btnClear       = document.getElementById('btn-clear');
    const fileCount      = document.getElementById('file-count');

    // Views
    const viewUpload     = document.getElementById('view-upload');
    const viewIngestion  = document.getElementById('view-ingestion');
    const viewChamber    = document.getElementById('view-chamber');
    const thraggCore     = document.getElementById('thragg-core');

    // Chamber Elements
    const chamberSessionId = document.getElementById('chamber-session-id');
    const chamberPipeline  = document.getElementById('chamber-pipeline');
    const chamberError     = document.getElementById('chamber-error-box');
    const chamberErrorDet  = document.getElementById('chamber-error-detail');

    // The 9 Conceptual Stages mapping
    const PIPELINE_STAGES = [
      { id: 'st-intake', name: 'Evidence Intake', desc: 'Receiving and validating files', trigger: 'UPLOADING' },
      { id: 'st-module', name: 'Module Execution', desc: 'Parsing evidence with specific modules', trigger: 'ANALYZING_1' },
      { id: 'st-entity', name: 'Entity Resolution', desc: 'Extracting and normalizing entities', trigger: 'ANALYZING_2' },
      { id: 'st-rel',    name: 'Relationship Mapping', desc: 'Connecting entities', trigger: 'ANALYZING_3' },
      { id: 'st-corr',   name: 'Correlation Engine', desc: 'Finding cross-module correlations', trigger: 'ANALYZING_4' },
      { id: 'st-chain',  name: 'Attack Chain Discovery', desc: 'Building attack narratives', trigger: 'ANALYZING_5' },
      { id: 'st-risk',   name: 'Risk Assessment', desc: 'Scoring risks and mapping MITRE', trigger: 'ANALYZING_6' },
      { id: 'st-report', name: 'Executive Report Generation', desc: 'Compiling offline intelligence', trigger: 'GENERATING_REPORTS' },
      { id: 'st-dash',   name: 'Dashboard Preparation', desc: 'Finalizing JSON outputs', trigger: 'COMPLETE' }
    ];

    // Build Pipeline DOM
    function renderChamberPipeline() {
      chamberPipeline.innerHTML = PIPELINE_STAGES.map((s, i) => `
        <div class="pipeline-step pending" id="${s.id}">
          <div class="step-dot">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
              <circle cx="12" cy="12" r="2"/>
            </svg>
          </div>
          <div class="step-text">
            <div class="step-name">${i+1}. ${s.name}</div>
            <div class="step-detail">${s.desc}</div>
          </div>
        </div>
      `).join('');
    }
    renderChamberPipeline();

    // -- File Utilities --
    function ext(filename) {
      const dot = filename.lastIndexOf('.');
      return dot >= 0 ? filename.slice(dot).toLowerCase() : '';
    }
    function extClass(extension) {
      const map = { '.log': 'ext-log', '.xml': 'ext-xml', '.json': 'ext-json', '.html': 'ext-html', '.txt': 'ext-txt' };
      return map[extension] || 'ext-txt';
    }
    function formatBytes(bytes) {
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }

    // -- Validation & File List --
    function validateFiles(files) {
      for (const f of files) {
        const e = ext(f.name);
        if (!ALLOWED_EXTS.has(e)) return `"${f.name}" is not supported.`;
        if (f.size > MAX_FILE_BYTES) return `"${f.name}" exceeds 10 MB.`;
      }
      return null;
    }
    function renderFileList() {
      fileList.innerHTML = '';
      let total = 0;
      selectedFiles.forEach((f, i) => {
        total += f.size;
        const e = ext(f.name);
        fileList.insertAdjacentHTML('beforeend', `
          <div class="file-item" id="file-item-${i}">
            <span class="file-type-badge ${extClass(e)}">${e.replace('.', '')}</span>
            <span class="file-name" title="${f.name}">${f.name}</span>
            <span class="file-size">${formatBytes(f.size)}</span>
            <button class="file-remove" data-index="${i}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
          </div>
        `);
      });
      if (selectedFiles.length > 0) {
        const pct = Math.min(100, (total / MAX_TOTAL_BYTES) * 100);
        sizeTracker.style.display = 'flex';
        sizeBar.style.width = pct + '%';
        sizeBar.className = 'size-bar' + (pct > 90 ? ' danger' : pct > 70 ? ' warn' : '');
        sizeLabel.textContent = formatBytes(total) + ' / 50 MB';
      } else {
        sizeTracker.style.display = 'none';
      }
      fileCount.textContent = selectedFiles.length ? `${selectedFiles.length} file(s)` : '';
      btnAnalyze.disabled = selectedFiles.length === 0;
      btnClear.style.display = selectedFiles.length > 0 ? '' : 'none';
      hideError();
    }
    function addFiles(files) {
      const incoming = Array.from(files);
      const err = validateFiles(incoming);
      if (err) { showError('Validation Error', err); return; }
      const existing = new Set(selectedFiles.map(f => f.name));
      const newFiles = incoming.filter(f => !existing.has(f.name));
      const merged = [...selectedFiles, ...newFiles];
      const total = merged.reduce((s, f) => s + f.size, 0);
      if (total > MAX_TOTAL_BYTES) { showError('Size Exceeded', `Total size > 50 MB`); return; }
      selectedFiles = merged;
      renderFileList();
    }
    fileList.addEventListener('click', e => {
      const btn = e.target.closest('.file-remove');
      if (!btn) return;
      selectedFiles.splice(parseInt(btn.dataset.index, 10), 1);
      renderFileList();
    });
    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => { if(fileInput.files.length) addFiles(fileInput.files); fileInput.value = ''; });
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
    dropZone.addEventListener('dragleave', e => { if (!dropZone.contains(e.relatedTarget)) dropZone.classList.remove('drag-over'); });
    dropZone.addEventListener('drop', e => { e.preventDefault(); dropZone.classList.remove('drag-over'); if (e.dataTransfer.files.length) addFiles(e.dataTransfer.files); });
    btnClear.addEventListener('click', () => { selectedFiles = []; renderFileList(); });

    function showError(title, detail) { errorTitle.textContent = title; errorDetail.textContent = detail; errorBox.classList.add('visible'); }
    function hideError() { errorBox.classList.remove('visible'); }

    // -- Animation & Transition --
    async function playIngestionAnimation() {
      return new Promise(resolve => {
        const fileElements = Array.from(document.querySelectorAll('.file-item'));
        const clones = [];
        // 1. Switch views visually but keep clones fixed
        fileElements.forEach((el, index) => {
          const rect = el.getBoundingClientRect();
          const clone = el.cloneNode(true);
          clone.className = 'flying-file';
          // Ensure it picks up correct internal elements like badges
          const e = ext(selectedFiles[index].name);
          clone.innerHTML = `
            <span class="file-type-badge ${extClass(e)}">${e.replace('.', '')}</span>
            <span class="file-name">${selectedFiles[index].name}</span>
          `;
          clone.style.top = rect.top + 'px';
          clone.style.left = rect.left + 'px';
          clone.style.width = rect.width + 'px';
          document.body.appendChild(clone);
          clones.push(clone);
        });

        viewUpload.classList.remove('active');
        viewIngestion.classList.add('active');

        // 2. Animate each clone to center
        const coreRect = thraggCore.getBoundingClientRect();
        const coreX = coreRect.left + coreRect.width / 2;
        const coreY = coreRect.top + coreRect.height / 2;

        if (clones.length === 0) return resolve();

        clones.forEach((clone, i) => {
          setTimeout(() => {
            const cloneRect = clone.getBoundingClientRect();
            const startX = cloneRect.left + cloneRect.width / 2;
            const startY = cloneRect.top + cloneRect.height / 2;
            const tx = coreX - startX;
            const ty = coreY - startY;

            clone.style.transform = `translate(${tx}px, ${ty}px) scale(0.1)`;
            clone.style.opacity = '0';
            
            setTimeout(() => {
              thraggCore.classList.add('pulse');
              setTimeout(() => thraggCore.classList.remove('pulse'), 300);
            }, 500);

            if (i === clones.length - 1) {
              setTimeout(() => {
                clones.forEach(c => c.remove());
                resolve();
              }, 600); // Wait for last file animation to finish
            }
          }, i * 300); // Stagger
        });
      });
    }

    btnAnalyze.addEventListener('click', async () => {
      if (selectedFiles.length === 0) return;
      hideError();
      btnAnalyze.classList.add('loading');
      btnAnalyze.disabled = true;
      btnClear.disabled = true;

      const form = new FormData();
      selectedFiles.forEach(f => form.append('files', f));

      let sessionId;
      try {
        const res = await fetch('/api/upload', { method: 'POST', body: form });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || data.message || 'Upload failed');
        sessionId = data.session_id;
        
        const analyzeRes = await fetch(`/api/analyze/${sessionId}`, { method: 'POST' });
        if (!analyzeRes.ok) throw new Error('Analysis trigger failed');
      } catch (err) {
        showError('Error', err.message);
        btnAnalyze.classList.remove('loading');
        btnAnalyze.disabled = false;
        btnClear.disabled = false;
        return;
      }

      currentSessionId = sessionId;
      chamberSessionId.textContent = 'Session: ' + sessionId;

      // Play Animation
      await playIngestionAnimation();

      // Switch to Chamber
      viewIngestion.classList.remove('active');
      viewChamber.classList.add('active');

      // Start hybrid progress polling
      startPolling(sessionId);
    });

    // -- Hybrid Progress Logic --
    let analyzingSimTimer = null;
    let analyzingStage = 1; // Tracks 1 to 6 inside ANALYZING (indices 1 to 6 in PIPELINE_STAGES)

    function updatePipelineUI(targetStageIndex, isFailed=false) {
      PIPELINE_STAGES.forEach((s, i) => {
        const el = document.getElementById(s.id);
        if (!el) return;
        
        if (isFailed) {
          el.className = 'pipeline-step ' + (i < targetStageIndex ? 'done' : i === targetStageIndex ? 'failed' : 'pending');
        } else {
          if (i < targetStageIndex) el.className = 'pipeline-step done';
          else if (i === targetStageIndex) el.className = 'pipeline-step active';
          else el.className = 'pipeline-step pending';
        }

        const dot = el.querySelector('.step-dot');
        if (i < targetStageIndex || (!isFailed && i === PIPELINE_STAGES.length - 1 && targetStageIndex === PIPELINE_STAGES.length - 1)) {
          dot.innerHTML = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>`;
        } else if (isFailed && i === targetStageIndex) {
          dot.innerHTML = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
        } else {
           dot.innerHTML = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="2"/></svg>`;
        }
      });
    }

    function handleAnalyzingSimulation() {
      if (!analyzingSimTimer) {
        analyzingSimTimer = setInterval(() => {
          if (analyzingStage < 6) {
            analyzingStage++;
            updatePipelineUI(analyzingStage);
          }
        }, 1500); // Conceptually advance a stage every 1.5s
      }
    }

    function startPolling(sessionId) {
      updatePipelineUI(0); // Intake
      pollTimer = setInterval(() => poll(sessionId), POLL_INTERVAL);
    }

    async function poll(sessionId) {
      let data;
      try {
        const res = await fetch(`/api/status/${sessionId}`);
        if (!res.ok) return;
        data = await res.json();
      } catch { return; }

      const state = data.status;
      
      if (state === 'QUEUED' || state === 'UPLOADING') {
        updatePipelineUI(0);
      } else if (state === 'ANALYZING') {
        updatePipelineUI(analyzingStage);
        handleAnalyzingSimulation();
      } else if (state === 'GENERATING_REPORTS') {
        if (analyzingSimTimer) { clearInterval(analyzingSimTimer); analyzingSimTimer = null; }
        updatePipelineUI(7); // Jump to report gen
      } else if (state === 'COMPLETE') {
        clearInterval(pollTimer);
        if (analyzingSimTimer) clearInterval(analyzingSimTimer);
        updatePipelineUI(8);
        setTimeout(() => {
          window.location.href = `/dashboard/${sessionId}`;
        }, 1200);
      } else if (state === 'FAILED') {
        clearInterval(pollTimer);
        if (analyzingSimTimer) clearInterval(analyzingSimTimer);
        
        let errStage = 0;
        if (analyzingStage > 1 && analyzingStage <= 6) errStage = analyzingStage;
        else errStage = PIPELINE_STAGES.findIndex(s => s.trigger === state);
        if (errStage === -1) errStage = analyzingStage;

        updatePipelineUI(errStage, true);
        chamberErrorDet.textContent = data.error_detail || 'Unknown error occurred.';
        chamberError.classList.add('visible');
      }
    }
</script>"""

content = content[:js_start] + new_js + content[js_end:]
path.write_text(content)
print("Updated frontend/upload/index.html")
