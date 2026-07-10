/* ==========================================================================
   THRAGG — Knowledge Graph Component (Physics + SVG)
   ========================================================================== */

const THRAGG_KnowledgeGraph = {
  container: null,
  svgRoot: null,
  gTransform: null,
  physics: null,
  
  nodes: [],
  links: [],
  nodeMap: {},
  
  scale: 1,
  panX: 0,
  panY: 0,
  isDraggingCanvas: false,
  isDraggingNode: null,
  lastMouseX: 0,
  lastMouseY: 0,
  
  selectedNodeId: null,

  render(container) {
    if (!container) return;
    this.destroy();
    this.container = container;

    container.innerHTML = `
      <div class="card" style="display: flex; flex-direction: column; height: 100%;">
        <div class="card-header" style="flex-shrink: 0; z-index: 20; position: relative;">
          <div>
            <span class="section-title" style="margin:0">Knowledge Graph</span>
            <span class="badge badge-info" id="kg-badge">Initializing...</span>
          </div>
          <div style="display: flex; gap: var(--space-2);">
            <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" id="kg-reset-btn">Reset View</button>
            <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" id="kg-fit-btn">Fit</button>
          </div>
        </div>
        <div class="card-body" style="padding: 0; flex: 1; position: relative; overflow: hidden; background: #000;" id="kg-viewport">
          <svg id="kg-svg" style="width: 100%; height: 100%; cursor: grab;">
            <defs>
              <pattern id="kg-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.02)" stroke-width="1"/>
              </pattern>
              <marker id="kg-arrow" markerWidth="8" markerHeight="8" refX="24" refY="4" orient="auto">
                <polygon points="0 0, 8 4, 0 8" fill="rgba(255,255,255,0.3)"/>
              </marker>
              <marker id="kg-arrow-highlight" markerWidth="8" markerHeight="8" refX="24" refY="4" orient="auto">
                <polygon points="0 0, 8 4, 0 8" fill="var(--brand-primary)"/>
              </marker>
              <linearGradient id="kg-core-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#6c5ce7"/>
                <stop offset="100%" stop-color="#a29bfe"/>
              </linearGradient>
            </defs>
            <rect width="100%" height="100%" fill="url(#kg-grid)" id="kg-bg-rect"/>
            <g id="kg-transform-layer">
              <g id="kg-links-layer"></g>
              <g id="kg-nodes-layer"></g>
            </g>
          </svg>
        </div>
      </div>
    `;

    this.svgRoot = document.getElementById('kg-svg');
    this.gTransform = document.getElementById('kg-transform-layer');
    this.linksLayer = document.getElementById('kg-links-layer');
    this.nodesLayer = document.getElementById('kg-nodes-layer');

    this._initData();
    
    if (!this._eventsBound) {
      this._bindEvents();

      if (typeof THRAGG_EventBus !== 'undefined') {
        this._onContextChanged = (context) => {
          if (!context) this.selectNode(null);
          else {
            const t = context.type.toLowerCase();
            if (t === 'entity') this.selectNode(context.id);
            else if (t === 'finding' || t === 'correlation' || t === 'observation') this.highlightFinding(context.id);
            else if (t === 'attack chain' || t === 'attack_chain') {
              const chainData = (THRAGG_DATA.attack_chains || []).find(c => c.id === context.id || c.title === context.id);
              if (chainData) this.highlightChain(chainData);
              else this.selectNode(null);
            }
            else this.selectNode(null);
          }
        };
        THRAGG_EventBus.on('CONTEXT_CHANGED', this._onContextChanged);

        this._onHoverPreview = (context) => {
          if (!context) this._onNodeHover(null);
          else if (context.type === 'Entity') this._onNodeHover(this.nodeMap[context.id]);
        };
        THRAGG_EventBus.on('HOVER_PREVIEW', this._onHoverPreview);

        this._onChainSelected = (chainData) => this.highlightChain(chainData);
        THRAGG_EventBus.on('CHAIN_SELECTED', this._onChainSelected);

        this._onReplayStep = (data) => {
          if (!data || !data.step) return;
          this._highlightReplayStep(data.step.source_id, data.step.target_id);
        };
        THRAGG_EventBus.on('REPLAY_STEP_CHANGED', this._onReplayStep);

        this._onReplayStopped = () => {
          if (this.svgRoot) this.svgRoot.classList.remove('kg-replay-mode');
          this.clearSelection();
        };
        THRAGG_EventBus.on('REPLAY_STOPPED', this._onReplayStopped);

        this._onGlobalFilterChanged = () => {
          setTimeout(() => this._fitToScreen(), 100);
        };
        THRAGG_EventBus.on('GLOBAL_FILTER_CHANGED', this._onGlobalFilterChanged);

      }
      this._eventsBound = true;
    }

    this._startPhysics();
  },

  _initData() {
    this.nodes = [];
    this.links = [];
    this.nodeMap = {};

    const rawNodes = Array.isArray(THRAGG_DATA.resolved_entities) ? THRAGG_DATA.resolved_entities : Object.values(THRAGG_DATA.resolved_entities || {});
    const rawLinks = THRAGG_DATA.relationships || [];

    if (!rawNodes.length) {
      if (this.container) {
        this.container.innerHTML = `
          <div class="empty-state" style="height: 100%; justify-content: center;">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin-bottom: var(--space-4);">
              <circle cx="12" cy="12" r="3"></circle>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
            </svg>
            <div class="empty-state-title" style="font-size: var(--font-size-lg); font-weight: var(--font-weight-semibold); color: var(--text-primary); margin-bottom: var(--space-2);">No Knowledge Graph Generated</div>
            <div class="empty-state-text" style="color: var(--text-secondary); max-width: 400px; text-align: center;">
              No entity relationships could be mapped from the current intelligence dataset.
            </div>
          </div>
        `;
      }
      return;
    }

    const viewport = document.getElementById('kg-viewport');
    const vw = viewport ? viewport.clientWidth : 800;
    const vh = viewport ? viewport.clientHeight : 500;

    // Add Central Core Node
    const coreNode = {
      id: 'THRAGG-CORE',
      isCore: true,
      x: vw / 2,
      y: vh / 2,
      vx: 0, vy: 0,
      radius: 25,
      color: 'url(#kg-core-grad)',
      fixed: true // pinned to center
    };
    this.nodes.push(coreNode);
    this.nodeMap[coreNode.id] = coreNode;

    // Map Entities — scatter in radial sunflower pattern for wide initial spread
    const scatterRadius = Math.min(vw, vh) * 0.38; // 38% of smaller dimension
    const goldenAngle = Math.PI * (3 - Math.sqrt(5)); // ~137.5°
    rawNodes.forEach((n, i) => {
      const entityType = n.entity_type || 'UNKNOWN';
      const colorMap = {
        'HOST': '#00d2ff',
        'USER': '#f97316',
        'CLOUD_RESOURCE': '#6c5ce7',
        'SERVICE': '#eab308',
        'APPLICATION': '#22c55e',
        'NETWORK': '#00d2ff',
        // Fallbacks
        'Host': '#00d2ff',
        'User': '#f97316',
        'Cloud': '#6c5ce7',
        'Service': '#eab308',
        'Web': '#22c55e',
        'Network': '#00d2ff'
      };
      
      const colorKey = colorMap[entityType] ? entityType : entityType.toUpperCase();
      const color = colorMap[colorKey] || '#94a3b8';
      
      const displayLabel = 
        n.primary_identifier ??
        n.attributes?.hostname ??
        n.attributes?.username ??
        n.attributes?.name ??
        n.id;

      // Sunflower spiral: distributes nodes evenly without clustering at origin
      const r = scatterRadius * Math.sqrt((i + 1) / rawNodes.length);
      const angle = i * goldenAngle;

      const node = {
        id: n.id,
        type: entityType,
        label: displayLabel,
        x: vw / 2 + r * Math.cos(angle),
        y: vh / 2 + r * Math.sin(angle),
        vx: 0, vy: 0,
        radius: 18,
        color: color,
        fixed: false
      };
      this.nodes.push(node);
      this.nodeMap[n.id] = node;
    });

    // Map Links
    let validLinkCount = 0;
    rawLinks.forEach(l => {
      const srcId = l.source_entity_id || l.source;
      const tgtId = l.target_entity_id || l.target;
      const rType = l.relationship_type || l.type || 'RELATED_TO';

      if (srcId && tgtId && this.nodeMap[srcId] && this.nodeMap[tgtId]) {
        this.links.push({
          source: srcId,
          target: tgtId,
          type: rType
        });
        validLinkCount++;
      }
    });

    const badge = document.getElementById('kg-badge');
    if (badge) badge.textContent = `${this.nodes.length-1} entities · ${validLinkCount} relationships`;

    // Initial DOM creation
    this._renderSvgElements();
  },

  _renderSvgElements() {
    if (!this.linksLayer || !this.nodesLayer) return;
    this.linksLayer.innerHTML = this.links.map(l => `
      <line id="link-${l.source}-${l.target}" 
            class="kg-link" 
            stroke="rgba(255,255,255,0.15)" 
            stroke-width="1.5" 
            stroke-linecap="round"
            marker-end="url(#kg-arrow)"></line>
    `).join('');

    this.nodesLayer.innerHTML = this.nodes.map(n => {
      if (n.isCore) {
        return `
          <g id="node-${n.id}" class="kg-node" transform="translate(${n.x},${n.y})">
            <circle r="${n.radius}" fill="${n.color}" opacity="0.9" />
            <text y="3" text-anchor="middle" fill="#fff" font-size="8" font-family="var(--font-sans)" font-weight="bold">CORE</text>
          </g>
        `;
      }
      const glow = `rgba(${this._hexToRgb(n.color)}, 0.2)`;
      return `
        <g id="node-${n.id}" class="kg-node" transform="translate(${n.x},${n.y})" cursor="pointer">
          <circle r="${n.radius}" fill="${glow}" stroke="${n.color}" stroke-width="1.5" />
          <text class="kg-label" y="3" text-anchor="middle" fill="${n.color}" font-size="7" font-family="var(--font-mono)" font-weight="bold" pointer-events="none" style="transition: opacity 0.3s ease;">${n.type}</text>
          <text class="kg-label" y="24" text-anchor="middle" fill="var(--text-secondary)" font-size="8" font-family="var(--font-sans)" pointer-events="none" style="transition: opacity 0.3s ease;">${n.label}</text>
        </g>
      `;
    }).join('');

    // Attach listeners
    this.nodes.forEach(n => {
      const el = document.getElementById(`node-${n.id}`);
      if (el && !n.isCore) {
        el.addEventListener('mousedown', (e) => this._onNodeMouseDown(e, n));
        el.addEventListener('mouseenter', () => {
          if (typeof THRAGG_InvestigationSession !== 'undefined') THRAGG_InvestigationSession.setHoverPreview('Entity', n.id);
        });
        el.addEventListener('mouseleave', () => {
          if (typeof THRAGG_InvestigationSession !== 'undefined') THRAGG_InvestigationSession.clearHoverPreview();
        });
        el.addEventListener('click', (e) => {
          e.stopPropagation();
          if (typeof THRAGG_InvestigationSession !== 'undefined') {
            THRAGG_InvestigationSession.setContext('Entity', n.id);
          }
        });
      }
    });
  },

  _startPhysics() {
    if (!this.nodes.length) return;
    const viewport = document.getElementById('kg-viewport');
    const vw = viewport ? viewport.clientWidth : 800;
    const vh = viewport ? viewport.clientHeight : 500;

    if (this.physics) {
      this.physics.stop();
    }

    this.physics = new THRAGG_GraphPhysics(
      this.nodes,
      this.links,
      vw,
      vh,
      () => this._updateSvgPositions(),
      () => {
        // Delay fit to let final tick positions settle in the DOM
        clearTimeout(this._fitTimer);
        this._fitTimer = setTimeout(() => this._fitToScreen(), 50);
      }
    );
    this.physics.start();

    // Reframe on viewport resize (context panel open/close, window resize)
    if (typeof ResizeObserver !== 'undefined' && viewport) {
      if (this._resizeObserver) {
        this._resizeObserver.disconnect();
      }
      this._resizeObserver = new ResizeObserver(() => {
        // Only reframe if not mid-drag
        if (!this.isDraggingCanvas && !this.isDraggingNode && !this.physics?.isRunning) {
          this._fitToScreen();
        }
      });
      this._resizeObserver.observe(viewport);
    }
  },

  _updateSvgPositions() {
    const epsilon = 0.1;
    const nodeWrites = [];
    const linkWrites = [];
    const nodeMoved = new Set();

    this.nodes.forEach(n => {
      const moved = n._lastRenderX === undefined ||
        Math.abs(n.x - n._lastRenderX) >= epsilon ||
        Math.abs(n.y - n._lastRenderY) >= epsilon;
      if (moved) {
        nodeMoved.add(n.id);
        const el = document.getElementById(`node-${n.id}`);
        if (el) {
          nodeWrites.push({ el, node: n });
        }
      }
    });

    this.links.forEach(l => {
      const source = this.nodeMap[l.source];
      const target = this.nodeMap[l.target];
      if (source && target) {
        const moved = l._lastRenderX1 === undefined || nodeMoved.has(source.id) || nodeMoved.has(target.id);
        if (moved) {
          const el = document.getElementById(`link-${l.source}-${l.target}`);
          if (el) {
            linkWrites.push({ el, link: l, source, target });
          }
        }
      }
    });

    nodeWrites.forEach(({ el, node }) => {
      el.setAttribute('transform', `translate(${node.x},${node.y})`);
      node._lastRenderX = node.x;
      node._lastRenderY = node.y;
    });

    linkWrites.forEach(({ el, link, source, target }) => {
      el.setAttribute('x1', source.x);
      el.setAttribute('y1', source.y);
      el.setAttribute('x2', target.x);
      el.setAttribute('y2', target.y);
      link._lastRenderX1 = source.x;
      link._lastRenderY1 = source.y;
      link._lastRenderX2 = target.x;
      link._lastRenderY2 = target.y;
    });
  },

  _updateTransform() {
    if (this.gTransform) {
      this.gTransform.setAttribute('transform', `translate(${this.panX}, ${this.panY}) scale(${this.scale})`);
    }
    const bg = document.getElementById('kg-grid');
    if (bg) {
      bg.setAttribute('x', this.panX);
      bg.setAttribute('y', this.panY);
    }
    if (this.nodesLayer) {
      if (this.scale < 0.6) {
        this.nodesLayer.classList.add('kg-hide-labels');
      } else {
        this.nodesLayer.classList.remove('kg-hide-labels');
      }
    }
  },

  _bindEvents() {
    const svg = this.svgRoot;
    if (!svg) return;
    this._boundSvgRoot = svg;
    
    // Panning
    this._onSvgMouseDown = (e) => {
      if (e.target.closest('.kg-node')) return; // handled by node
      this.isDraggingCanvas = true;
      this.lastMouseX = e.clientX;
      this.lastMouseY = e.clientY;
      svg.style.cursor = 'grabbing';
      
      if (typeof THRAGG_EventBus !== 'undefined') {
        THRAGG_EventBus.emit('ENTITY_DESELECTED', null);
      }
    };
    svg.addEventListener('mousedown', this._onSvgMouseDown);

    this._onMouseMove = (e) => {
      if (this.isDraggingCanvas) {
        const dx = e.clientX - this.lastMouseX;
        const dy = e.clientY - this.lastMouseY;
        this.panX += dx;
        this.panY += dy;
        this.lastMouseX = e.clientX;
        this.lastMouseY = e.clientY;
        this._updateTransform();
      } else if (this.isDraggingNode) {
        // Find screen coordinates to SVG coordinates
        const ctm = this.gTransform.getScreenCTM().inverse();
        const pt = svg.createSVGPoint();
        pt.x = e.clientX;
        pt.y = e.clientY;
        const svgPt = pt.matrixTransform(ctm);
        
        this.isDraggingNode.x = svgPt.x;
        this.isDraggingNode.y = svgPt.y;
        if (this.physics) this.physics.reheat(0.3); // Gentle reheat
      }
    };
    window.addEventListener('mousemove', this._onMouseMove);

    this._onMouseUp = () => {
      this.isDraggingCanvas = false;
      if (this.isDraggingNode) {
        this.isDraggingNode.fixed = false;
        this.isDraggingNode = null;
      }
      svg.style.cursor = 'grab';
    };
    window.addEventListener('mouseup', this._onMouseUp);

    // Zooming
    this._onSvgWheel = (e) => {
      e.preventDefault();
      const zoomSensitivity = 0.001;
      const delta = -e.deltaY * zoomSensitivity;
      const oldScale = this.scale;
      this.scale = Math.max(0.1, Math.min(4, this.scale * (1 + delta)));
      
      // Zoom toward cursor
      const rect = svg.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      
      this.panX = mx - (mx - this.panX) * (this.scale / oldScale);
      this.panY = my - (my - this.panY) * (this.scale / oldScale);
      
      this._updateTransform();
    };
    svg.addEventListener('wheel', this._onSvgWheel, { passive: false });

    // Buttons
    const resetBtn = document.getElementById('kg-reset-btn');
    if (resetBtn) {
      this._resetBtn = resetBtn;
      this._onResetClick = () => {
        // Always reframe to actual graph bounds on reset
        this._fitToScreen();
        if (this.physics) this.physics.reheat(0.8);
      };
      resetBtn.addEventListener('click', this._onResetClick);
    }

    const fitBtn = document.getElementById('kg-fit-btn');
    if (fitBtn) {
      this._fitBtn = fitBtn;
      this._onFitClick = () => {
        this._fitToScreen();
      };
      fitBtn.addEventListener('click', this._onFitClick);
    }
  },

  _fitToScreen() {
    const viewport = document.getElementById('kg-viewport');
    if (!viewport || this.nodes.length === 0) return;

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    this.nodes.forEach(n => {
      // Account for node radius so circles don't clip at edges
      if (n.x - n.radius < minX) minX = n.x - n.radius;
      if (n.x + n.radius > maxX) maxX = n.x + n.radius;
      if (n.y - n.radius < minY) minY = n.y - n.radius;
      if (n.y + n.radius > maxY) maxY = n.y + n.radius;
    });

    const vw = viewport.clientWidth;
    const vh = viewport.clientHeight;

    // Target 88% fill — 6% padding on each side
    const paddingFraction = 0.06;
    const usableW = vw * (1 - paddingFraction * 2);
    const usableH = vh * (1 - paddingFraction * 2);

    const graphW = (maxX - minX) || 1;
    const graphH = (maxY - minY) || 1;

    // Pick the scale that makes the larger graph dimension fill the usable area
    const scaleX = usableW / graphW;
    const scaleY = usableH / graphH;
    // Use min so the graph always fits; cap at 3 to avoid excessive zoom-in on tiny graphs
    this.scale = Math.min(scaleX, scaleY, 3);

    // Center the bounding box
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    this.panX = vw / 2 - cx * this.scale;
    this.panY = vh / 2 - cy * this.scale;

    this.gTransform.style.transition = 'transform 0.45s cubic-bezier(0.25, 0.46, 0.45, 0.94)';
    this._updateTransform();
    clearTimeout(this._transitionTimer);
    this._transitionTimer = setTimeout(() => {
      if (this.gTransform) this.gTransform.style.transition = 'none';
    }, 500);
  },

  _onNodeMouseDown(e, node) {
    e.stopPropagation();
    this.isDraggingNode = node;
    node.fixed = true; // Pin during drag
  },

  _onNodeHover(hoveredNode) {
    if (this.selectedNodeId) return; // Don't disrupt selection
    
    const allNodeEls = document.querySelectorAll('.kg-node');
    const allLinkEls = document.querySelectorAll('.kg-link');

    if (!hoveredNode) {
      allNodeEls.forEach(el => { 
        el.style.opacity = '1'; 
        el.style.filter = 'none'; 
        el.classList.remove('preview', 'neighbor');
      });
      allLinkEls.forEach(el => { el.style.opacity = '1'; el.setAttribute('stroke', 'rgba(255,255,255,0.15)'); });
      return;
    }

    const connectedNodeIds = new Set();
    connectedNodeIds.add(hoveredNode.id);
    
    this.links.forEach(l => {
      if (l.source === hoveredNode.id) connectedNodeIds.add(l.target);
      if (l.target === hoveredNode.id) connectedNodeIds.add(l.source);
    });

    allNodeEls.forEach(el => {
      const id = el.id.replace('node-', '');
      el.classList.remove('preview', 'neighbor');
      if (id === hoveredNode.id) {
        el.style.opacity = '1';
        el.style.filter = 'drop-shadow(0 0 8px rgba(255,255,255,0.2))';
        el.classList.add('preview');
      } else if (!connectedNodeIds.has(id) && id !== 'THRAGG-CORE') {
        el.style.opacity = '0.15';
        el.style.filter = 'grayscale(100%)';
      } else {
        el.style.opacity = '1';
        el.style.filter = 'drop-shadow(0 0 8px rgba(255,255,255,0.2))';
        el.classList.add('neighbor');
      }
    });

    allLinkEls.forEach(el => {
      const linkId = el.id;
      if (linkId.includes(hoveredNode.id)) {
        el.style.opacity = '1';
        el.setAttribute('stroke', 'var(--brand-primary)');
      } else {
        el.style.opacity = '0.1';
      }
    });
  },

  highlightFinding(findingId) {
    let entities = [];
    let finding = (THRAGG_DATA.executive_assessment?.observations || []).find(o => o.summary.includes(findingId));
    if (finding && finding.entities) entities = finding.entities;
    if (!finding) {
      finding = (THRAGG_DATA.correlations || []).find(c => c.title === findingId);
      if (finding && finding.entities) entities = finding.entities;
    }

    if (!entities.length) return this.selectNode(null);

    // Instead of selecting one node, highlight all nodes related to this finding
    this.selectedNodeId = 'MULTI'; // Block hover
    const allNodeEls = document.querySelectorAll('.kg-node');
    const allLinkEls = document.querySelectorAll('.kg-link');

    allNodeEls.forEach(el => {
      const id = el.id.replace('node-', '');
      if (entities.includes(id) || id === 'THRAGG-CORE') {
        el.style.opacity = '1';
        el.style.filter = 'drop-shadow(0 0 12px var(--brand-primary))';
      } else {
        el.style.opacity = '0.15';
        el.style.filter = 'grayscale(100%)';
      }
    });

    allLinkEls.forEach(el => {
      el.style.opacity = '0.1';
    });
  },

  selectNode(nodeId) {
    this.selectedNodeId = nodeId;
    const allNodeEls = document.querySelectorAll('.kg-node');
    const allLinkEls = document.querySelectorAll('.kg-link');

    if (!nodeId) {
      // Clear selection
      allNodeEls.forEach(el => {
        el.classList.remove('selected-node', 'active', 'neighbor');
        el.style.opacity = '1';
        el.style.filter = 'none';
      });
      allLinkEls.forEach(el => { 
        el.style.opacity = '1'; 
        el.setAttribute('stroke', 'rgba(255,255,255,0.15)'); 
        el.setAttribute('marker-end', 'url(#kg-arrow)'); 
      });
      return;
    }

    const node = this.nodeMap[nodeId];
    if (node) {
      // Pan to node
      const viewport = document.getElementById('kg-viewport');
      if (viewport) {
        this.panX = viewport.clientWidth/2 - node.x * this.scale;
        this.panY = viewport.clientHeight/2 - node.y * this.scale;
        if (this.gTransform) {
          this.gTransform.style.transition = 'transform var(--transition-spring)';
          this._updateTransform();
          clearTimeout(this._transitionTimer);
          this._transitionTimer = setTimeout(() => { if (this.gTransform) this.gTransform.style.transition = 'none'; }, 500);
        }
      }
    }

    // Highlight
    const connectedNodeIds = new Set();
    connectedNodeIds.add(nodeId);
    this.links.forEach(l => {
      if (l.source === nodeId) connectedNodeIds.add(l.target);
      if (l.target === nodeId) connectedNodeIds.add(l.source);
    });

    allNodeEls.forEach(el => {
      const id = el.id.replace('node-', '');
      el.classList.remove('selected-node', 'active', 'neighbor');
      if (id === nodeId) {
        el.classList.add('selected-node', 'active');
        el.style.opacity = '1';
        // Raise to top so it renders above other nodes
        el.parentNode.appendChild(el);
      } else if (!connectedNodeIds.has(id) && id !== 'THRAGG-CORE') {
        el.style.opacity = '0.15';
        el.style.filter = 'grayscale(100%)';
      } else {
        el.classList.add('neighbor');
        el.style.opacity = '1';
        el.style.filter = 'none';
      }
    });

    allLinkEls.forEach(el => {
      if (el.id.includes(nodeId)) {
        el.style.opacity = '1';
        el.setAttribute('stroke', 'var(--brand-primary)');
        el.setAttribute('marker-end', 'url(#kg-arrow-highlight)');
        // Raise to top so edge glows above other edges
        el.parentNode.appendChild(el);
      } else {
        el.style.opacity = '0.1';
        el.setAttribute('stroke', 'rgba(255,255,255,0.15)');
        el.setAttribute('marker-end', 'url(#kg-arrow)');
      }
    });
  },

  /* ── REPLAY MODE ───────────────────────────────────────────────────── */

  _highlightReplayStep(sourceId, targetId) {
    if (!this.svgRoot) return;
    this.svgRoot.classList.add('kg-replay-mode');

    // Reset all nodes and links
    document.querySelectorAll('.kg-node').forEach(el => {
      el.classList.remove('highlight', 'dimmed', 'replay-active');
      el.classList.add('dimmed');
      el.style.opacity = '0.15';
    });
    document.querySelectorAll('.kg-link').forEach(el => {
      el.classList.remove('highlight', 'dimmed', 'replay-active');
      el.classList.add('dimmed');
      el.style.opacity = '0.05';
      el.setAttribute('stroke', 'rgba(255,255,255,0.15)');
      el.setAttribute('stroke-width', '1.5');
    });

    // Highlight active nodes and link
    const nodesToPan = [];

    const highlightNode = (id) => {
      const el = document.getElementById(`node-${id}`);
      if (el) {
        el.classList.remove('dimmed');
        el.classList.add('replay-active', 'highlight');
        el.style.opacity = '1';
        nodesToPan.push(this.nodeMap[id]);
      }
    };

    if (sourceId) highlightNode(sourceId);
    if (targetId) highlightNode(targetId);

    if (sourceId && targetId) {
      const linkId = `link-${sourceId}-${targetId}`;
      const linkIdReverse = `link-${targetId}-${sourceId}`;
      let linkEl = document.getElementById(linkId) || document.getElementById(linkIdReverse);

      if (linkEl) {
        linkEl.classList.remove('dimmed');
        linkEl.classList.add('replay-active', 'highlight');
        linkEl.style.opacity = '1';
        linkEl.setAttribute('stroke', 'var(--color-critical)');
        linkEl.setAttribute('stroke-width', '3');
        linkEl.setAttribute('marker-end', 'url(#kg-arrow-highlight)');
      }
    }

    // Auto-pan to active nodes if engine is playing
    if (nodesToPan.length > 0 && typeof THRAGG_ReplayEngine !== 'undefined' && THRAGG_ReplayEngine.state === 'PLAYING') {
      let sumX = 0, sumY = 0;
      nodesToPan.forEach(n => { sumX += n.x; sumY += n.y; });
      const cx = sumX / nodesToPan.length;
      const cy = sumY / nodesToPan.length;

      const viewport = document.getElementById('kg-viewport');
      if (viewport) {
        const vw = viewport.clientWidth;
        const vh = viewport.clientHeight;
        this.panX = (vw / 2) - (cx * this.scale);
        this.panY = (vh / 2) - (cy * this.scale);
        this._updateTransform();
      }
    }
  },

  highlightChain(chainData) {
    if (!chainData || !chainData.participating_entities) {
      this.selectNode(null);
      return;
    }
    const entities = new Set(chainData.participating_entities);
    
    const allNodeEls = document.querySelectorAll('.kg-node');
    allNodeEls.forEach(el => {
      const id = el.id.replace('node-', '');
      if (entities.has(id) || id === 'THRAGG-CORE') {
        el.style.opacity = '1';
        el.style.filter = 'drop-shadow(0 0 12px var(--color-critical))';
      } else {
        el.style.opacity = '0.15';
        el.style.filter = 'grayscale(100%)';
      }
    });
  },

  _hexToRgb(hex) {
    // Basic hex to rgb, handles #abc or #aabbcc
    if (!hex || hex.startsWith('url')) return '108, 92, 231';
    let c = hex.substring(1).split('');
    if(c.length === 3){ c= [c[0], c[0], c[1], c[1], c[2], c[2]]; }
    c = '0x' + c.join('');
    return `${(c>>16)&255}, ${(c>>8)&255}, ${c&255}`;
  },

  destroy() {
    clearTimeout(this._fitTimer);
    clearTimeout(this._transitionTimer);
    this._fitTimer = null;
    this._transitionTimer = null;
    if (this.physics) {
      this.physics.stop();
      this.physics = null;
    }
    if (this._resizeObserver) {
      this._resizeObserver.disconnect();
      this._resizeObserver = null;
    }
    if (this._onMouseMove) {
      window.removeEventListener('mousemove', this._onMouseMove);
      this._onMouseMove = null;
    }
    if (this._onMouseUp) {
      window.removeEventListener('mouseup', this._onMouseUp);
      this._onMouseUp = null;
    }
    if (this._boundSvgRoot) {
      if (this._onSvgMouseDown) this._boundSvgRoot.removeEventListener('mousedown', this._onSvgMouseDown);
      if (this._onSvgWheel) this._boundSvgRoot.removeEventListener('wheel', this._onSvgWheel);
      this._boundSvgRoot = null;
      this._onSvgMouseDown = null;
      this._onSvgWheel = null;
    }
    if (this._resetBtn && this._onResetClick) {
      this._resetBtn.removeEventListener('click', this._onResetClick);
      this._resetBtn = null;
      this._onResetClick = null;
    }
    if (this._fitBtn && this._onFitClick) {
      this._fitBtn.removeEventListener('click', this._onFitClick);
      this._fitBtn = null;
      this._onFitClick = null;
    }
    if (typeof THRAGG_EventBus !== 'undefined') {
      const offMethod = THRAGG_EventBus.off ? 'off' : (THRAGG_EventBus.removeListener ? 'removeListener' : null);
      if (offMethod) {
        if (this._onContextChanged) THRAGG_EventBus[offMethod]('CONTEXT_CHANGED', this._onContextChanged);
        if (this._onHoverPreview) THRAGG_EventBus[offMethod]('HOVER_PREVIEW', this._onHoverPreview);
        if (this._onChainSelected) THRAGG_EventBus[offMethod]('CHAIN_SELECTED', this._onChainSelected);
        if (this._onReplayStep) THRAGG_EventBus[offMethod]('REPLAY_STEP_CHANGED', this._onReplayStep);
        if (this._onReplayStopped) THRAGG_EventBus[offMethod]('REPLAY_STOPPED', this._onReplayStopped);
        if (this._onGlobalFilterChanged) THRAGG_EventBus[offMethod]('GLOBAL_FILTER_CHANGED', this._onGlobalFilterChanged);
      }
    }
    this._eventsBound = false;
    this.isDraggingCanvas = false;
    this.isDraggingNode = null;
  }
};
