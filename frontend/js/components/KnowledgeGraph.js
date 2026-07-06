/* ==========================================================================
   THRAGG — Knowledge Graph Component (Placeholder)
   ========================================================================== */

const THRAGG_KnowledgeGraph = {
  render(container) {
    if (!container) return;

    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0">Knowledge Graph</span>
          <span class="badge badge-info">
            ${THRAGG_DATA.framework_snapshot.resolved_entity_count} entities · ${THRAGG_DATA.framework_snapshot.relationship_count} relationships
          </span>
        </div>
        <div class="card-body" style="padding: 0;">
          <div class="knowledge-graph-container" id="kg-container">
            <svg class="kg-placeholder-svg" viewBox="0 0 800 500" xmlns="http://www.w3.org/2000/svg">
              <!-- Background grid -->
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" stroke-width="1"/>
                </pattern>
                <marker id="arrowhead" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
                  <polygon points="0 0, 8 4, 0 8" fill="rgba(255,255,255,0.15)"/>
                </marker>
                <linearGradient id="nodeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stop-color="#6c5ce7"/>
                  <stop offset="100%" stop-color="#a29bfe"/>
                </linearGradient>
              </defs>

              <!-- Grid -->
              <rect width="800" height="500" fill="url(#grid)"/>

              <!-- Connection lines -->
              <g stroke="rgba(255,255,255,0.08)" stroke-width="1.5" marker-end="url(#arrowhead)">
                <line x1="400" y1="120" x2="250" y2="250"/>
                <line x1="400" y1="120" x2="550" y2="250"/>
                <line x1="250" y1="250" x2="180" y2="380"/>
                <line x1="250" y1="250" x2="320" y2="380"/>
                <line x1="550" y1="250" x2="480" y2="380"/>
                <line x1="550" y1="250" x2="620" y2="380"/>
                <line x1="400" y1="120" x2="400" y2="30"/>
              </g>

              <!-- Outer glow rings -->
              <circle cx="400" cy="120" r="35" fill="none" stroke="rgba(108,92,231,0.15)" stroke-width="1">
                <animate attributeName="r" values="35;45;35" dur="3s" repeatCount="indefinite"/>
                <animate attributeName="opacity" values="0.5;0;0.5" dur="3s" repeatCount="indefinite"/>
              </circle>

              <!-- Core node -->
              <circle cx="400" cy="120" r="22" fill="url(#nodeGrad)" opacity="0.9"/>
              <text x="400" y="118" text-anchor="middle" fill="white" font-size="8" font-weight="bold" font-family="Inter, sans-serif">THRAGG</text>
              <text x="400" y="128" text-anchor="middle" fill="rgba(255,255,255,0.5)" font-size="6" font-family="Inter, sans-serif">CORE</text>

              <!-- Entity nodes -->
              <g>
                <circle cx="250" cy="250" r="16" fill="rgba(0,210,255,0.15)" stroke="#00d2ff" stroke-width="1.5"/>
                <text x="250" y="254" text-anchor="middle" fill="#00d2ff" font-size="7" font-weight="bold" font-family="Inter, sans-serif">HOST</text>

                <circle cx="550" cy="250" r="16" fill="rgba(108,92,231,0.15)" stroke="#6c5ce7" stroke-width="1.5"/>
                <text x="550" y="254" text-anchor="middle" fill="#a29bfe" font-size="6" font-weight="bold" font-family="Inter, sans-serif">CLOUD</text>

                <circle cx="180" cy="380" r="14" fill="rgba(249,115,22,0.15)" stroke="#f97316" stroke-width="1.5"/>
                <text x="180" y="384" text-anchor="middle" fill="#f97316" font-size="6" font-weight="bold" font-family="Inter, sans-serif">USER</text>

                <circle cx="320" cy="380" r="14" fill="rgba(234,179,8,0.15)" stroke="#eab308" stroke-width="1.5"/>
                <text x="320" y="384" text-anchor="middle" fill="#eab308" font-size="6" font-weight="bold" font-family="Inter, sans-serif">SVC</text>

                <circle cx="480" cy="380" r="14" fill="rgba(34,197,94,0.15)" stroke="#22c55e" stroke-width="1.5"/>
                <text x="480" y="384" text-anchor="middle" fill="#22c55e" font-size="6" font-weight="bold" font-family="Inter, sans-serif">WEB</text>

                <circle cx="620" cy="380" r="14" fill="rgba(59,130,246,0.15)" stroke="#3b82f6" stroke-width="1.5"/>
                <text x="620" y="384" text-anchor="middle" fill="#3b82f6" font-size="6" font-weight="bold" font-family="Inter, sans-serif">ID</text>
              </g>

              <!-- Top level -->
              <circle cx="400" cy="30" r="10" fill="rgba(239,68,68,0.15)" stroke="#ef4444" stroke-width="1"/>
              <text x="400" y="33" text-anchor="middle" fill="#ef4444" font-size="5" font-weight="bold" font-family="Inter, sans-serif">EXT</text>

              <!-- Labels -->
              <g fill="rgba(255,255,255,0.15)" font-size="5" font-family="Inter, sans-serif">
                <text x="325" y="185" transform="rotate(-25, 325, 185)">EXPOSES</text>
                <text x="475" y="185" transform="rotate(25, 475, 185)">CONTAINS</text>
                <text x="215" y="315">AUTHENTICATED_TO</text>
                <text x="285" y="315">MEMBER_OF</text>
                <text x="515" y="315">RELATED_TO</text>
                <text x="575" y="315">USES</text>
              </g>

              <!-- Animated flow dots on connections -->
              <circle r="2.5" fill="rgba(108,92,231,0.6)">
                <animateMotion dur="4s" repeatCount="indefinite" path="M400,120 L250,250"/>
              </circle>
              <circle r="2.5" fill="rgba(0,210,255,0.6)">
                <animateMotion dur="5s" repeatCount="indefinite" path="M250,250 L180,380"/>
              </circle>
              <circle r="2.5" fill="rgba(108,92,231,0.6)">
                <animateMotion dur="3.5s" repeatCount="indefinite" path="M400,120 L550,250"/>
              </circle>
            </svg>
          </div>
        </div>
      </div>
    `;
  }
};
