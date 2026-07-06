/* ==========================================================================
   THRAGG — Intelligence Core Visualization
   ==========================================================================
   Renders an animated centerpiece showing intelligence flowing from 5
   security domains into the THRAGG core using Canvas.
   ========================================================================== */

const THRAGG_IntelligenceCore = {
  canvas: null,
  ctx: null,
  animFrame: null,
  particles: [],
  connections: [],
  domains: [],
  corePulse: 0,
  time: 0,

  /* ── Domain configuration ──────────────────────────────────────────── */
  DOMAIN_CONFIG: [
    { id: 'network',  label: 'NETWORK',  color: '#00d2ff', x: 0, y: 0 },
    { id: 'cloud',    label: 'CLOUD',    color: '#6c5ce7', x: 0, y: 0 },
    { id: 'identity', label: 'IDENTITY', color: '#f97316', x: 0, y: 0 },
    { id: 'web',      label: 'WEB',      color: '#22c55e', x: 0, y: 0 },
    { id: 'logs',     label: 'LOGS',     color: '#eab308', x: 0, y: 0 }
  ],

  /* ── Initialize the visualization ──────────────────────────────────── */
  init(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Destroy any existing canvas and animation loop before reinitializing
    this.destroy();
    container.innerHTML = '';

    this.canvas = document.createElement('canvas');
    container.appendChild(this.canvas);
    this.ctx = this.canvas.getContext('2d');

    this.resize();
    window.addEventListener('resize', () => this.resize());

    this._initDomains();
    this._initParticles();
    this._animate();
  },

  /* ── Handle resize ─────────────────────────────────────────────────── */
  resize() {
    const container = this.canvas.parentElement;
    const rect = container.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = rect.width * dpr;
    this.canvas.height = rect.height * dpr;
    this.canvas.style.width = `${rect.width}px`;
    this.canvas.style.height = `${rect.height}px`;
    if (this.ctx) {
      this.ctx.scale(dpr, dpr);
      this.width = rect.width;
      this.height = rect.height;
      this._initDomains();
    }
  },

  /* ── Calculate domain positions in a pentagon around the core ──────── */
  _initDomains() {
    const cx = this.width / 2;
    const cy = this.height / 2;
    const radius = Math.min(this.width, this.height) * 0.32;
    const count = this.DOMAIN_CONFIG.length;

    this.DOMAIN_CONFIG.forEach((domain, i) => {
      const angle = (i / count) * Math.PI * 2 - Math.PI / 2;
      domain.x = cx + Math.cos(angle) * radius;
      domain.y = cy + Math.sin(angle) * radius;
    });

    this.coreX = cx;
    this.coreY = cy;
    this.coreRadius = Math.min(this.width, this.height) * 0.08;
  },

  /* ── Create data-flow particles ────────────────────────────────────── */
  _initParticles() {
    this.particles = [];
    const cx = this.coreX;
    const cy = this.coreY;

    this.DOMAIN_CONFIG.forEach((domain) => {
      // Outbound flow from core to domain
      for (let i = 0; i < 3; i++) {
        this.particles.push({
          x: cx,
          y: cy,
          targetX: domain.x,
          targetY: domain.y,
          progress: Math.random(),
          speed: 0.003 + Math.random() * 0.004,
          color: domain.color,
          size: 1.5 + Math.random() * 1.5,
          opacity: 0.6 + Math.random() * 0.4,
          phase: Math.random() * Math.PI * 2,
          wobble: 3 + Math.random() * 4,
          from: 'core'
        });
      }

      // Inbound flow from domain to core
      for (let i = 0; i < 4; i++) {
        this.particles.push({
          x: domain.x,
          y: domain.y,
          targetX: cx,
          targetY: cy,
          progress: Math.random(),
          speed: 0.002 + Math.random() * 0.003,
          color: domain.color,
          size: 1 + Math.random() * 2,
          opacity: 0.4 + Math.random() * 0.4,
          phase: Math.random() * Math.PI * 2,
          wobble: 2 + Math.random() * 3,
          from: 'domain'
        });
      }
    });
  },

  /* ── Main animation loop ───────────────────────────────────────────── */
  _animate() {
    this.time += 0.01;
    this.corePulse = 0.6 + Math.sin(this.time * 1.5) * 0.4;

    this._draw();
    this._updateParticles();
    this.animFrame = requestAnimationFrame(() => this._animate());
  },

  /* ── Render the frame ──────────────────────────────────────────────── */
  _draw() {
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;

    // Clear
    ctx.clearRect(0, 0, w, h);

    // ── Background glow ────────────────────────────────────────────────
    const bgGrad = ctx.createRadialGradient(
      this.coreX, this.coreY, 0,
      this.coreX, this.coreY, w * 0.5
    );
    bgGrad.addColorStop(0, 'rgba(108, 92, 231, 0.06)');
    bgGrad.addColorStop(0.5, 'rgba(108, 92, 231, 0.02)');
    bgGrad.addColorStop(1, 'rgba(10, 15, 30, 0)');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, w, h);

    // ── Orbital rings ──────────────────────────────────────────────────
    const ringRadius = Math.min(w, h) * 0.2;
    for (let r = 0; r < 3; r++) {
      ctx.beginPath();
      ctx.arc(this.coreX, this.coreY, ringRadius + r * 18, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(108, 92, 231, ${0.04 + r * 0.02})`;
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // ── Connection lines from domains to core ──────────────────────────
    this.DOMAIN_CONFIG.forEach((domain) => {
      ctx.beginPath();
      ctx.moveTo(domain.x, domain.y);
      ctx.lineTo(this.coreX, this.coreY);
      ctx.strokeStyle = `rgba(255, 255, 255, 0.04)`;
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 8]);
      ctx.stroke();
      ctx.setLineDash([]);

      // Glow dot on connection
      const midX = (domain.x + this.coreX) / 2;
      const midY = (domain.y + this.coreY) / 2;
      ctx.beginPath();
      ctx.arc(midX, midY, 2, 0, Math.PI * 2);
      ctx.fillStyle = domain.color + '30';
      ctx.fill();
    });

    // ── Domain nodes ───────────────────────────────────────────────────
    this.DOMAIN_CONFIG.forEach((domain) => {
      // Outer glow
      const glowGrad = ctx.createRadialGradient(
        domain.x, domain.y, 0,
        domain.x, domain.y, 24
      );
      glowGrad.addColorStop(0, domain.color + '30');
      glowGrad.addColorStop(1, domain.color + '00');
      ctx.fillStyle = glowGrad;
      ctx.fillRect(domain.x - 24, domain.y - 24, 48, 48);

      // Node circle
      ctx.beginPath();
      ctx.arc(domain.x, domain.y, 8, 0, Math.PI * 2);
      ctx.fillStyle = domain.color;
      ctx.fill();

      // Inner highlight
      ctx.beginPath();
      ctx.arc(domain.x - 2, domain.y - 2, 3, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255,255,255,0.3)';
      ctx.fill();

      // Label
      ctx.fillStyle = 'rgba(255,255,255,0.5)';
      ctx.font = '9px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(domain.label, domain.x, domain.y + 14);
    });

    // ── Particles ──────────────────────────────────────────────────────
    this.particles.forEach((p) => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.globalAlpha = p.opacity * (1 - Math.abs(p.progress - 0.5) * 0.6);
      ctx.fill();
      ctx.globalAlpha = 1;

      // Particle glow
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size * 3, 0, Math.PI * 2);
      ctx.fillStyle = p.color + '15';
      ctx.fill();
    });

    // ── Core ───────────────────────────────────────────────────────────
    // Outer pulse
    const pulseRadius = this.coreRadius * (1 + (1 - this.corePulse) * 0.3);
    ctx.beginPath();
    ctx.arc(this.coreX, this.coreY, pulseRadius, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(108, 92, 231, ${(1 - this.corePulse) * 0.08})`;
    ctx.fill();

    // Core glow
    const coreGlow = ctx.createRadialGradient(
      this.coreX, this.coreY, 0,
      this.coreX, this.coreY, this.coreRadius * 2.5
    );
    coreGlow.addColorStop(0, `rgba(108, 92, 231, ${this.corePulse * 0.3})`);
    coreGlow.addColorStop(0.5, `rgba(162, 155, 254, ${this.corePulse * 0.1})`);
    coreGlow.addColorStop(1, 'rgba(108, 92, 231, 0)');
    ctx.fillStyle = coreGlow;
    ctx.fillRect(
      this.coreX - this.coreRadius * 2.5,
      this.coreY - this.coreRadius * 2.5,
      this.coreRadius * 5,
      this.coreRadius * 5
    );

    // Core body
    const coreGrad = ctx.createRadialGradient(
      this.coreX - this.coreRadius * 0.3,
      this.coreY - this.coreRadius * 0.3,
      0,
      this.coreX, this.coreY,
      this.coreRadius
    );
    coreGrad.addColorStop(0, 'rgba(200, 190, 255, 0.9)');
    coreGrad.addColorStop(0.4, 'rgba(108, 92, 231, 0.8)');
    coreGrad.addColorStop(1, 'rgba(70, 50, 180, 0.6)');
    ctx.beginPath();
    ctx.arc(this.coreX, this.coreY, this.coreRadius, 0, Math.PI * 2);
    ctx.fillStyle = coreGrad;
    ctx.fill();

    // Core border
    ctx.beginPath();
    ctx.arc(this.coreX, this.coreY, this.coreRadius, 0, Math.PI * 2);
    ctx.strokeStyle = `rgba(162, 155, 254, ${this.corePulse * 0.5})`;
    ctx.lineWidth = 2;
    ctx.stroke();

    // Core highlight
    ctx.beginPath();
    ctx.arc(
      this.coreX - this.coreRadius * 0.25,
      this.coreY - this.coreRadius * 0.35,
      this.coreRadius * 0.35,
      0,
      Math.PI * 2
    );
    ctx.fillStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.fill();

    // Core center dot
    ctx.beginPath();
    ctx.arc(this.coreX, this.coreY, 3, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
    ctx.fill();

    // ── "THRAGG" label at core ─────────────────────────────────────────
    ctx.fillStyle = `rgba(255, 255, 255, ${0.3 + this.corePulse * 0.3})`;
    ctx.font = 'bold 11px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'bottom';
    ctx.fillText('THRAGG', this.coreX, this.coreY - this.coreRadius - 8);

    ctx.fillStyle = 'rgba(255, 255, 255, 0.15)';
    ctx.font = '7px Inter, sans-serif';
    ctx.textBaseline = 'top';
    ctx.fillText('INTELLIGENCE CORE', this.coreX, this.coreY + this.coreRadius + 6);
  },

  /* ── Update particle positions ─────────────────────────────────────── */
  _updateParticles() {
    this.particles.forEach((p) => {
      p.progress += p.speed;

      if (p.progress > 1) {
        p.progress = 0;
        // Reset to origin
        if (p.from === 'core') {
          p.x = this.coreX;
          p.y = this.coreY;
        } else {
          const domain = this.DOMAIN_CONFIG.find(d => d.color === p.color);
          if (domain) {
            p.x = domain.x;
            p.y = domain.y;
          }
        }
      }

      // Interpolate position with wobble
      const t = p.progress;
      const wobbleOffset = Math.sin(t * Math.PI * 4 + p.phase) * p.wobble * (1 - Math.abs(t - 0.5) * 2);

      if (p.from === 'core') {
        p.x = this.coreX + (p.targetX - this.coreX) * t + wobbleOffset * 0.3;
        p.y = this.coreY + (p.targetY - this.coreY) * t + wobbleOffset * 0.5;
      } else {
        p.x = p.targetX + (this.coreX - p.targetX) * t + wobbleOffset * 0.3;
        p.y = p.targetY + (this.coreY - p.targetY) * t + wobbleOffset * 0.5;
      }
    });
  },

  /* ── Clean up ──────────────────────────────────────────────────────── */
  destroy() {
    if (this.animFrame) {
      cancelAnimationFrame(this.animFrame);
      this.animFrame = null;
    }
    window.removeEventListener('resize', () => this.resize());
  }
};
