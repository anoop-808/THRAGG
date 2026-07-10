/* ==========================================================================
   THRAGG — Lightweight Graph Physics Engine
   Deterministic, auto-stopping force simulation for SVG nodes.
   ========================================================================== */

class THRAGG_GraphPhysics {
  constructor(nodes, links, width, height, onTick, onEnd) {
    this.nodes = nodes; // { id, x, y, vx, vy, radius }
    this.links = links; // { source, target }
    this.width = width;
    this.height = height;
    this.onTick = onTick;
    this.onEnd = onEnd;
    this.nodeMap = new Map(this.nodes.map(node => [node.id, node]));

    // Simulation params
    this.alpha = 1.0;
    this.alphaMin = 0.002;
    this.alphaDecay = 0.022;
    this.velocityDecay = 0.5; // Friction
    this.alphaStableMin = 0.03;
    this.movementMin = 0.02;
    
    // Force params
    this.chargeStrength = -2200; // Strong repulsion — pushes nodes far apart
    this.linkDistance = 240;    // Long preferred link length — wide graph footprint
    this.linkStrength = 0.08;
    this.centerStrength = 0.006; // Very weak gravity — let repulsion dominate

    this.rafId = null;
    this.isRunning = false;
    this.hasEnded = false;
    this.averageMovement = Infinity;
  }

  // Calculate distance between two points
  _distance(n1, n2) {
    const dx = n2.x - n1.x;
    const dy = n2.y - n1.y;
    return Math.sqrt(dx * dx + dy * dy) || 0.01;
  }

  // Run one step of the simulation
  tick() {
    if (!this.isRunning) return;

    if (this.alpha < this.alphaMin) {
      this._finish();
      return;
    }

    const n = this.nodes.length;

    // 1. Repulsive forces (Coulomb) - O(n^2) but n is small (<1000)
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const n1 = this.nodes[i];
        const n2 = this.nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        
        // F = k * (q1*q2) / d^2
        const force = (this.alpha * this.chargeStrength) / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;

        n1.vx -= fx;
        n1.vy -= fy;
        n2.vx += fx;
        n2.vy += fy;
      }
    }

    // 2. Attractive forces (Links)
    for (let i = 0; i < this.links.length; i++) {
      const link = this.links[i];
      const source = this.nodeMap.get(link.source);
      const target = this.nodeMap.get(link.target);
      if (!source || !target) continue;

      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      
      const force = this.alpha * this.linkStrength * (dist - this.linkDistance);
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      source.vx += fx;
      source.vy += fy;
      target.vx -= fx;
      target.vy -= fy;
    }

    // 3. Centering force
    const cx = this.width / 2;
    const cy = this.height / 2;
    for (let i = 0; i < n; i++) {
      const node = this.nodes[i];
      node.vx += (cx - node.x) * this.alpha * this.centerStrength;
      node.vy += (cy - node.y) * this.alpha * this.centerStrength;
    }

    // 4. Position update & velocity decay
    let totalMovement = 0;
    for (let i = 0; i < n; i++) {
      const node = this.nodes[i];
      if (!node.fixed) {
        totalMovement += Math.sqrt(node.vx * node.vx + node.vy * node.vy);
        node.x += node.vx;
        node.y += node.vy;
      }
      node.vx *= this.velocityDecay;
      node.vy *= this.velocityDecay;
    }
    
    const currentMovement = n ? totalMovement / n : 0;
    if (this.averageMovement === Infinity) {
      this.averageMovement = currentMovement;
    } else {
      this.averageMovement = this.averageMovement * 0.8 + currentMovement * 0.2;
    }

    this.alpha *= (1 - this.alphaDecay);

    if (this.onTick) this.onTick(this.nodes, this.links);

    if (this.alpha < this.alphaMin || (this.alpha < this.alphaStableMin && this.averageMovement < this.movementMin)) {
      this._finish();
      return;
    }

    this.rafId = requestAnimationFrame(() => this.tick());
  }

  start() {
    if (this.isRunning) return;
    
    // Check reduced motion
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reducedMotion) {
      // Simulate instantly without rendering steps
      this.alpha = 1.0;
      while (this.alpha >= this.alphaMin) {
        this.tickWithoutRaf();
      }
      if (this.onTick) this.onTick(this.nodes, this.links);
      if (this.onEnd) this.onEnd();
      return;
    }

    this.isRunning = true;
    this.hasEnded = false;
    this.averageMovement = Infinity;
    this.alpha = 1.0;
    this.tick();
  }
  
  tickWithoutRaf() {
    // Simplified tick without raf for fast forward (reduced motion)
    const n = this.nodes.length;
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const n1 = this.nodes[i];
        const n2 = this.nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const force = (this.alpha * this.chargeStrength) / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        n1.vx -= fx;
        n1.vy -= fy;
        n2.vx += fx;
        n2.vy += fy;
      }
    }
    for (let i = 0; i < this.links.length; i++) {
      const link = this.links[i];
      const source = this.nodeMap.get(link.source);
      const target = this.nodeMap.get(link.target);
      if (!source || !target) continue;
      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const force = this.alpha * this.linkStrength * (dist - this.linkDistance);
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      source.vx += fx;
      source.vy += fy;
      target.vx -= fx;
      target.vy -= fy;
    }
    const cx = this.width / 2;
    const cy = this.height / 2;
    for (let i = 0; i < n; i++) {
      const node = this.nodes[i];
      node.vx += (cx - node.x) * this.alpha * this.centerStrength;
      node.vy += (cy - node.y) * this.alpha * this.centerStrength;
      if (!node.fixed) {
        node.x += node.vx;
        node.y += node.vy;
      }
      node.vx *= this.velocityDecay;
      node.vy *= this.velocityDecay;
    }
    this.alpha *= (1 - this.alphaDecay);
  }

  stop() {
    this.isRunning = false;
    if (this.rafId) cancelAnimationFrame(this.rafId);
    this.rafId = null;
  }

  _finish() {
    if (this.hasEnded) return;
    this.hasEnded = true;
    this.stop();
    if (this.onEnd) this.onEnd();
  }

  reheat(targetAlpha = 0.5) {
    this.alpha = targetAlpha;
    if (!this.isRunning) {
      this.start();
    }
  }
}
