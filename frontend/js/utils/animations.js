/* ==========================================================================
   THRAGG — Animation Utilities
   ========================================================================== */

const THRAGG_Animations = {
  /* ── Animate element opacity and transform ─────────────────────────── */
  fadeIn(element, delay = 0, duration = 400) {
    if (!element) return;
    element.style.opacity = '0';
    element.style.transform = 'translateY(12px)';
    element.style.transition = `all ${duration}ms cubic-bezier(0.4, 0, 0.2, 1) ${delay}ms`;
    requestAnimationFrame(() => {
      element.style.opacity = '1';
      element.style.transform = 'translateY(0)';
    });
  },

  /* ── Stagger children ──────────────────────────────────────────────── */
  stagger(container, delay = 40, duration = 400) {
    if (!container) return;
    const children = container.children;
    Array.from(children).forEach((child, i) => {
      child.style.opacity = '0';
      child.style.transform = 'translateY(12px)';
      child.style.transition = `all ${duration}ms cubic-bezier(0.4, 0, 0.2, 1) ${i * delay}ms`;
      requestAnimationFrame(() => {
        child.style.opacity = '1';
        child.style.transform = 'translateY(0)';
      });
    });
  },

  /* ── Animated counter ──────────────────────────────────────────────── */
  countUp(element, target, duration = 1000, prefix = '', suffix = '') {
    if (!element) return;
    const start = performance.now();
    const animate = (now) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(eased * target);
      element.textContent = `${prefix}${current.toLocaleString()}${suffix}`;
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    requestAnimationFrame(animate);
  },

  /* ── Animate progress bars ─────────────────────────────────────────── */
  animateProgressBar(element, targetPercent, duration = 1200) {
    if (!element) return;
    const start = performance.now();
    const animate = (now) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = eased * targetPercent;
      element.style.width = `${current}%`;
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    requestAnimationFrame(animate);
  },

  /* ── Typewriter effect ─────────────────────────────────────────────── */
  typewriter(element, text, speed = 30, delay = 0) {
    if (!element) return;
    let index = 0;
    setTimeout(() => {
      const interval = setInterval(() => {
        if (index < text.length) {
          element.textContent += text.charAt(index);
          index++;
        } else {
          clearInterval(interval);
        }
      }, speed);
    }, delay);
  }
};
