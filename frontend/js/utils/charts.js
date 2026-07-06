/* ==========================================================================
   THRAGG — Chart Utilities
   ========================================================================== */

const THRAGG_Charts = {
  /* ── Create a donut chart on canvas ────────────────────────────────── */
  donut(canvas, segments, size = 120) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;
    const radius = size / 2 - 8;
    const innerRadius = radius * 0.6;
    const total = segments.reduce((sum, s) => sum + s.count, 0);
    if (total === 0) return;

    let startAngle = -Math.PI / 2;
    segments.forEach((seg) => {
      const sliceAngle = (seg.count / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
      ctx.arc(cx, cy, innerRadius, startAngle + sliceAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = seg.color;
      ctx.fill();

      // Label
      const midAngle = startAngle + sliceAngle / 2;
      const labelR = (radius + innerRadius) / 2;
      const lx = cx + Math.cos(midAngle) * labelR;
      const ly = cy + Math.sin(midAngle) * labelR;
      if (sliceAngle > 0.3) {
        ctx.fillStyle = 'rgba(255,255,255,0.9)';
        ctx.font = 'bold 10px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(seg.count, lx, ly);
      }

      startAngle += sliceAngle;
    });

    // Center text
    ctx.fillStyle = 'rgba(255,255,255,0.7)';
    ctx.font = 'bold 16px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total, cx, cy - 4);
    ctx.fillStyle = 'rgba(255,255,255,0.3)';
    ctx.font = '8px Inter, sans-serif';
    ctx.fillText('total', cx, cy + 10);
  },

  /* ── Create a mini sparkline on canvas ─────────────────────────────── */
  sparkline(canvas, values, color = '#6c5ce7', width = 120, height = 30) {
    if (!canvas || !values.length) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.scale(dpr, dpr);

    const padding = 2;
    const w = width - padding * 2;
    const h = height - padding * 2;
    const min = Math.min(...values);
    const max = Math.max(...values);
    const range = max - min || 1;

    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';

    values.forEach((v, i) => {
      const x = padding + (i / (values.length - 1)) * w;
      const y = padding + h - ((v - min) / range) * h;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Fill area
    const lastX = padding + w;
    const lastY = padding + h - ((values[values.length - 1] - min) / range) * h;
    ctx.lineTo(lastX, padding + h);
    ctx.lineTo(padding, padding + h);
    ctx.closePath();
    const gradient = ctx.createLinearGradient(0, padding, 0, padding + h);
    gradient.addColorStop(0, color + '40');
    gradient.addColorStop(1, color + '05');
    ctx.fillStyle = gradient;
    ctx.fill();
  },

  /* ── Severity colors ───────────────────────────────────────────────── */
  severityColor(level) {
    const colors = {
      CRITICAL: '#ef4444',
      HIGH: '#f97316',
      MEDIUM: '#eab308',
      LOW: '#22c55e',
      INFO: '#3b82f6',
      EXCELLENT: '#22c55e',
      GOOD: '#3b82f6',
      FAIR: '#eab308',
      POOR: '#f97316',
      CRITICAL_BUSINESS: '#ef4444'
    };
    return colors[level] || '#64748b';
  },

  /* ── Domain colors ─────────────────────────────────────────────────── */
  domainColor(domain) {
    const colors = {
      network: '#00d2ff',
      cloud: '#6c5ce7',
      identity: '#f97316',
      web: '#22c55e',
      logs: '#eab308'
    };
    return colors[domain.toLowerCase()] || '#64748b';
  },

  /* ── Format a number for display ───────────────────────────────────── */
  formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toString();
  },

  /* ── Format a timestamp ────────────────────────────────────────────── */
  formatTimestamp(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZoneName: 'short'
    });
  },

  /* ── Format relative time ──────────────────────────────────────────── */
  timeAgo(ts) {
    if (!ts) return '—';
    const now = new Date();
    const past = new Date(ts);
    const diff = Math.floor((now - past) / 1000);
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 2592000) return `${Math.floor(diff / 86400)}d ago`;
    return this.formatTimestamp(ts);
  }
};
