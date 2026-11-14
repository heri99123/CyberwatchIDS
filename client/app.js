// ============================================================================
// CyberWatch IDS — Frontend Application
// ============================================================================

const API = '/api';

let ws = null;
let reconnectTimer = null;
let lastStats = null;
let timelineRaf = null;

// ============================================================================
// Tab navigation
// ============================================================================

const navButtons = document.querySelectorAll('.nav-btn');

navButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    navButtons.forEach(b => {
      b.classList.remove('active');
      b.removeAttribute('aria-current');
    });
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

    btn.classList.add('active');
    btn.setAttribute('aria-current', 'page');

    const tabId = btn.dataset.tab;
    const section = document.getElementById('tab-' + tabId);
    if (section) section.classList.add('active');

    loadTabData(tabId);
  });
});

function loadTabData(tab) {
  switch (tab) {
    case 'dashboard': loadDashboard(); break;
    case 'cve': loadCVEs(); break;
    case 'events': loadEvents(); break;
    case 'alerts': loadAlerts(); break;
    case 'rules': loadRules(); break;
    case 'iprep': loadIPReputation(); break;
  }
}

// ============================================================================
// WebSocket
// ============================================================================

function connectWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = protocol + '//' + window.location.host + '/ws';

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    setConnectionState(true);
    ws.send(JSON.stringify({ type: 'subscribe', channels: ['events', 'alerts', 'stats'] }));
  };

  ws.onclose = () => {
    setConnectionState(false);
    // Clear any pending reconnect so we never stack timers.
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connectWebSocket, 3000);
  };

  ws.onerror = () => {
    // onclose fires right after; state is handled there.
  };

  ws.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (e) {
      return;
    }
    if (msg.type === 'events') addLiveFeedItem(msg.data);
    else if (msg.type === 'stats') updateStats(msg.data);
  };
}

function setConnectionState(isLive) {
  const label = document.getElementById('connection-status');
  const dot = document.querySelector('.status-dot');
  if (!label || !dot) return;
  label.textContent = isLive ? 'Connected' : 'Reconnecting…';
  dot.classList.toggle('live', isLive);
}

// ============================================================================
// Dashboard
// ============================================================================

async function loadDashboard() {
  const stats = await fetchJSON(API + '/stats');
  if (stats) updateStats(stats);
}

// The live feed is WebSocket-driven, so a freshly loaded page would sit empty
// until the next event arrives even though history exists. Backfill it once.
async function seedLiveFeed() {
  const feed = document.getElementById('live-feed');
  if (!feed || feed.querySelector('.feed-item')) return;

  const events = await fetchJSON(API + '/events?limit=20');
  if (!events || events.length === 0) return;

  // API returns newest-first; insert oldest-first so the newest ends up on top.
  [...events].reverse().forEach(ev => addLiveFeedItem(ev));
}

function updateStats(stats) {
  if (!stats) return;
  lastStats = stats;

  setText('stat-total-events', formatNum(stats.totalEvents));
  setText('stat-critical', formatNum(stats.criticalEvents));
  setText('stat-high', formatNum(stats.highEvents));
  setText('stat-blocked', formatNum(stats.blockedEvents));
  setText('stat-attackers', formatNum(stats.uniqueAttackers));
  setText('stat-alerts', formatNum(stats.activeAlerts));

  renderAttackTypes(stats.topAttackTypes);
  renderTopAttackers(stats.topAttackers);
  renderCVEMatches(stats.cveMatches);
  renderTimeline(stats.recentEvents);

  const stamp = document.getElementById('last-updated');
  if (stamp) stamp.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
}

function renderAttackTypes(types) {
  const host = document.getElementById('attack-types-chart');
  if (!host) return;

  if (!types || types.length === 0) {
    host.innerHTML = '<div class="empty-state">No attack data yet</div>';
    setText('attack-types-total', '');
    return;
  }

  const max = Math.max(...types.map(t => t.count), 1);
  const total = types.reduce((sum, t) => sum + t.count, 0);
  setText('attack-types-total', formatNum(total) + ' events');

  host.innerHTML = types.map(t => {
    const name = t.attack_type || t.event_type || 'Unknown';
    const pct = Math.max(2, Math.round((t.count / max) * 100));
    const sev = getAttackSeverity(name);
    return '<div class="bar-item">' +
      '<span class="bar-label" title="' + escapeHtml(name) + '">' + escapeHtml(name) + '</span>' +
      '<span class="bar-count">' + formatNum(t.count) + '</span>' +
      '<div class="bar-track"><div class="bar-fill ' + sev + '" style="width:' + pct + '%"></div></div>' +
    '</div>';
  }).join('');
}

function renderTopAttackers(attackers) {
  const host = document.getElementById('top-attackers');
  if (!host) return;

  if (!attackers || attackers.length === 0) {
    host.innerHTML = '<div class="empty-state">No attacker data</div>';
    return;
  }

  host.innerHTML = attackers.map(a => {
    const sev = a.max_severity || 'LOW';
    return '<div class="list-item">' +
      '<div class="list-item-left">' +
        '<span class="severity-badge ' + escapeHtml(sev) + '">' + escapeHtml(sev) + '</span>' +
        '<span>' + escapeHtml(a.source_ip) + '</span>' +
      '</div>' +
      '<span class="list-item-count">' + formatNum(a.count) + '</span>' +
    '</div>';
  }).join('');
}

function renderCVEMatches(matches) {
  const host = document.getElementById('cve-matches');
  if (!host) return;

  if (!matches || matches.length === 0) {
    host.innerHTML = '<div class="empty-state">No CVE-matched attacks yet</div>';
    return;
  }

  host.innerHTML = matches.map(c => {
    return '<div class="list-item">' +
      '<div class="list-item-left">' +
        '<span class="feed-cve" data-cve="' + escapeHtml(c.matched_cve) + '">' + escapeHtml(c.matched_cve) + '</span>' +
      '</div>' +
      '<span class="list-item-count">' + formatNum(c.count) + '</span>' +
    '</div>';
  }).join('');
}

// ---------------------------------------------------------------------------
// Timeline (24 hourly buckets, responsive, HiDPI aware)
// ---------------------------------------------------------------------------

function buildHourSeries(recentEvents) {
  // The API returns { hour: 'YYYY-MM-DD HH:00:00', count } in UTC, newest first,
  // and omits hours with no traffic. Rebuild a dense 24-bucket series.
  const counts = new Map();
  (recentEvents || []).forEach(e => {
    if (!e || !e.hour) return;
    // SQLite returns "YYYY-MM-DD HH:00:00"; normalise the separator so the key
    // matches the ISO-style key produced below ("YYYY-MM-DDTHH").
    const key = String(e.hour).replace(' ', 'T').slice(0, 13);
    counts.set(key, Number(e.count) || 0);
  });

  const now = new Date();
  now.setMinutes(0, 0, 0);

  const series = [];
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600 * 1000);
    // Match the SQLite strftime output format: YYYY-MM-DDTHH (UTC)
    const key = d.toISOString().slice(0, 13);
    series.push({ date: d, count: counts.get(key) || 0 });
  }
  return series;
}

function renderTimeline(recentEvents) {
  const canvas = document.getElementById('timeline-chart');
  if (!canvas) return;

  const series = buildHourSeries(recentEvents);
  const wrap = canvas.parentElement;
  const cssW = Math.max(240, wrap.clientWidth);
  const cssH = Math.max(140, wrap.clientHeight);
  const dpr = window.devicePixelRatio || 1;

  canvas.width = Math.round(cssW * dpr);
  canvas.height = Math.round(cssH * dpr);

  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  const styles = getComputedStyle(document.documentElement);
  const colGrid = styles.getPropertyValue('--border').trim() || '#263044';
  const colAxis = styles.getPropertyValue('--text-muted').trim() || '#64708a';
  const colAccent = styles.getPropertyValue('--accent').trim() || '#22d3ee';
  const colAccentDim = styles.getPropertyValue('--accent-dim').trim() || '#0e7490';

  const padL = 34;
  const padR = 6;
  const padT = 12;
  const padB = 20;
  const plotW = cssW - padL - padR;
  const plotH = cssH - padT - padB;

  const maxCount = Math.max(...series.map(s => s.count), 1);
  // Round the axis up to a "nice" number so gridline labels are readable.
  const step = niceStep(maxCount);
  const axisMax = Math.ceil(maxCount / step) * step;

  ctx.font = '10px ' + (styles.getPropertyValue('--font-mono').trim() || 'monospace');
  ctx.textBaseline = 'middle';

  // Horizontal gridlines + y labels
  const lines = Math.round(axisMax / step);
  for (let i = 0; i <= lines; i++) {
    const value = step * i;
    const y = padT + plotH - (value / axisMax) * plotH;

    ctx.strokeStyle = colGrid;
    ctx.globalAlpha = i === 0 ? 0.9 : 0.45;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padL, Math.round(y) + 0.5);
    ctx.lineTo(padL + plotW, Math.round(y) + 0.5);
    ctx.stroke();
    ctx.globalAlpha = 1;

    ctx.fillStyle = colAxis;
    ctx.textAlign = 'right';
    ctx.fillText(compactNum(value), padL - 8, y);
  }

  // Bars
  const slot = plotW / series.length;
  const barW = Math.max(3, slot - 3);

  const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
  grad.addColorStop(0, colAccent);
  grad.addColorStop(1, colAccentDim);

  series.forEach((point, i) => {
    const x = padL + i * slot + (slot - barW) / 2;
    const h = point.count === 0 ? 0 : Math.max(2, (point.count / axisMax) * plotH);
    const y = padT + plotH - h;

    if (h === 0) {
      // Show a faint baseline tick so empty hours remain visible.
      ctx.fillStyle = colGrid;
      ctx.fillRect(x, padT + plotH - 1.5, barW, 1.5);
      return;
    }

    ctx.fillStyle = grad;
    roundRect(ctx, x, y, barW, h, Math.min(3, barW / 2));
    ctx.fill();
  });

  // X labels every 6 hours
  ctx.fillStyle = colAxis;
  ctx.textAlign = 'center';
  series.forEach((point, i) => {
    if (i % 6 !== 0 && i !== series.length - 1) return;
    const x = padL + i * slot + slot / 2;
    ctx.fillText(hourLabel(point.date), x, padT + plotH + 11);
  });
}

function roundRect(ctx, x, y, w, h, r) {
  const radius = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.lineTo(x + w - radius, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + radius);
  ctx.lineTo(x + w, y + h);
  ctx.lineTo(x, y + h);
  ctx.lineTo(x, y + radius);
  ctx.quadraticCurveTo(x, y, x + radius, y);
  ctx.closePath();
}

function niceStep(max) {
  if (max <= 5) return 1;
  const raw = max / 4;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / mag;
  let mult = 1;
  if (norm > 5) mult = 10;
  else if (norm > 2) mult = 5;
  else if (norm > 1) mult = 2;
  return mult * mag;
}

function compactNum(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(n % 1000000 === 0 ? 0 : 1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(n % 1000 === 0 ? 0 : 1) + 'k';
  return String(n);
}

function hourLabel(date) {
  return String(date.getHours()).padStart(2, '0') + ':00';
}

// Redraw on resize so the canvas never stays stretched or clipped.
window.addEventListener('resize', () => {
  if (timelineRaf) cancelAnimationFrame(timelineRaf);
  timelineRaf = requestAnimationFrame(() => {
    if (lastStats) renderTimeline(lastStats.recentEvents);
  });
});

// ============================================================================
// Live feed
// ============================================================================

function addLiveFeedItem(event) {
  const feed = document.getElementById('live-feed');
  if (!feed || !event) return;

  const empty = feed.querySelector('.empty-state');
  if (empty) empty.remove();

  const severity = event.severity || 'LOW';
  const action = event.action || 'log';

  const item = document.createElement('div');
  item.className = 'feed-item sev-' + severity;

  const cveHtml = event.matched_cve
    ? '<span class="feed-cve" data-cve="' + escapeHtml(event.matched_cve) + '">' + escapeHtml(event.matched_cve) + '</span>'
    : '';

  const pathHtml = event.path
    ? '<span class="path" title="' + escapeHtml((event.method || '') + ' ' + event.path) + '">' +
        escapeHtml((event.method ? event.method + ' ' : '') + event.path) + '</span>'
    : '';

  item.innerHTML =
    '<span class="feed-severity ' + escapeHtml(severity) + '">' + escapeHtml(severity) + '</span>' +
    '<div class="feed-content">' +
      '<div class="feed-title">' + escapeHtml(event.rule_name || event.attack_type || 'Detection') + '</div>' +
      '<div class="feed-meta">' +
        '<span>' + escapeHtml(event.source_ip || '—') + '</span>' +
        '<span>' + escapeHtml(event.attack_type || '') + '</span>' +
        pathHtml +
        cveHtml +
        '<span class="action-badge ' + escapeHtml(action) + '">' + escapeHtml(String(action).toUpperCase()) + '</span>' +
      '</div>' +
    '</div>' +
    '<span class="feed-time">' + formatTime(event.timestamp) + '</span>';

  feed.insertBefore(item, feed.firstChild);

  while (feed.children.length > 50) {
    feed.removeChild(feed.lastChild);
  }
}

// ============================================================================
// CVE database
// ============================================================================

let cveSearchTimer = null;

async function loadCVEs() {
  const results = await fetchJSON(API + '/cve');
  if (results) renderCVEs(results);
}

async function searchCVEs() {
  const q = document.getElementById('cve-search').value.trim();
  const severity = document.getElementById('cve-severity-filter').value;
  const url = API + '/cve?q=' + encodeURIComponent(q) + '&severity=' + encodeURIComponent(severity);
  const results = await fetchJSON(url);
  if (results) renderCVEs(results);
}

function renderCVEs(cves) {
  const list = document.getElementById('cve-list');
  if (!list) return;

  setText('cve-result-count', formatNum(cves.length));

  if (cves.length === 0) {
    list.innerHTML = '<div class="empty-state">No vulnerabilities match this query</div>';
    return;
  }

  list.innerHTML = cves.map(c => {
    const tags = c.tags
      ? c.tags.split(',').map(t => '<span class="cve-tag">' + escapeHtml(t.trim()) + '</span>').join('')
      : '';
    const score = typeof c.cvss_score === 'number' ? c.cvss_score.toFixed(1) : '—';

    return '<div class="cve-card" data-cve="' + escapeHtml(c.cve_id) + '" tabindex="0" role="button">' +
      '<div class="cve-card-header">' +
        '<span class="cve-id">' + escapeHtml(c.cve_id) + '</span>' +
        '<span class="cve-score ' + escapeHtml(c.cvss_severity || '') + '">' + score + '</span>' +
        '<span class="cve-title">' + escapeHtml(c.title) + '</span>' +
      '</div>' +
      '<div class="cve-product">' + escapeHtml(c.affected_product || 'Unknown product') +
        (c.affected_versions ? ' — ' + escapeHtml(c.affected_versions) : '') + '</div>' +
      '<div class="cve-description">' + escapeHtml(c.description) + '</div>' +
      (tags ? '<div class="cve-tags">' + tags + '</div>' : '') +
    '</div>';
  }).join('');
}

async function showCVEDetail(cveId) {
  if (!cveId) return;

  const cve = await fetchJSON(API + '/cve/' + encodeURIComponent(cveId));
  if (!cve) return;

  const modal = document.getElementById('cve-modal');
  const body = document.getElementById('cve-modal-body');
  if (!modal || !body) return;

  setText('cve-modal-title', cve.cve_id);

  const score = typeof cve.cvss_score === 'number' ? cve.cvss_score.toFixed(1) : 'N/A';
  const firstRef = (cve.references || '').split(',')[0].trim();
  const refHtml = firstRef
    ? '<a href="' + escapeHtml(firstRef) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(firstRef) + '</a>'
    : 'N/A';

  body.innerHTML =
    row('Title', escapeHtml(cve.title)) +
    row('Severity', '<span class="severity-badge ' + escapeHtml(cve.cvss_severity || '') + '">' + escapeHtml(cve.cvss_severity || 'N/A') + '</span>') +
    row('CVSS Score', '<span class="cve-score ' + escapeHtml(cve.cvss_severity || '') + '">' + score + '</span>') +
    row('CVSS Vector', '<span class="mono">' + escapeHtml(cve.cvss_vector || 'N/A') + '</span>') +
    row('CWE', escapeHtml(cve.cwe_id || 'N/A')) +
    row('Description', escapeHtml(cve.description || 'N/A')) +
    row('Affected Product', escapeHtml(cve.affected_product || 'N/A')) +
    row('Affected Versions', escapeHtml(cve.affected_versions || 'N/A')) +
    row('Patched Version', escapeHtml(cve.patched_version || 'N/A')) +
    row('Attack Vector', escapeHtml(cve.attack_vector || 'N/A')) +
    row('Attack Complexity', escapeHtml(cve.attack_complexity || 'N/A')) +
    row('Privileges Required', escapeHtml(cve.privileges_required || 'N/A')) +
    row('User Interaction', escapeHtml(cve.user_interaction || 'N/A')) +
    row('Confidentiality', escapeHtml(cve.confidentiality_impact || 'N/A')) +
    row('Integrity', escapeHtml(cve.integrity_impact || 'N/A')) +
    row('Availability', escapeHtml(cve.availability_impact || 'N/A')) +
    row('Remediation', escapeHtml(cve.remediation || 'N/A')) +
    row('References', refHtml) +
    row('Published', escapeHtml(cve.published_date || 'N/A')) +
    row('Last Modified', escapeHtml(cve.last_modified || 'N/A')) +
    row('Tags', escapeHtml(cve.tags || 'N/A'));

  openModal(modal);
}

function openModal(modal) {
  modal.style.display = 'flex';
  const closeBtn = modal.querySelector('.modal-close');
  if (closeBtn) closeBtn.focus();
  document.body.style.overflow = 'hidden';
}

function closeModal(modal) {
  modal.style.display = 'none';
  document.body.style.overflow = '';
}

// Modal close: button, backdrop click, Escape
document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('cve-modal');
  if (!modal) return;

  const closeBtn = modal.querySelector('.modal-close');
  if (closeBtn) closeBtn.addEventListener('click', () => closeModal(modal));

  // Only close when the backdrop itself is clicked, not the dialog content.
  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal(modal);
  });
});

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  const modal = document.getElementById('cve-modal');
  if (modal && modal.style.display !== 'none') closeModal(modal);
});

// ============================================================================
// Events
// ============================================================================

async function loadEvents() {
  const events = await fetchJSON(API + '/events?limit=100');
  if (events) renderEventsTable(events);
}

async function filterEvents() {
  const severity = document.getElementById('events-severity-filter').value;
  const ip = document.getElementById('events-ip-filter').value.trim();

  const params = new URLSearchParams();
  if (severity) params.set('severity', severity);
  if (ip) params.set('source_ip', ip);

  const query = params.toString();
  const events = await fetchJSON(API + '/events/search' + (query ? '?' + query : ''));
  if (events) renderEventsTable(events);
}

function resetEventFilters() {
  document.getElementById('events-severity-filter').value = '';
  document.getElementById('events-ip-filter').value = '';
  loadEvents();
}

function renderEventsTable(events) {
  const tbody = document.getElementById('events-tbody');
  if (!tbody) return;

  setText('events-count', formatNum(events.length));

  if (events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state">No events match these filters</div></td></tr>';
    return;
  }

  tbody.innerHTML = events.map(e => {
    const action = e.action || 'log';
    return '<tr>' +
      '<td class="time-cell">' + formatTime(e.timestamp) + '</td>' +
      '<td><span class="severity-badge ' + escapeHtml(e.severity || '') + '">' + escapeHtml(e.severity || '—') + '</span></td>' +
      '<td>' + escapeHtml(e.attack_type || e.rule_name || '—') + '</td>' +
      '<td class="mono">' + escapeHtml(e.source_ip || '—') + '</td>' +
      '<td>' + escapeHtml(e.rule_name || '—') + '</td>' +
      '<td>' + (e.matched_cve
        ? '<span class="feed-cve" data-cve="' + escapeHtml(e.matched_cve) + '">' + escapeHtml(e.matched_cve) + '</span>'
        : '<span style="color:var(--text-muted)">—</span>') + '</td>' +
      '<td><span class="action-badge ' + escapeHtml(action) + '">' + escapeHtml(String(action).toUpperCase()) + '</span></td>' +
      '<td class="path-cell" title="' + escapeHtml(e.path || '') + '">' + escapeHtml(e.path || '—') + '</td>' +
    '</tr>';
  }).join('');
}

// ============================================================================
// Alerts
// ============================================================================

const ALERT_ICON =
  '<svg viewBox="0 0 24 24" aria-hidden="true">' +
  '<path d="M18 8.6a6 6 0 1 0-12 0c0 5-2 6.4-2 6.4h16s-2-1.4-2-6.4Z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>' +
  '<path d="M10.3 19a2 2 0 0 0 3.4 0" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>' +
  '</svg>';

async function loadAlerts() {
  const alerts = await fetchJSON(API + '/alerts?unacknowledged=true');
  if (!alerts) return;

  setText('alerts-count', formatNum(alerts.length));

  const list = document.getElementById('alerts-list');
  if (!list) return;

  if (alerts.length === 0) {
    list.innerHTML = '<div class="empty-state">No active alerts — all clear</div>';
    return;
  }

  list.innerHTML = alerts.map(a => {
    // Alert messages are generated server-side as "<SEVERITY> severity: ...",
    // so we can colour the card without a dedicated severity column.
    const match = /^(CRITICAL|HIGH|MEDIUM|LOW)\b/i.exec(a.message || '');
    const sev = match ? match[1].toUpperCase() : '';

    return '<div class="alert-card' + (sev ? ' sev-' + sev : '') + '" id="alert-' + a.id + '">' +
      '<span class="alert-icon">' + ALERT_ICON + '</span>' +
      '<div class="alert-info">' +
        '<div class="alert-message">' + escapeHtml(a.message) + '</div>' +
        '<div class="alert-time">' + formatTime(a.alert_time) + ' · ' + escapeHtml(a.alert_type) + '</div>' +
      '</div>' +
      '<button class="btn btn-ghost btn-sm" data-ack="' + a.id + '">Acknowledge</button>' +
    '</div>';
  }).join('');
}

async function ackAlert(id) {
  const card = document.getElementById('alert-' + id);
  const btn = card ? card.querySelector('[data-ack]') : null;

  try {
    const res = await fetch(API + '/alerts/' + id + '/acknowledge', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: 'admin' })
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    if (card) {
      card.classList.add('ack');
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Acknowledged';
      }
    }
  } catch (err) {
    if (btn) {
      btn.textContent = 'Failed — retry';
      btn.classList.remove('btn-ghost');
      btn.classList.add('btn-danger');
    }
  }
}

// ============================================================================
// IDS Rules
// ============================================================================

async function loadRules() {
  const rules = await fetchJSON(API + '/rules');
  if (!rules) return;

  setText('rules-count', formatNum(rules.length));

  const grid = document.getElementById('rules-grid');
  if (!grid) return;

  if (rules.length === 0) {
    grid.innerHTML = '<div class="empty-state">No rules loaded</div>';
    return;
  }

  grid.innerHTML = rules.map(r => {
    const enabled = Number(r.enabled) === 1;
    return '<div class="rule-card">' +
      '<div class="rule-header">' +
        '<span class="rule-name">' + escapeHtml(r.rule_name) + '</span>' +
        '<span class="rule-id">' + escapeHtml(r.rule_id) + '</span>' +
      '</div>' +
      '<div class="rule-desc">' + escapeHtml(r.rule_description || '') + '</div>' +
      '<div class="rule-pattern" title="' + escapeHtml(r.pattern) + '">' + escapeHtml(r.pattern) + '</div>' +
      '<div class="rule-footer">' +
        '<div class="rule-meta">' +
          '<span class="severity-badge ' + escapeHtml(r.severity || '') + '">' + escapeHtml(r.severity || '') + '</span>' +
          '<span class="action-badge ' + escapeHtml(r.action || 'alert') + '">' + escapeHtml(String(r.action || 'alert').toUpperCase()) + '</span>' +
          (r.related_cve
            ? '<span class="feed-cve" data-cve="' + escapeHtml(r.related_cve) + '">' + escapeHtml(r.related_cve) + '</span>'
            : '') +
        '</div>' +
        '<button class="toggle-switch ' + (enabled ? 'on' : '') + '" ' +
          'data-rule="' + escapeHtml(r.rule_id) + '" ' +
          'aria-label="Toggle rule ' + escapeHtml(r.rule_id) + '" ' +
          'aria-pressed="' + (enabled ? 'true' : 'false') + '"></button>' +
      '</div>' +
    '</div>';
  }).join('');
}

async function toggleRule(ruleId) {
  try {
    await fetch(API + '/rules/' + encodeURIComponent(ruleId) + '/toggle', { method: 'PUT' });
  } finally {
    loadRules();
  }
}

// ============================================================================
// IP reputation
// ============================================================================

async function loadIPReputation() {
  const ips = await fetchJSON(API + '/ip-reputation');
  if (!ips) return;

  setText('iprep-count', formatNum(ips.length));

  const tbody = document.getElementById('iprep-tbody');
  if (!tbody) return;

  if (ips.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state">No IP reputation data yet</div></td></tr>';
    return;
  }

  tbody.innerHTML = ips.map(ip => {
    const level = (ip.threat_level || 'unknown').toLowerCase();
    const score = Number(ip.reputation_score) || 0;
    const width = Math.max(2, Math.min(100, score));

    return '<tr>' +
      '<td class="mono">' + escapeHtml(ip.ip_address) + '</td>' +
      '<td><div class="score-cell">' +
        '<span class="score-num">' + score + '</span>' +
        '<span class="score-track"><span class="score-fill" style="width:' + width + '%;background:' + getScoreColor(score) + '"></span></span>' +
      '</div></td>' +
      '<td class="threat-' + escapeHtml(level) + '">' + escapeHtml(level.toUpperCase()) + '</td>' +
      '<td class="mono">' + formatNum(ip.total_events) + '</td>' +
      '<td class="time-cell">' + formatTime(ip.last_seen) + '</td>' +
      '<td>' + (ip.blocked ? '<span class="ip-blocked">BLOCKED</span>' : '<span class="ip-clean">Active</span>') + '</td>' +
      '<td>' + (ip.blocked
        ? '<button class="btn btn-ghost btn-sm" data-unblock="' + escapeHtml(ip.ip_address) + '">Unblock</button>'
        : '<button class="btn btn-danger btn-sm" data-block="' + escapeHtml(ip.ip_address) + '">Block</button>') +
      '</td>' +
    '</tr>';
  }).join('');
}

async function blockIP(ip) {
  try {
    await fetch(API + '/ip-reputation/' + encodeURIComponent(ip) + '/block', { method: 'PUT' });
  } finally {
    loadIPReputation();
  }
}

async function unblockIP(ip) {
  try {
    await fetch(API + '/ip-reputation/' + encodeURIComponent(ip) + '/unblock', { method: 'PUT' });
  } finally {
    loadIPReputation();
  }
}

// ============================================================================
// Event delegation
// Replaces per-row inline onclick handlers with one listener per container.
// ============================================================================

document.addEventListener('click', (e) => {
  const target = e.target.closest('[data-cve], [data-ack], [data-rule], [data-block], [data-unblock]');
  if (!target) return;

  if (target.dataset.cve) return showCVEDetail(target.dataset.cve);
  if (target.dataset.ack) return ackAlert(Number(target.dataset.ack));
  if (target.dataset.rule) return toggleRule(target.dataset.rule);
  if (target.dataset.block) return blockIP(target.dataset.block);
  if (target.dataset.unblock) return unblockIP(target.dataset.unblock);
});

// Keyboard activation for CVE cards (they carry role="button" + tabindex)
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const card = e.target.closest('.cve-card[data-cve]');
  if (!card) return;
  e.preventDefault();
  showCVEDetail(card.dataset.cve);
});

// ============================================================================
// Simulator controls
// ============================================================================

const simStart = document.getElementById('sim-start');
const simStop = document.getElementById('sim-stop');
const simStatus = document.getElementById('sim-status');

if (simStart) {
  simStart.addEventListener('click', async () => {
    await fetch(API + '/simulate/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interval: 2500 })
    });
    simStart.disabled = true;
    simStop.disabled = false;
    simStatus.textContent = 'Running';
    simStatus.className = 'badge badge-running';
  });
}

if (simStop) {
  simStop.addEventListener('click', async () => {
    await fetch(API + '/simulate/stop', { method: 'POST' });
    simStart.disabled = false;
    simStop.disabled = true;
    simStatus.textContent = 'Idle';
    simStatus.className = 'badge badge-idle';
  });
}

// ============================================================================
// Search / filter bindings
// ============================================================================

const cveSearchInput = document.getElementById('cve-search');
if (cveSearchInput) {
  cveSearchInput.addEventListener('input', () => {
    if (cveSearchTimer) clearTimeout(cveSearchTimer);
    cveSearchTimer = setTimeout(searchCVEs, 250);
  });
  cveSearchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      if (cveSearchTimer) clearTimeout(cveSearchTimer);
      searchCVEs();
    }
  });
}

bind('cve-search-btn', 'click', searchCVEs);
bind('cve-severity-filter', 'change', searchCVEs);
bind('events-filter-btn', 'click', filterEvents);
bind('events-reset-btn', 'click', resetEventFilters);
bind('refresh-events', 'click', loadEvents);
bind('refresh-alerts', 'click', loadAlerts);
bind('refresh-rules', 'click', loadRules);
bind('refresh-iprep', 'click', loadIPReputation);

// Enter inside the IP filter applies the filter
bind('events-ip-filter', 'keydown', (e) => {
  if (e.key === 'Enter') filterEvents();
});

function bind(id, event, handler) {
  const el = document.getElementById(id);
  if (el) el.addEventListener(event, handler);
}

// ============================================================================
// Helpers
// ============================================================================

async function fetchJSON(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.error('Fetch failed:', url, err);
    return null;
  }
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function formatNum(n) {
  if (n === undefined || n === null) return '0';
  return Number(n).toLocaleString();
}

function formatTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  const time = d.toLocaleTimeString('en-GB', { hour12: false });
  const date = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
  return time + ' · ' + date;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/[&<>"']/g, (c) => {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return map[c];
  });
}

function row(label, value) {
  return '<div class="detail-row">' +
    '<div class="detail-label">' + escapeHtml(label) + '</div>' +
    '<div class="detail-value">' + (value !== null && value !== undefined && value !== '' ? value : 'N/A') + '</div>' +
  '</div>';
}

function getAttackSeverity(attackType) {
  const map = {
    'SQL Injection': 'critical',
    'Command Injection': 'critical',
    'Log4j Injection': 'critical',
    'OGNL Injection': 'critical',
    'Web Shell': 'critical',
    'Code Injection': 'critical',
    'XXE Injection': 'high',
    'Cross-Site Scripting (XSS)': 'high',
    'Path Traversal': 'high',
    'LFI/RFI': 'high',
    'SSRF': 'high',
    'RDP Attack': 'high',
    'Scanner': 'medium'
  };
  return map[attackType] || 'info';
}

function getScoreColor(score) {
  if (score >= 75) return '#ff4d4f';
  if (score >= 50) return '#ff8c00';
  if (score >= 25) return '#f5c518';
  return '#3fb950';
}

// ============================================================================
// Init
// ============================================================================

connectWebSocket();
loadDashboard();
seedLiveFeed();
setInterval(loadDashboard, 10000);
