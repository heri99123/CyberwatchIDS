// CyberWatch IDS — Main Server (v3.0 — Multi-tenant SaaS)
const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const path = require('path');
const IntrusionDetectionEngine = require('./ids-engine');
const AttackSimulator = require('./simulator');
const { verifyJWT, requireAuth, requireAdmin } = require('./auth');
const createAuthRouter = require('./auth-routes');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

const ids = new IntrusionDetectionEngine();
let simulator = null;

const PORT = process.env.PORT || 8421;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve built Vue frontend (production) — falls back to legacy client/ if dist/ doesn't exist
const distPath = path.join(__dirname, '..', 'dist');
const legacyClientPath = path.join(__dirname, '..', 'client');
const fs = require('fs');

// Auto-build if dist/ doesn't exist but vite is available (cloud sandbox first-run)
if (!fs.existsSync(distPath) && fs.existsSync(path.join(__dirname, '..', 'node_modules', 'vite'))) {
  try {
    require('child_process').execSync('node node_modules/vite/bin/vite.js build', {
      cwd: path.join(__dirname, '..'),
      stdio: 'inherit',
      timeout: 60000
    });
  } catch (e) {
    console.error('[Server] Auto-build failed:', e.message);
  }
}

if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
} else {
  app.use(express.static(legacyClientPath));
}

// ============================
// Auth Router — will be mounted after IDS init
// ============================
let auditLog = (orgId, userId, userEmail, action, resource, details, req) => {};

function mountAuthRoutes() {
  auditLog = function(orgId, userId, userEmail, action, resource, details, req) {
    try {
      ids.db.prepare('INSERT INTO audit_logs (org_id, user_id, user_email, action, resource, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(orgId, userId, userEmail, action, resource, JSON.stringify(details || {}), req?.headers?.['x-forwarded-for'] || req?.socket?.remoteAddress || '');
    } catch (e) {
      console.error('[Audit] Failed to log:', e.message);
    }
  };

  app.use('/api', createAuthRouter(ids.db, auditLog));
}

// ============================
// Helper: extract org_id from auth token or API key
// ============================
function getOrgFromRequest(req) {
  // Try JWT token first
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const payload = verifyJWT(token);
    if (payload && payload.orgId) return payload.orgId;
  }
  // Try API key
  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const key = ids.db.prepare('SELECT org_id FROM api_keys WHERE key_prefix LIKE ? AND revoked = 0').get(apiKey.substring(0, 10) + '%');
    if (key) {
      // Update last used
      ids.db.prepare('UPDATE api_keys SET last_used = datetime(\'now\') WHERE key_prefix LIKE ?').run(apiKey.substring(0, 10) + '%');
      return key.org_id;
    }
  }
  return null;
}

// ============================
// WebSocket — Live event push (multi-tenant)
// ============================
const wsClients = new Set();

wss.on('connection', (ws, req) => {
  wsClients.add(ws);
  
  // Extract org_id from URL query or first message
  ws.orgId = null;
  const url = new URL(req.url, 'http://localhost');
  const token = url.searchParams.get('token');
  if (token) {
    const payload = verifyJWT(token);
    if (payload) ws.orgId = payload.orgId;
  }

  console.log('[WS] Client connected. Total: ' + wsClients.size);

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'subscribe') {
        ws.subscription = data.channels || ['events', 'alerts', 'stats'];
      }
      if (data.type === 'auth' && data.token) {
        const payload = verifyJWT(data.token);
        if (payload) ws.orgId = payload.orgId;
      }
    } catch (e) { /* ignore */ }
  });

  ws.on('close', () => {
    wsClients.delete(ws);
    console.log('[WS] Client disconnected. Total: ' + wsClients.size);
  });

  // Send initial stats
  ws.send(JSON.stringify({ type: 'stats', data: ids.getStats() }));
});

function broadcast(type, data, orgId) {
  const message = JSON.stringify({ type, data });
  for (const client of wsClients) {
    if (client.readyState === 1) {
      // If orgId is specified, only send to clients of that org
      if (orgId && client.orgId && client.orgId !== orgId) continue;
      client.send(message);
    }
  }
}

// ============================
// IDS Middleware — Inspect all requests (with org_id)
// ============================
app.use((req, res, next) => {
  // Skip auth routes and static assets
  if (req.path.startsWith('/api/auth/') || req.path.startsWith('/assets/') || req.path.startsWith('/ws')) {
    return next();
  }

  // Get real client IP
  const sourceIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const sourcePort = req.socket.remotePort;

  const reqData = {
    method: req.method,
    path: req.url,
    query: req.query,
    body: req.body,
    headers: req.headers,
    sourceIp,
    sourcePort,
    destination: req.headers.host || 'localhost'
  };

  // Run IDS inspection
  const result = ids.inspectRequest(reqData);

  if (result.totalDetections > 0) {
    // Get org_id from request (optional — works even without auth)
    const orgId = getOrgFromRequest(req);

    for (const detection of result.detections) {
      const eventId = ids.logSecurityEvent(detection, orgId);

      broadcast('events', { ...detection, id: eventId, timestamp: new Date().toISOString() }, orgId);

      if (detection.severity === 'CRITICAL' || detection.severity === 'HIGH') {
        broadcast('alerts', {
          event_id: eventId,
          alert_type: detection.attack_type,
          message: detection.severity + ' severity: ' + detection.rule_name + ' from ' + detection.source_ip,
          timestamp: new Date().toISOString()
        }, orgId);

        // Create notification for org users
        if (orgId) {
          try {
            const users = ids.db.prepare('SELECT id FROM users WHERE org_id = ? AND status = ?').all(orgId, 'active');
            for (const user of users) {
              ids.db.prepare('INSERT INTO notifications (org_id, user_id, type, title, message, data) VALUES (?, ?, ?, ?, ?, ?)')
                .run(orgId, user.id, 'alert', detection.severity + ' Alert: ' + detection.rule_name,
                  'Attack from ' + detection.source_ip + ' — ' + detection.attack_type,
                  JSON.stringify({ eventId, severity: detection.severity }));
            }
          } catch (e) { /* notifications table might not exist yet */ }
        }
      }
    }

    broadcast('stats', ids.getStats(orgId), orgId);

    if (result.shouldBlock) {
      return res.status(403).json({
        error: 'Request blocked by IDS',
        reason: 'Malicious pattern detected',
        severity: result.highestSeverity,
        detections: result.detections.map(d => ({
          rule: d.rule_name,
          attack_type: d.attack_type,
          severity: d.severity,
          matched_cve: d.matched_cve
        }))
      });
    }
  }

  next();
});

// ============================
// API Routes — Multi-tenant (org_id scoped)
// ============================

// Helper: get org_id from request (requires auth for data routes)
function requireOrg(req, res, next) {
  const orgId = getOrgFromRequest(req);
  if (!orgId) {
    return res.status(401).json({ error: 'Authentication required', code: 'NO_AUTH' });
  }
  req.orgId = orgId;
  next();
}

// --- Security Events (org-scoped) ---
app.get('/api/events', requireOrg, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const events = ids.db.prepare('SELECT * FROM security_events WHERE org_id = ? ORDER BY timestamp DESC LIMIT ?').all(req.orgId, limit);
  res.json(events);
});

app.get('/api/events/search', requireOrg, (req, res) => {
  const { severity, attack_type, source_ip } = req.query;
  let sql = 'SELECT * FROM security_events WHERE org_id = ?';
  const params = [req.orgId];
  if (severity) { sql += ' AND severity = ?'; params.push(severity); }
  if (attack_type) { sql += ' AND attack_type = ?'; params.push(attack_type); }
  if (source_ip) { sql += ' AND source_ip = ?'; params.push(source_ip); }
  sql += ' ORDER BY timestamp DESC LIMIT 200';
  res.json(ids.db.prepare(sql).all(...params));
});

// --- CVE Database (shared — no org scoping) ---
app.get('/api/cve', (req, res) => {
  const query = req.query.q || '';
  const severity = req.query.severity || 'ALL';
  const results = ids.searchCVEs(query, severity);
  res.json(results);
});

app.get('/api/cve/:id', (req, res) => {
  const cve = ids.getCVE(req.params.id);
  if (!cve) return res.status(404).json({ error: 'CVE not found' });
  res.json(cve);
});

// --- IDS Rules (shared defaults, org can override) ---
app.get('/api/rules', (req, res) => {
  res.json(ids.getRules());
});

app.put('/api/rules/:id/toggle', requireOrg, (req, res) => {
  const rule = ids.db.prepare('SELECT enabled FROM ids_rules WHERE rule_id = ?').get(req.params.id);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });
  const newEnabled = rule.enabled ? 0 : 1;
  ids.db.prepare('UPDATE ids_rules SET enabled = ? WHERE rule_id = ?').run(newEnabled, req.params.id);
  ids.loadRules();
  res.json({ rule_id: req.params.id, enabled: newEnabled });
});

// --- IP Reputation (org-scoped) ---
app.get('/api/ip-reputation', requireOrg, (req, res) => {
  const ips = ids.db.prepare('SELECT * FROM ip_reputation WHERE org_id = ? OR org_id IS NULL ORDER BY total_events DESC LIMIT 200').all(req.orgId);
  res.json(ips);
});

app.put('/api/ip-reputation/:ip/block', requireOrg, (req, res) => {
  ids.db.prepare('UPDATE ip_reputation SET blocked = 1 WHERE ip_address = ? AND (org_id = ? OR org_id IS NULL)').run(req.params.ip, req.orgId);
  res.json({ ip: req.params.ip, blocked: true });
});

app.put('/api/ip-reputation/:ip/unblock', requireOrg, (req, res) => {
  ids.db.prepare('UPDATE ip_reputation SET blocked = 0 WHERE ip_address = ? AND (org_id = ? OR org_id IS NULL)').run(req.params.ip, req.orgId);
  res.json({ ip: req.params.ip, blocked: false });
});

// --- Alerts (org-scoped) ---
app.get('/api/alerts', requireOrg, (req, res) => {
  const unacknowledgedOnly = req.query.unacknowledged === 'true';
  let sql = 'SELECT * FROM alerts WHERE org_id = ? OR org_id IS NULL';
  const params = [req.orgId];
  if (unacknowledgedOnly) { sql += ' AND acknowledged = 0'; }
  sql += ' ORDER BY alert_time DESC LIMIT 100';
  res.json(ids.db.prepare(sql).all(...params));
});

app.put('/api/alerts/:id/acknowledge', requireOrg, (req, res) => {
  ids.acknowledgeAlert(req.params.id, req.body.user || req.user?.email || 'system');
  res.json({ acknowledged: true });
});

// --- Statistics (org-scoped) ---
app.get('/api/stats', (req, res) => {
  const orgId = getOrgFromRequest(req);
  res.json(ids.getStats(orgId));
});

// --- Maintenance: purge event/alert/reputation data (org-scoped) ---
app.post('/api/reset', requireOrg, (req, res) => {
  try {
    const purged = ids.resetEventData(req.orgId);
    broadcast('stats', ids.getStats(req.orgId), req.orgId);
    res.json({ status: 'ok', purged });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- Simulator Control ---
app.post('/api/simulate/start', requireOrg, (req, res) => {
  const interval = req.body.interval || 3000;
  simulator.start(interval, req.orgId);
  res.json({ status: 'running', interval });
});

app.post('/api/simulate/stop', (req, res) => {
  simulator.stop();
  res.json({ status: 'stopped' });
});

app.get('/api/simulate/status', (req, res) => {
  res.json({ running: simulator.running });
});

// --- Manual attack injection ---
app.post('/api/simulate/attack', requireOrg, (req, res) => {
  const { attack_type } = req.body;
  const event = simulator.generateAttack(attack_type);
  if (event) {
    event.org_id = req.orgId;
    simulator.fireEvent(event);
    res.json({ fired: true, event });
  } else {
    res.status(400).json({ error: 'Unknown attack type' });
  }
});

// --- Dashboard summary (org-scoped) ---
app.get('/api/dashboard', requireOrg, (req, res) => {
  const stats = ids.getStats(req.orgId);
  const recentEvents = ids.db.prepare('SELECT * FROM security_events WHERE org_id = ? ORDER BY timestamp DESC LIMIT 5').all(req.orgId);
  const activeAlerts = ids.db.prepare('SELECT COUNT(*) as cnt FROM alerts WHERE (org_id = ? OR org_id IS NULL) AND acknowledged = 0').get(req.orgId);
  const topAttackers = ids.db.prepare('SELECT source_ip, COUNT(*) as cnt, MAX(severity) as max_sev FROM security_events WHERE org_id = ? GROUP BY source_ip ORDER BY cnt DESC LIMIT 5').all(req.orgId);
  
  res.json({
    stats,
    recentEvents,
    activeAlertCount: activeAlerts?.cnt || 0,
    topAttackers
  });
});

// --- Main page ---
app.get('/', (req, res) => {
  const indexPath = fs.existsSync(distPath)
    ? path.join(distPath, 'index.html')
    : path.join(legacyClientPath, 'index.html');
  res.sendFile(indexPath);
});

// SPA fallback: serve index.html for any non-API, non-file route
app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api') && !req.path.startsWith('/ws')) {
    const indexPath = fs.existsSync(distPath)
      ? path.join(distPath, 'index.html')
      : path.join(legacyClientPath, 'index.html');
    if (fs.existsSync(indexPath)) {
      return res.sendFile(indexPath);
    }
  }
  next();
});

// ============================
// Start Server
// ============================
async function start() {
  await ids.init();

  // Mount auth routes AFTER IDS init (so ids.db is ready)
  mountAuthRoutes();

  simulator = new AttackSimulator(ids, broadcast);

  server.listen(PORT, () => {
    console.log('');
    console.log('============================================');
    console.log('  CyberWatch IDS v3.0 — Multi-tenant SaaS');
    console.log('============================================');
    console.log('  Dashboard:  http://localhost:' + PORT);
    console.log('  WebSocket:  ws://localhost:' + PORT + '/ws');
    console.log('  API Base:    http://localhost:' + PORT + '/api');
    console.log('============================================');
    console.log('');
    console.log('[IDS] Engine initialized with ' + ids.compiledRules.length + ' rules');
    console.log('[Auth] JWT authentication enabled');
    console.log('[Multi-tenant] Organization data isolation active');
    console.log('');
  });
}

start().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

module.exports = { app, server, ids, simulator: () => simulator, broadcast: () => broadcast };
