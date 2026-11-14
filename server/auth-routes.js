// CyberWatch IDS — Auth & Organization Routes
const express = require('express');
const crypto = require('crypto');
const { hashPassword, verifyPassword, signJWT, verifyJWT, generateApiKey, requireAuth, requireAdmin } = require('./auth');

function createAuthRouter(db, auditLog) {
  const router = express.Router();

  // Helper: generate unique ID
  function genId(prefix = '') {
    return prefix + crypto.randomUUID();
  }

  // Helper: create slug from org name
  function slugify(text) {
    return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') + '-' + crypto.randomBytes(3).toString('hex');
  }

  // ============================
  // Public Routes (no auth)
  // ============================

  // --- Register new organization + admin user ---
  router.post('/auth/register', (req, res) => {
    const { orgName, name, email, password } = req.body;
    
    if (!orgName || !name || !email || !password) {
      return res.status(400).json({ error: 'All fields required: orgName, name, email, password' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if email already exists in any org
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) {
      return res.status(409).json({ error: 'Email already registered', code: 'EMAIL_EXISTS' });
    }

    const orgId = genId('org_');
    const userId = genId('usr_');
    const slug = slugify(orgName);

    try {
      // Create organization
      db.prepare('INSERT INTO organizations (id, name, slug, plan, max_users, settings) VALUES (?, ?, ?, ?, ?, ?)')
        .run(orgId, orgName, slug, 'free', 5, JSON.stringify({ emailAlerts: false, slackWebhook: '' }));

      // Create admin user
      const passwordHash = hashPassword(password);
      db.prepare('INSERT INTO users (id, org_id, email, name, password_hash, role, status) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(userId, orgId, email, name, passwordHash, 'admin', 'active');

      // Generate JWT
      const token = signJWT({
        sub: userId,
        email,
        name,
        role: 'admin',
        orgId,
        orgName
      });

      auditLog(orgId, userId, email, 'register', 'organization', { orgName }, req);

      res.json({
        token,
        user: { id: userId, email, name, role: 'admin', orgId, orgName },
        organization: { id: orgId, name: orgName, slug, plan: 'free' }
      });
    } catch (e) {
      res.status(500).json({ error: 'Registration failed: ' + e.message });
    }
  });

  // --- Login ---
  router.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ? AND status = ?').get(email, 'active');
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials', code: 'INVALID_CREDENTIALS' });
    }

    if (!verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials', code: 'INVALID_CREDENTIALS' });
    }

    // Get org info
    const org = db.prepare('SELECT * FROM organizations WHERE id = ?').get(user.org_id);
    if (!org) {
      return res.status(500).json({ error: 'Organization not found' });
    }

    // Update last login
    db.prepare('UPDATE users SET last_login = datetime(\'now\') WHERE id = ?').run(user.id);

    const token = signJWT({
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      orgId: user.org_id,
      orgName: org.name
    });

    auditLog(user.org_id, user.id, user.email, 'login', 'auth', {}, req);

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role, orgId: user.org_id, orgName: org.name },
      organization: { id: org.id, name: org.name, slug: org.slug, plan: org.plan }
    });
  });

  // --- Verify token (for frontend on reload) ---
  router.get('/auth/verify', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token' });
    }
    const token = authHeader.substring(7);
    const payload = verifyJWT(token);
    if (!payload) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    const user = db.prepare('SELECT u.*, o.name as org_name FROM users u JOIN organizations o ON u.org_id = o.id WHERE u.id = ?').get(payload.sub);
    if (!user || user.status !== 'active') {
      return res.status(401).json({ error: 'User inactive' });
    }

    res.json({
      user: { id: user.id, email: user.email, name: user.name, role: user.role, orgId: user.org_id, orgName: user.org_name },
      organization: { id: user.org_id, name: user.org_name }
    });
  });

  // ============================
  // Authenticated Routes
  // ============================

  // --- Get current user profile ---
  router.get('/auth/me', requireAuth, (req, res) => {
    const user = db.prepare('SELECT u.id, u.email, u.name, u.role, u.status, u.last_login, u.created_at, o.name as org_name, o.plan, o.max_users FROM users u JOIN organizations o ON u.org_id = o.id WHERE u.id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  });

  // ============================
  // Admin Routes (admin role required)
  // ============================

  // --- List users in organization ---
  router.get('/admin/users', requireAuth, requireAdmin, (req, res) => {
    const users = db.prepare('SELECT id, email, name, role, status, last_login, created_at FROM users WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
    res.json(users);
  });

  // --- Create new user in organization ---
  router.post('/admin/users', requireAuth, requireAdmin, (req, res) => {
    const { email, name, password, role } = req.body;
    if (!email || !name || !password) {
      return res.status(400).json({ error: 'email, name, password required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check max users
    const org = db.prepare('SELECT max_users FROM organizations WHERE id = ?').get(req.user.orgId);
    const count = db.prepare('SELECT COUNT(*) as cnt FROM users WHERE org_id = ?').get(req.user.orgId);
    if (count.cnt >= org.max_users) {
      return res.status(403).json({ error: 'Maximum user limit reached for your plan (' + org.max_users + ')' });
    }

    // Check if email exists in this org
    const existing = db.prepare('SELECT id FROM users WHERE org_id = ? AND email = ?').get(req.user.orgId, email);
    if (existing) {
      return res.status(409).json({ error: 'Email already exists in your organization' });
    }

    const userId = genId('usr_');
    const passwordHash = hashPassword(password);
    const userRole = ['admin', 'analyst', 'viewer'].includes(role) ? role : 'viewer';

    db.prepare('INSERT INTO users (id, org_id, email, name, password_hash, role, status) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(userId, req.user.orgId, email, name, passwordHash, userRole, 'active');

    auditLog(req.user.orgId, req.user.id, req.user.email, 'create_user', 'user', { email, name, role: userRole }, req);

    res.json({ id: userId, email, name, role: userRole, status: 'active' });
  });

  // --- Update user role ---
  router.put('/admin/users/:id/role', requireAuth, requireAdmin, (req, res) => {
    const { role } = req.body;
    if (!['admin', 'analyst', 'viewer'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ? AND org_id = ?').get(req.params.id, req.user.orgId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
    auditLog(req.user.orgId, req.user.id, req.user.email, 'update_role', 'user', { userId: req.params.id, role }, req);
    res.json({ id: req.params.id, role });
  });

  // --- Disable/Enable user ---
  router.put('/admin/users/:id/status', requireAuth, requireAdmin, (req, res) => {
    const { status } = req.body;
    if (!['active', 'disabled'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ? AND org_id = ?').get(req.params.id, req.user.orgId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.id === req.user.id && status === 'disabled') {
      return res.status(400).json({ error: 'Cannot disable yourself' });
    }
    
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, req.params.id);
    auditLog(req.user.orgId, req.user.id, req.user.email, 'update_status', 'user', { userId: req.params.id, status }, req);
    res.json({ id: req.params.id, status });
  });

  // --- Delete user ---
  router.delete('/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ? AND org_id = ?').get(req.params.id, req.user.orgId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete yourself' });
    }
    
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    auditLog(req.user.orgId, req.user.id, req.user.email, 'delete_user', 'user', { userId: req.params.id, email: user.email }, req);
    res.json({ deleted: true });
  });

  // --- Organization settings ---
  router.get('/admin/org', requireAuth, requireAdmin, (req, res) => {
    const org = db.prepare('SELECT id, name, slug, plan, max_users, settings, created_at FROM organizations WHERE id = ?').get(req.user.orgId);
    if (!org) return res.status(404).json({ error: 'Organization not found' });
    org.settings = JSON.parse(org.settings || '{}');
    
    const userCount = db.prepare('SELECT COUNT(*) as cnt FROM users WHERE org_id = ?').get(req.user.orgId);
    org.userCount = userCount.cnt;
    
    res.json(org);
  });

  // --- Update organization settings ---
  router.put('/admin/org', requireAuth, requireAdmin, (req, res) => {
    const { name, settings } = req.body;
    
    if (name) {
      db.prepare('UPDATE organizations SET name = ? WHERE id = ?').run(name, req.user.orgId);
    }
    if (settings) {
      const current = db.prepare('SELECT settings FROM organizations WHERE id = ?').get(req.user.orgId);
      const merged = { ...JSON.parse(current.settings || '{}'), ...settings };
      db.prepare('UPDATE organizations SET settings = ? WHERE id = ?').run(JSON.stringify(merged), req.user.orgId);
    }
    
    auditLog(req.user.orgId, req.user.id, req.user.email, 'update_org', 'organization', { name, settings }, req);
    res.json({ updated: true });
  });

  // ============================
  // API Keys
  // ============================

  // --- List API keys ---
  router.get('/admin/api-keys', requireAuth, requireAdmin, (req, res) => {
    const keys = db.prepare('SELECT key_id, org_id, name, key_prefix, permissions, last_used, created_at, revoked FROM api_keys WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
    res.json(keys);
  });

  // --- Create API key ---
  router.post('/admin/api-keys', requireAuth, requireAdmin, (req, res) => {
    const { name, permissions } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    
    const keyId = genId('key_');
    const fullKey = generateApiKey();
    const keyPrefix = fullKey.substring(0, 10) + '...';
    const perms = ['read', 'read-write'].includes(permissions) ? permissions : 'read';
    
    db.prepare('INSERT INTO api_keys (key_id, org_id, name, key_prefix, permissions) VALUES (?, ?, ?, ?, ?)')
      .run(keyId, req.user.orgId, name, keyPrefix, perms);
    
    auditLog(req.user.orgId, req.user.id, req.user.email, 'create_apikey', 'api_key', { name, keyId }, req);
    
    res.json({ keyId, name, key: fullKey, permissions: perms, note: 'Save this key securely. It will not be shown again.' });
  });

  // --- Revoke API key ---
  router.delete('/admin/api-keys/:id', requireAuth, requireAdmin, (req, res) => {
    db.prepare('UPDATE api_keys SET revoked = 1 WHERE key_id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
    auditLog(req.user.orgId, req.user.id, req.user.email, 'revoke_apikey', 'api_key', { keyId: req.params.id }, req);
    res.json({ revoked: true });
  });

  // ============================
  // Incidents
  // ============================

  // --- List incidents ---
  router.get('/incidents', requireAuth, (req, res) => {
    const incidents = db.prepare('SELECT * FROM incidents WHERE org_id = ? ORDER BY created_at DESC LIMIT 100').all(req.user.orgId);
    res.json(incidents);
  });

  // --- Create incident ---
  router.post('/incidents', requireAuth, (req, res) => {
    const { title, description, severity, eventIds } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    
    const id = genId('inc_');
    db.prepare('INSERT INTO incidents (id, org_id, title, description, severity, event_ids, assigned_to) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(id, req.user.orgId, title, description || '', severity || 'medium', JSON.stringify(eventIds || []), req.user.id);
    
    auditLog(req.user.orgId, req.user.id, req.user.email, 'create_incident', 'incident', { id, title }, req);
    res.json({ id, title, status: 'open' });
  });

  // --- Update incident ---
  router.put('/incidents/:id', requireAuth, (req, res) => {
    const { status, severity, assignedTo, description } = req.body;
    const inc = db.prepare('SELECT * FROM incidents WHERE id = ? AND org_id = ?').get(req.params.id, req.user.orgId);
    if (!inc) return res.status(404).json({ error: 'Incident not found' });
    
    const updates = [];
    const params = [];
    if (status) { updates.push('status = ?'); params.push(status); }
    if (severity) { updates.push('severity = ?'); params.push(severity); }
    if (assignedTo) { updates.push('assigned_to = ?'); params.push(assignedTo); }
    if (description) { updates.push('description = ?'); params.push(description); }
    updates.push('updated_at = datetime(\'now\')');
    if (status === 'resolved') updates.push('resolved_at = datetime(\'now\')');
    
    params.push(req.params.id, req.user.orgId);
    db.prepare(`UPDATE incidents SET ${updates.join(', ')} WHERE id = ? AND org_id = ?`).run(...params);
    
    auditLog(req.user.orgId, req.user.id, req.user.email, 'update_incident', 'incident', { id: req.params.id, status, severity }, req);
    res.json({ id: req.params.id, updated: true });
  });

  // ============================
  // Notifications
  // ============================

  router.get('/notifications', requireAuth, (req, res) => {
    const notifs = db.prepare('SELECT * FROM notifications WHERE org_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 50').all(req.user.orgId, req.user.id);
    res.json(notifs);
  });

  router.put('/notifications/:id/read', requireAuth, (req, res) => {
    db.prepare('UPDATE notifications SET read = 1 WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
    res.json({ read: true });
  });

  // ============================
  // Audit Logs
  // ============================

  router.get('/admin/audit-logs', requireAuth, requireAdmin, (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    const logs = db.prepare('SELECT * FROM audit_logs WHERE org_id = ? ORDER BY timestamp DESC LIMIT ?').all(req.user.orgId, limit);
    res.json(logs);
  });

  // --- Export data (CSV-like JSON) ---
  router.get('/admin/export/:type', requireAuth, requireAdmin, (req, res) => {
    const type = req.params.type;
    const orgId = req.user.orgId;
    let data = [];
    let filename = type + '_export_' + Date.now() + '.json';
    
    if (type === 'events') {
      data = db.prepare('SELECT * FROM security_events WHERE org_id = ? ORDER BY timestamp DESC LIMIT 10000').all(orgId);
    } else if (type === 'alerts') {
      data = db.prepare('SELECT * FROM alerts WHERE org_id = ? ORDER BY alert_time DESC LIMIT 10000').all(orgId);
    } else if (type === 'incidents') {
      data = db.prepare('SELECT * FROM incidents WHERE org_id = ?').all(orgId);
    } else if (type === 'audit') {
      data = db.prepare('SELECT * FROM audit_logs WHERE org_id = ? ORDER BY timestamp DESC LIMIT 10000').all(orgId);
    } else {
      return res.status(400).json({ error: 'Invalid export type. Use: events, alerts, incidents, audit' });
    }
    
    auditLog(orgId, req.user.id, req.user.email, 'export_data', 'export', { type, count: data.length }, req);
    
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/json');
    res.json({ type, exported_at: new Date().toISOString(), count: data.length, data });
  });

  return router;
}

module.exports = createAuthRouter;
