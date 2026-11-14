// Intrusion Detection System — Detection Engine
const { initDatabase } = require('./db');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'data', 'cve-database.db');

class IntrusionDetectionEngine {
  constructor() {
    this.db = null;
    this.dbWrapper = null;
    this.rules = [];
    this.compiledRules = [];
    this._saveTimer = null;
  }

  async init() {
    this.dbWrapper = await initDatabase();
    this.db = this.dbWrapper;
    this.loadRules();
    // Auto-save every 5 seconds to persist new events
    this._saveTimer = setInterval(() => {
      try { this.db._save(); } catch(e) {}
    }, 5000);
  }

  loadRules() {
    this.rules = this.db.prepare('SELECT * FROM ids_rules WHERE enabled = 1').all();
    this.compiledRules = this.rules.map(rule => {
      let flags = 'i';
      if (rule.pattern_flags) flags = rule.pattern_flags;
      // Strip PCRE-style (?i) inline flag prefix — JS doesn't support it, we use flags instead
      let patternStr = rule.pattern;
      if (patternStr.startsWith('(?i)')) {
        patternStr = patternStr.substring(4);
      }
      // Remove any other inline flag groups like (?i:...)
      patternStr = patternStr.replace(/\(\?[a-z]+:/g, '(');
      try {
        return {
          ...rule,
          regex: new RegExp(patternStr, flags)
        };
      } catch (e) {
        console.error('[IDS] Invalid regex for rule ' + rule.rule_id + ': ' + e.message);
        return null;
      }
    }).filter(r => r !== null);
    console.log('[IDS] Loaded ' + this.compiledRules.length + ' active detection rules');
  }

  // Inspect an HTTP request and return array of detected threats
  inspectRequest(reqData) {
    const {
      method,
      path: reqPath,
      query,
      body,
      headers,
      sourceIp,
      sourcePort,
      destination
    } = reqData;

    const surfaces = [];
    surfaces.push({ field: 'path', value: reqPath || '', location: 'URL Path' });

    if (query) {
      if (typeof query === 'object') {
        for (const [key, val] of Object.entries(query)) {
          surfaces.push({ field: key, value: String(val), location: 'Query Param: ' + key });
        }
      } else if (typeof query === 'string') {
        surfaces.push({ field: 'query', value: query, location: 'Query String' });
      }
    }

    if (body) {
      if (typeof body === 'object') {
        for (const [key, val] of Object.entries(body)) {
          surfaces.push({ field: key, value: String(val), location: 'Body Param: ' + key });
        }
      } else if (typeof body === 'string') {
        surfaces.push({ field: 'body', value: body, location: 'Request Body' });
      }
    }

    if (headers) {
      const headerFields = ['user-agent', 'content-type', 'content-disposition', 'referer', 'cookie', 'x-forwarded-for', 'authorization', 'accept'];
      for (const h of headerFields) {
        if (headers[h]) {
          surfaces.push({ field: h, value: String(headers[h]), location: 'Header: ' + h, isHeader: true });
        }
      }
    }

    const detections = [];

    for (const surface of surfaces) {
      for (const rule of this.compiledRules) {
        // SSRF rules must only evaluate user-controlled input (path/query/body).
        // Headers such as Referer legitimately contain hostnames like "localhost"
        // and would otherwise raise a false positive on every same-origin request.
        if (surface.isHeader && rule.attack_type === 'SSRF') continue;
        try {
          const match = surface.value.match(rule.regex);
          if (match) {
            const detection = {
              event_type: 'attack',
              rule_id: rule.rule_id,
              rule_name: rule.rule_name,
              rule_description: rule.rule_description || '',
              attack_type: rule.attack_type,
              severity: rule.severity,
              matched_pattern: match[0],
              matched_cve: rule.related_cve || null,
              action: rule.action || 'alert',
              source_ip: sourceIp || 'unknown',
              source_port: sourcePort || null,
              destination: destination || reqPath || '',
              method: method || 'GET',
              path: reqPath || '/',
              payload: surface.value.substring(0, 2000),
              user_agent: headers && headers['user-agent'] ? headers['user-agent'] : null,
              matched_field: surface.field,
              matched_location: surface.location
            };
            detections.push(detection);
            break;
          }
        } catch (e) { /* regex error, skip */ }
      }
    }

    const shouldBlock = detections.some(d => d.action === 'block');
    const criticalCount = detections.filter(d => d.severity === 'CRITICAL').length;

    return {
      detections,
      shouldBlock,
      criticalCount,
      totalDetections: detections.length,
      highestSeverity: this.getHighestSeverity(detections)
    };
  }

  getHighestSeverity(detections) {
    const order = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
    let highest = 'INFO';
    let highestVal = 0;
    for (const d of detections) {
      const val = order[d.severity] || 0;
      if (val > highestVal) { highestVal = val; highest = d.severity; }
    }
    return highest;
  }

  logSecurityEvent(detection, orgId) {
    const timestamp = new Date().toISOString();

    const result = this.db.prepare(`
      INSERT INTO security_events
      (timestamp, event_type, attack_type, severity, source_ip, source_port, destination,
       method, path, payload, user_agent, rule_id, rule_name, rule_description,
       matched_pattern, matched_cve, action, blocked, org_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      timestamp, detection.event_type || 'attack', detection.attack_type || null, detection.severity,
      detection.source_ip, detection.source_port, detection.destination,
      detection.method, detection.path, detection.payload, detection.user_agent,
      detection.rule_id, detection.rule_name, detection.rule_description,
      detection.matched_pattern, detection.matched_cve, detection.action,
      detection.action === 'block' ? 1 : 0, orgId || null
    );

    const eventId = result.lastInsertRowid;

    if (detection.severity === 'CRITICAL' || detection.severity === 'HIGH') {
      this.db.prepare(`
        INSERT INTO alerts (event_id, alert_time, alert_type, message, org_id)
        VALUES (?, ?, ?, ?, ?)
      `).run(eventId, timestamp, detection.attack_type,
        detection.severity + ' severity: ' + detection.rule_name + ' from ' + detection.source_ip, orgId || null);
    }

    this.updateIPReputation(detection.source_ip, detection.severity, orgId);
    return eventId;
  }

  updateIPReputation(ip, severity, orgId) {
    if (!ip || ip === 'unknown') return;
    const existing = this.db.prepare('SELECT * FROM ip_reputation WHERE ip_address = ? AND (org_id = ? OR org_id IS NULL)').get(ip, orgId);
    const scoreMap = { 'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 5, 'LOW': 1, 'INFO': 0 };
    const scoreAdd = scoreMap[severity] || 0;

    if (existing) {
      const newScore = Math.min(100, (existing.reputation_score || 0) + scoreAdd);
      let threatLevel = 'low';
      if (newScore >= 75) threatLevel = 'critical';
      else if (newScore >= 50) threatLevel = 'high';
      else if (newScore >= 25) threatLevel = 'medium';

      this.db.prepare(`
        UPDATE ip_reputation
        SET reputation_score = ?, threat_level = ?, last_seen = ?, total_events = total_events + 1
        WHERE ip_address = ? AND (org_id = ? OR org_id IS NULL)
      `).run(newScore, threatLevel, new Date().toISOString(), ip, orgId);
    } else {
      let threatLevel = 'low';
      if (scoreAdd >= 25) threatLevel = 'critical';
      else if (scoreAdd >= 15) threatLevel = 'high';

      this.db.prepare(`
        INSERT INTO ip_reputation (ip_address, reputation_score, threat_level, first_seen, last_seen, total_events, org_id)
        VALUES (?, ?, ?, ?, ?, 1, ?)
      `).run(ip, scoreAdd, threatLevel, new Date().toISOString(), new Date().toISOString(), orgId || null);
    }
  }

  getStats(orgId) {
    const orgFilter = orgId ? 'WHERE (org_id = ? OR org_id IS NULL)' : '';
    const orgParams = orgId ? [orgId] : [];
    
    const totalEvents = this.db.prepare(`SELECT COUNT(*) as count FROM security_events ${orgFilter}`).get(...orgParams).count;
    const blockedEvents = this.db.prepare(`SELECT COUNT(*) as count FROM security_events ${orgFilter ? orgFilter + ' AND' : 'WHERE'} blocked = 1`).get(...orgParams).count;
    const criticalEvents = this.db.prepare(`SELECT COUNT(*) as count FROM security_events ${orgFilter ? orgFilter + ' AND' : 'WHERE'} severity = 'CRITICAL'`).get(...orgParams).count;
    const highEvents = this.db.prepare(`SELECT COUNT(*) as count FROM security_events ${orgFilter ? orgFilter + ' AND' : 'WHERE'} severity = 'HIGH'`).get(...orgParams).count;
    const uniqueAttackers = this.db.prepare(`SELECT COUNT(DISTINCT source_ip) as count FROM security_events ${orgFilter}`).get(...orgParams).count;
    const activeAlerts = this.db.prepare(`SELECT COUNT(*) as count FROM alerts ${orgFilter ? orgFilter.replace('security_events', 'alerts') : ''} AND acknowledged = 0`).get(...orgParams).count;

    const topAttackTypes = this.db.prepare(`
      SELECT event_type, attack_type, COUNT(*) as count
      FROM security_events ${orgFilter} GROUP BY attack_type ORDER BY count DESC LIMIT 10
    `).all(...orgParams);

    const topAttackers = this.db.prepare(`
      SELECT source_ip, COUNT(*) as count,
        CASE MAX(CASE severity
                   WHEN 'CRITICAL' THEN 4
                   WHEN 'HIGH' THEN 3
                   WHEN 'MEDIUM' THEN 2
                   WHEN 'LOW' THEN 1
                   ELSE 0 END)
          WHEN 4 THEN 'CRITICAL'
          WHEN 3 THEN 'HIGH'
          WHEN 2 THEN 'MEDIUM'
          WHEN 1 THEN 'LOW'
          ELSE 'LOW'
        END as max_severity
      FROM security_events ${orgFilter} GROUP BY source_ip ORDER BY count DESC LIMIT 10
    `).all(...orgParams);

    const recentEvents = this.db.prepare(`
      SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as count
      FROM security_events ${orgFilter ? orgFilter + ' AND' : 'WHERE'} timestamp >= datetime('now', '-24 hours')
      GROUP BY hour ORDER BY hour DESC
    `).all(...orgParams);

    const cveMatches = this.db.prepare(`
      SELECT matched_cve, COUNT(*) as count
      FROM security_events ${orgFilter ? orgFilter + ' AND' : 'WHERE'} matched_cve IS NOT NULL
      GROUP BY matched_cve ORDER BY count DESC LIMIT 10
    `).all(...orgParams);

    return {
      totalEvents, blockedEvents, criticalEvents, highEvents,
      uniqueAttackers, activeAlerts, topAttackTypes, topAttackers,
      recentEvents, cveMatches
    };
  }

  getRecentEvents(limit, orgId) {
    if (orgId) {
      return this.db.prepare('SELECT * FROM security_events WHERE org_id = ? OR org_id IS NULL ORDER BY timestamp DESC LIMIT ?').all(orgId, limit || 50);
    }
    return this.db.prepare('SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?').all(limit || 50);
  }

  searchCVEs(query, severityFilter) {
    let sql = 'SELECT * FROM cve_entries WHERE 1=1';
    const params = [];
    if (query) {
      sql += ' AND (cve_id LIKE ? OR title LIKE ? OR description LIKE ? OR affected_product LIKE ? OR tags LIKE ?)';
      const likeQuery = '%' + query + '%';
      params.push(likeQuery, likeQuery, likeQuery, likeQuery, likeQuery);
    }
    if (severityFilter && severityFilter !== 'ALL') {
      sql += ' AND cvss_severity = ?';
      params.push(severityFilter);
    }
    sql += ' ORDER BY cvss_score DESC';
    return this.db.prepare(sql).all(...params);
  }

  getCVE(cveId) {
    return this.db.prepare('SELECT * FROM cve_entries WHERE cve_id = ?').get(cveId);
  }

  getRules() {
    // Order by severity rank, not alphabetically (text DESC would put MEDIUM
    // above CRITICAL because 'M' > 'C').
    return this.db.prepare(`
      SELECT * FROM ids_rules
      ORDER BY CASE severity
                 WHEN 'CRITICAL' THEN 4
                 WHEN 'HIGH' THEN 3
                 WHEN 'MEDIUM' THEN 2
                 WHEN 'LOW' THEN 1
                 ELSE 0 END DESC,
               rule_id ASC
    `).all();
  }

  getIPReputation() {
    return this.db.prepare('SELECT * FROM ip_reputation ORDER BY reputation_score DESC').all();
  }

  acknowledgeAlert(alertId, user) {
    return this.db.prepare(`
      UPDATE alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ? WHERE id = ?
    `).run(user || 'admin', new Date().toISOString(), alertId);
  }

  // Purge runtime telemetry (events, alerts, IP reputation) but keep CVE data and rules.
  resetEventData(orgId) {
    if (orgId) {
      const counts = {
        events: this.db.prepare('SELECT COUNT(*) as c FROM security_events WHERE org_id = ?').get(orgId).c,
        alerts: this.db.prepare('SELECT COUNT(*) as c FROM alerts WHERE org_id = ?').get(orgId).c,
        ips: this.db.prepare('SELECT COUNT(*) as c FROM ip_reputation WHERE org_id = ?').get(orgId).c
      };
      this.db.prepare('DELETE FROM alerts WHERE org_id = ?').run(orgId);
      this.db.prepare('DELETE FROM security_events WHERE org_id = ?').run(orgId);
      this.db.prepare('DELETE FROM ip_reputation WHERE org_id = ?').run(orgId);
      this.db._save();
      console.log('[IDS] Event data purged for org ' + orgId + ': ' + counts.events + ' events, ' + counts.alerts + ' alerts, ' + counts.ips + ' IPs');
      return counts;
    }
    const counts = {
      events: this.db.prepare('SELECT COUNT(*) as c FROM security_events').get().c,
      alerts: this.db.prepare('SELECT COUNT(*) as c FROM alerts').get().c,
      ips: this.db.prepare('SELECT COUNT(*) as c FROM ip_reputation').get().c
    };
    this.db.prepare('DELETE FROM alerts').run();
    this.db.prepare('DELETE FROM security_events').run();
    this.db.prepare('DELETE FROM ip_reputation').run();
    try {
      this.db.prepare("DELETE FROM sqlite_sequence WHERE name IN ('security_events','alerts')").run();
    } catch (e) { /* sqlite_sequence may not exist yet */ }
    this.db._save();
    console.log('[IDS] Event data purged: ' + counts.events + ' events, ' + counts.alerts + ' alerts, ' + counts.ips + ' IPs');
    return counts;
  }

  close() {
    if (this._saveTimer) clearInterval(this._saveTimer);
    try { this.db._save(); } catch(e) {}
    this.db.close();
  }
}

module.exports = IntrusionDetectionEngine;
